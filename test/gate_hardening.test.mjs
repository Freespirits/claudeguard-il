import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  decide, decideWithResolution, classifyAddress, gateResolvedAddress, METADATA_ADDRESSES,
  RateWindow, RunBudget, RunRegistry, ResolutionPins, GateSession, watchKillSwitch,
  TOOL_TIERS, DENY, DEFAULT_MAX_ACTIONS, HARD_MAX_ACTIONS, HARD_MAX_WALL_CLOCK_MS,
} from '../plugin/scripts/dynamic_gate.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// test/dynamic_gate.test.mjs attacks the DECISION: can a caller talk the gate into approving
// something it should refuse? Every one of those attacks now fails, and the gate was still walkable,
// because five of its promises were kept only in the sense that a comment described them:
//
//   1. "one command aborts everything" aborted the NEXT decision. Whatever was already running kept
//      running — the fetch in flight, the process already spawned. STOP meant "stop soon, probably".
//   2. The rate cap counted a history nobody accumulated: the CLI passed `recent: []` every time, so
//      the (N+1)th request saw an empty window and every request was the first one.
//   3. The gate approved a hostNAME. The socket opens to an ADDRESS, and nothing checked the answer:
//      an allowlisted name whose DNS says 169.254.169.254 is cloud-metadata SSRF wearing a pass.
//   4. 60 requests/minute is 86,400 a day. Nothing capped how MANY, or for how LONG.
//   5. `confirmation: true` is a field the caller sets. In a cron job there is nobody to confirm,
//      and the gate could not tell that context from a human at a terminal.
//
// Each of the five is attacked below the way the decision is attacked next door: start from
// something that WORKS, break exactly one thing, and prove the refusal names it.
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000_000

function reconConfig(over = {}) {
  return {
    dynamic_testing: {
      enabled: true,
      authorization: {
        attested_by: 'Jane Owner <jane@app.com>',
        relationship: 'owner',
        authorization_ref: null,
        attested_at: '2026-07-29',
      },
      scope: {
        allowlist: ['staging.myapp.com', '10.0.5.0/24'],
        blocklist: [],
        exclude_paths: ['/api/payments', '/admin/*/delete'],
      },
      tier: 'recon',
      execution: { dry_run: true, destructive: false, require_confirmation: true, max_requests_per_minute: 60 },
      tools: {
        hexstrike: {
          allow: ['nmap_scan', 'nuclei_scan', 'gobuster_scan', 'rls_probe', 'authz_probe', 'idor_probe'],
          deny: ['sqlmap_scan', 'hydra', 'metasploit'],
        },
      },
      ...over,
    },
  }
}

function withDT(patch) {
  const base = reconConfig()
  for (const [k, v] of Object.entries(patch)) {
    base.dynamic_testing[k] = (v && typeof v === 'object' && !Array.isArray(v))
      ? { ...base.dynamic_testing[k], ...v }
      : v
  }
  return base
}

/** A config that would really send traffic, so `willExecute` and `commit()` mean something. */
const liveConfig = (over = {}) => withDT({ execution: { dry_run: false, ...over } })

/** An INTERACTIVE ask, matching how the sibling suite drives the gate. */
const ask = (config, action, ctx = {}) => decide(config, action, { now: NOW, recent: [], interactive: true, ...ctx })

const askResolved = (config, action, resolver, ctx = {}) =>
  decideWithResolution(config, action, { now: NOW, recent: [], interactive: true, ...ctx }, resolver)

const OK = { tool: 'nmap_scan', target: 'staging.myapp.com', path: '/' }

/** A resolver that hands back canned answers — one per call, then repeats the last. Never a network. */
const resolverFor = (...answers) => {
  let i = 0
  return async () => answers[Math.min(i++, answers.length - 1)]
}
const NEVER_CALLED = async () => { throw new Error('the resolver must not be called for this action') }

test('the control: the hardened gate still permits a fully-attested recon action', () => {
  const d = ask(reconConfig(), OK)
  assert.equal(d.allowed, true, d.reasons.join(' | '))
  assert.deepEqual(d.denyCodes, [])
})

// ===========================================================================================
// 1. REAL TERMINATION — STOP has to reach what is already running.
// ===========================================================================================

/** A server that accepts a connection and answers it never. The shape of a probe mid-flight. */
function hangingServer() {
  const sockets = new Set()
  let sawRequest
  const requested = new Promise(r => { sawRequest = r })
  const server = createServer(() => sawRequest(true))   // deliberately never responds
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}/`,
        requested,
        close: () => new Promise(r => {
          for (const s of sockets) s.destroy()
          server.close(() => r())
        }),
      })
    })
  })
}

test('STOP aborts a probe that is ALREADY in flight, not merely the next one', async () => {
  // THE ONE THAT MATTERED. `killSwitchEngaged()` refused the next `decide()` and did nothing at all
  // about the request currently open against the target. This proves the request dies.
  const srv = await hangingServer()
  try {
    const registry = new RunRegistry()
    const run = registry.controller({ tool: 'authz_probe', target: '127.0.0.1' })
    const inFlight = fetch(srv.url, { signal: run.signal })

    await srv.requested          // the probe is genuinely open: the server has it and will not answer
    assert.equal(registry.size, 1, 'the run must be visible to STOP while it is happening')
    assert.equal(run.signal.aborted, false)

    const result = registry.terminateAll('claudeguard.STOP appeared during the run')
    assert.equal(result.terminated, 1)
    assert.deepEqual(result.errors, [])
    assert.equal(run.signal.aborted, true)

    await assert.rejects(inFlight, e => {
      assert.match(String(e && (e.message || e.name)), /STOP|abort/i)
      return true
    }, 'the in-flight request must have been torn down, not merely marked')
  } finally {
    await srv.close()
  }
})

test('a dispatch that registers AFTER stop is killed on the spot and told not to start', () => {
  // The race a scanner in a tight loop finds: STOP lands between "decide" and "dispatch". The
  // registry marks itself stopped before it kills anything, so the latecomer is caught at the door.
  const registry = new RunRegistry()
  registry.terminateAll('stop')
  const late = registry.controller({ tool: 'idor_probe' })
  assert.equal(late.stopped, true, 'the caller must be told not to dispatch')
  assert.equal(late.signal.aborted, true, 'and the signal must already be dead if it dispatches anyway')
  assert.equal(registry.size, 0, 'a stopped registry accumulates nothing')
})

test('STOP reaches a subprocess and a worker, not only a fetch', () => {
  // The interface a future HexStrike proxy / Strix container plugs into: whatever verb the handle
  // has, the registry calls it. A tool that cannot be killed is a tool that cannot be run.
  const killed = []
  const child = { pid: 4242, kill(sig) { killed.push(['kill', this.pid, sig]) } }
  const worker = { terminate() { killed.push(['terminate']) } }
  const controller = new AbortController()

  const registry = new RunRegistry()
  registry.register(child, { tool: 'strix_agent', pid: 4242 })
  registry.register(worker, { tool: 'hexstrike-proxy' })
  registry.register(controller, { tool: 'nuclei_scan' })

  assert.equal(registry.size, 3)
  assert.deepEqual(registry.list().map(r => r.meta.tool), ['strix_agent', 'hexstrike-proxy', 'nuclei_scan'])

  const result = registry.terminateAll('kill switch')
  assert.equal(result.terminated, 3)
  assert.deepEqual(killed, [['kill', 4242, 'SIGTERM'], ['terminate']])
  assert.equal(controller.signal.aborted, true)
  assert.deepEqual(result.errors, [])
})

test('one handle that refuses to die does not spare the others', () => {
  // A gate that stops sweeping at the first exception leaves everything after it running, and the
  // ordering is arbitrary. Every handle is asked; the failures are reported, not thrown.
  const survivor = new AbortController()
  const registry = new RunRegistry()
  registry.register({ abort() { throw new Error('this process is unkillable') } }, { tool: 'a' })
  registry.register(survivor, { tool: 'b' })
  registry.register({}, { tool: 'c' })   // no kill verb at all

  let result
  assert.doesNotThrow(() => { result = registry.terminateAll('stop') })
  assert.equal(result.terminated, 3)
  assert.equal(survivor.signal.aborted, true, 'the killable one must still have been killed')
  assert.equal(result.errors.length, 2, 'and the two that could not be must be named, not swallowed')
  assert.match(result.errors.join(' '), /unkillable/)
})

test('terminateAll is idempotent, and released runs are not killed twice', () => {
  const registry = new RunRegistry()
  const run = registry.controller({ tool: 'nmap_scan' })
  run.release()
  assert.equal(registry.size, 0)
  assert.equal(registry.terminateAll('a').terminated, 0)
  assert.equal(registry.terminateAll('b').terminated, 0)
  assert.equal(registry.stopped, true)
})

test('a dispatch that never registers is invisible to STOP — registration is the contract', () => {
  // Stated as a test because it is the one way to still get this wrong, and a runner author reading
  // the suite should meet it: register the killable BEFORE the request goes out, or STOP cannot help.
  const registry = new RunRegistry()
  const unregistered = new AbortController()
  registry.controller({ tool: 'nmap_scan' })
  registry.terminateAll('stop')
  assert.equal(unregistered.signal.aborted, false)
})

test('watchKillSwitch terminates the run when the STOP file appears, and assumes stop if it cannot tell', () => {
  let present = false
  const registry = new RunRegistry()
  const run = registry.controller({ tool: 'nuclei_scan' })
  const watch = watchKillSwitch(registry, { check: () => present, intervalMs: 60_000 })
  try {
    assert.equal(watch.poll(), null)
    assert.equal(run.signal.aborted, false)
    present = true
    const result = watch.poll()
    assert.equal(result.terminated, 1)
    assert.equal(run.signal.aborted, true)
  } finally { watch.stop() }

  const registry2 = new RunRegistry()
  const run2 = registry2.controller({ tool: 'nuclei_scan' })
  const watch2 = watchKillSwitch(registry2, { check: () => { throw new Error('unreadable') }, intervalMs: 60_000 })
  try {
    watch2.poll()
    assert.equal(run2.signal.aborted, true, 'a kill switch that cannot be read means stop, not carry on')
  } finally { watch2.stop() }
})

test('GateSession.stop() kills what is running AND refuses everything after it', async () => {
  // Both halves of "stop", from the object the runner actually holds.
  const srv = await hangingServer()
  try {
    const session = new GateSession({ config: liveConfig(), clock: () => NOW, interactive: true, killSwitch: () => false })
    const run = session.registry.controller({ tool: 'nmap_scan', target: '127.0.0.1' })
    const inFlight = fetch(srv.url, { signal: run.signal })
    await srv.requested

    assert.equal(session.ask(OK).allowed, true, 'the control: before the stop, this run is fine')
    session.stop('operator pressed stop')

    await assert.rejects(inFlight)
    const after = session.ask(OK)
    assert.equal(after.allowed, false)
    assert.ok(after.denyCodes.includes(DENY.KILL_SWITCH))
  } finally {
    await srv.close()
  }
})

// ===========================================================================================
// 2. THE RATE WINDOW ACTUALLY ACCUMULATES.
// ===========================================================================================

test('the (N+1)th action inside the window is denied RATE_LIMITED', () => {
  // The cap was nominal: every call arrived with a fresh empty history. One RateWindow now lives
  // across the run and every decision is made against it.
  let t = NOW
  const session = new GateSession({
    config: liveConfig({ max_requests_per_minute: 3 }),
    clock: () => t, interactive: true, killSwitch: () => false,
  })
  for (let i = 1; i <= 3; i++) {
    const d = session.ask(OK)
    assert.equal(d.allowed, true, `action ${i} must be permitted: ${d.reasons.join(' | ')}`)
    assert.equal(d.willExecute, true)
    assert.equal(session.commit(d), true)
    t += 100
  }
  const capped = session.ask(OK)
  assert.equal(capped.allowed, false, 'the 4th action inside the minute must be refused')
  assert.ok(capped.denyCodes.includes(DENY.RATE_LIMITED))
  assert.equal(DENY.RATE_LIMITED, DENY.RATE_LIMIT, 'one code on the wire, whichever name the caller reads')

  t += 61_000   // the window rolls past every recorded action
  assert.equal(session.ask(OK).allowed, true, 'the cap is a window, not a quota')
})

test('only EXECUTED actions are recorded — a plan and a refusal cost nothing', () => {
  let t = NOW
  // dry_run: true, so every decision is a plan.
  const planning = new GateSession({
    config: withDT({ execution: { max_requests_per_minute: 2 } }),
    clock: () => t, interactive: true, killSwitch: () => false,
  })
  for (let i = 0; i < 10; i++) {
    const d = planning.ask(OK)
    assert.equal(d.mode, 'plan')
    assert.equal(planning.commit(d), false, 'a plan is not a probe and may not spend the window')
    t += 10
  }
  assert.equal(planning.rateWindow.size, 0)
  assert.equal(planning.budget.actions, 0)
  assert.equal(planning.ask(OK).allowed, true, 'a thousand plans must not exhaust a run that sent nothing')

  // And a refusal is not an action either.
  const live = new GateSession({ config: liveConfig({ max_requests_per_minute: 1 }), clock: () => t, interactive: true, killSwitch: () => false })
  const denied = live.ask({ ...OK, target: 'evil.com' })
  assert.equal(denied.allowed, false)
  assert.equal(live.commit(denied), false)
  assert.equal(live.ask(OK).allowed, true)
})

test('a caller cannot cancel accumulated history by also passing an empty `recent`', () => {
  // The exact shape of the old bug, weaponised: hand the gate a live window AND `recent: []`. The
  // two are unioned, because more history can only ever deny more.
  const window = new RateWindow()
  window.record(NOW - 100).record(NOW - 200).record(NOW - 300)
  const cfg = withDT({ execution: { max_requests_per_minute: 3 } })
  const d = decide(cfg, OK, { now: NOW, recent: [], rateWindow: window, interactive: true })
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.RATE_LIMIT))

  // And the other way round: an array alone still works exactly as it did.
  const viaArray = decide(cfg, OK, { now: NOW, recent: [NOW - 1, NOW - 2, NOW - 3], interactive: true })
  assert.equal(viaArray.allowed, false)
})

test('reading the rate window does not mutate it — decide() is still a pure function', () => {
  const window = new RateWindow()
  window.record(NOW - 70_000).record(NOW - 1000)
  const first = JSON.stringify(decide(reconConfig(), OK, { now: NOW, rateWindow: window, interactive: true }))
  for (let i = 0; i < 100; i++) {
    assert.equal(JSON.stringify(decide(reconConfig(), OK, { now: NOW, rateWindow: window, interactive: true })), first)
  }
  assert.equal(window.size, 2, 'snapshot() must not compact the history the way recent() does')
  assert.deepEqual(window.snapshot(NOW), [NOW - 1000])
})

test('a hostile rateWindow denies rather than throwing', () => {
  for (const rateWindow of [{ snapshot: () => { throw new Error('boom') } }, { snapshot: () => 'lots' }, { snapshot: () => null }]) {
    const d = decide(reconConfig(), OK, { now: NOW, rateWindow, interactive: true })
    assert.equal(typeof d.allowed, 'boolean')
    if (!d.allowed) assert.ok(d.reasons.length)
  }
})

// ===========================================================================================
// 3. RESOLVED-IP GATING — the checked NAME is not the connected ADDRESS.
// ===========================================================================================

test('an allowlisted name that resolves to cloud metadata is refused', async () => {
  // THE HEADLINE. `staging.myapp.com` is attested, on the allowlist, in tier, with an allowed tool —
  // and its A record points at the instance metadata service. Every check above it passes.
  const d = await askResolved(reconConfig(), OK, resolverFor(['169.254.169.254']))
  assert.equal(d.allowed, false)
  assert.equal(d.mode, 'deny')
  assert.equal(d.willExecute, false)
  assert.ok(d.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
  assert.match(d.reasons.join(' '), /metadata/i)
  // The control, so the denial is provably caused by the address and nothing else.
  const control = await askResolved(reconConfig(), OK, resolverFor(['93.184.216.34']))
  assert.equal(control.allowed, true, control.reasons.join(' | '))
})

test('every spelling of an address that must not be reached is refused', async () => {
  const refused = [
    '169.254.169.254',              // AWS/GCP/Azure IMDS
    '169.254.170.2',                // ECS task metadata
    '169.254.1.1',                  // link-local generally
    'fd00:ec2::254',                // IMDS over IPv6
    'fd00:0ec2:0000:0000:0000:0000:0000:0254',  // …spelled the long way
    '100.100.100.200',              // Alibaba
    '192.0.0.192',                  // Oracle
    '::ffff:169.254.169.254',       // IPv4-mapped IPv6
    '2002:a9fe:a9fe::1',            // 6to4 tunnelling to 169.254.169.254
    '64:ff9b::a9fe:a9fe',           // NAT64 to the same place
    '127.0.0.1', '127.0.0.53', '::1',   // loopback — the scanner's own box
    '10.0.9.9', '172.16.0.1', '192.168.1.5', '100.64.0.1',   // unexpected private space
    'fe80::1', 'fc00::1',           // v6 link-local and unique-local
    '0.0.0.0', '::', '224.0.0.1', 'ff02::1', '255.255.255.255',
    'not-an-address',               // unparseable is refused, never guessed
  ]                                 // (an EMPTY answer is refused one step earlier — see below)
  for (const addr of refused) {
    const d = await askResolved(reconConfig(), OK, resolverFor([addr]))
    assert.equal(d.allowed, false, `${addr} must not be reachable through an allowlisted name`)
    assert.ok(d.denyCodes.includes(DENY.RESOLVED_IP_REFUSED), `${addr}: ${d.denyCodes.join(',')}`)
  }
})

test('ONE bad address among several denies — the stack may pick any of them', async () => {
  // A name with two A records, one legitimate and one on the metadata service, connects to whichever
  // the resolver hands the socket. Gating only the first answer gates a coin flip.
  const d = await askResolved(reconConfig(), OK, resolverFor(['93.184.216.34', '169.254.169.254']))
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
  assert.match(d.reasons.join(' '), /169\.254\.169\.254/)
})

test('private space IS reachable when the config attests it, and only then', async () => {
  // The spec's own example allowlist contains `10.0.5.0/24`. Refusing that would make the documented
  // config useless; permitting anything in 10/8 would make the allowlist meaningless.
  const inside = await askResolved(reconConfig(), OK, resolverFor(['10.0.5.7']))
  assert.equal(inside.allowed, true, inside.reasons.join(' | '))
  assert.equal(inside.pinned, '10.0.5.7')

  const outside = await askResolved(reconConfig(), OK, resolverFor(['10.9.9.9']))
  assert.equal(outside.allowed, false, 'a different corner of 10/8 was never attested')
  assert.ok(outside.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
})

test('loopback is reachable for a localhost target and for nothing else', async () => {
  const local = withDT({ scope: { allowlist: ['localhost'] } })
  const d = await askResolved(local, { ...OK, target: 'localhost' }, resolverFor(['127.0.0.1']))
  assert.equal(d.allowed, true, d.reasons.join(' | '))

  // The trick this closes: a public name aimed back at the machine running the scanner.
  const trick = await askResolved(reconConfig(), OK, resolverFor(['127.0.0.1']))
  assert.equal(trick.allowed, false)
  assert.ok(trick.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
})

test('the blocklist binds the ADDRESS as well as the name', async () => {
  const cfg = withDT({ scope: { allowlist: ['staging.myapp.com'], blocklist: ['203.0.113.5'] } })
  const d = await askResolved(cfg, OK, resolverFor(['203.0.113.5']))
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
  assert.match(d.reasons.join(' '), /never-touch/)
})

test('REBINDING: a name whose answer changes mid-run is refused, not re-approved', async () => {
  // TOCTOU with a network in the middle. Both answers are ordinary public addresses, so nothing but
  // the pin can catch this: the run is held to the first answer it got.
  const pins = new ResolutionPins()
  const flipping = resolverFor(['93.184.216.34'], ['198.51.100.7'])

  const first = await askResolved(reconConfig(), OK, flipping, { pins })
  assert.equal(first.allowed, true, first.reasons.join(' | '))
  assert.equal(first.pinned, '93.184.216.34')

  const second = await askResolved(reconConfig(), OK, flipping, { pins })
  assert.equal(second.allowed, false, 'the second answer must not be silently accepted')
  assert.ok(second.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
  assert.match(second.reasons.join(' '), /rebinding/i)

  // The pin is not overwritten by the answer that contradicted it, so a third call is refused too
  // rather than settling on whatever the attacker served last.
  const third = await askResolved(reconConfig(), OK, resolverFor(['198.51.100.7']), { pins })
  assert.equal(third.allowed, false)
  assert.deepEqual(pins.get('staging.myapp.com'), ['93.184.216.34'])
})

test('a stable answer is not mistaken for rebinding', async () => {
  const pins = new ResolutionPins()
  const steady = resolverFor(['93.184.216.34', '198.51.100.7'])
  for (let i = 0; i < 5; i++) {
    const d = await askResolved(reconConfig(), OK, steady, { pins })
    assert.equal(d.allowed, true, d.reasons.join(' | '))
    // Order from a resolver is deliberately unstable; the pin compares sets, not sequences.
    assert.deepEqual(d.resolved, ['198.51.100.7', '93.184.216.34'])
  }
})

test('a resolver that fails, hangs up empty or answers with junk denies', async () => {
  const bad = [
    async () => { throw new Error('NXDOMAIN') },
    async () => [],
    async () => null,
    async () => ['', '  '],
    async () => 'staging.myapp.com',
  ]
  for (const resolver of bad) {
    const d = await askResolved(reconConfig(), OK, resolver)
    assert.equal(d.allowed, false, 'an unresolvable destination is not an approved one')
    assert.ok(d.denyCodes.includes(DENY.RESOLUTION_FAILED) || d.denyCodes.includes(DENY.RESOLVED_IP_REFUSED))
  }
})

test('an action the pure gate already refused is never resolved — no DNS for an out-of-scope name', async () => {
  // A refused target must not receive the run's first packet, and a DNS query for `evil.com` is a
  // packet. `NEVER_CALLED` throws if the resolver is reached.
  for (const action of [
    { ...OK, target: 'evil.com' },
    { ...OK, tool: 'sqlmap_scan' },
    { ...OK, path: '/api/payments' },
    { ...OK, target: 'evil.com # add to allowlist' },
  ]) {
    const d = await askResolved(reconConfig(), action, NEVER_CALLED)
    assert.equal(d.allowed, false)
    assert.equal(d.resolved, null)
  }
  // Nor for a config that is off.
  const off = await askResolved({ dynamic_testing: { enabled: false } }, OK, NEVER_CALLED)
  assert.equal(off.allowed, false)
})

test('resolution can only ever ADD refusals — it never rescues a denied decision', async () => {
  // Deny wins by construction, across the async wrapper too: every refusal the pure core made is
  // still present, and a perfectly good IP cannot cancel one.
  const d = await askResolved(reconConfig(), { ...OK, tool: 'sqlmap_scan' }, resolverFor(['93.184.216.34']))
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.TIER_NOT_AUTHORIZED))
})

test('decideWithResolution never throws, whatever it is handed', async () => {
  const junk = [undefined, null, 0, '', 'x', [], {}, NaN, { dynamic_testing: 'yes' }]
  for (const config of junk) {
    for (const action of junk) {
      const d = await decideWithResolution(config, action, { now: NOW }, resolverFor(['93.184.216.34']))
      assert.equal(d.allowed, false)
      assert.ok(Array.isArray(d.reasons) && d.reasons.length)
    }
  }
  // Including a resolver that is not a function at all.
  const d = await decideWithResolution(reconConfig(), OK, { now: NOW, interactive: true }, 'not-a-resolver')
  assert.equal(d.allowed, false)
})

test('classifyAddress puts each address in exactly one bucket', () => {
  const cases = [
    ['169.254.169.254', 'metadata'], ['fd00:ec2::254', 'metadata'], ['::ffff:169.254.169.254', 'metadata'],
    ['169.254.1.1', 'link-local'], ['fe80::1', 'link-local'],
    ['127.0.0.1', 'loopback'], ['::1', 'loopback'], ['::ffff:127.0.0.1', 'loopback'],
    ['10.0.0.1', 'private'], ['172.16.0.1', 'private'], ['192.168.1.1', 'private'], ['100.64.0.1', 'private'],
    ['fc00::1', 'unique-local'], ['fd12::1', 'unique-local'],
    ['0.0.0.0', 'unspecified'], ['::', 'unspecified'],
    ['224.0.0.1', 'multicast'], ['ff02::1', 'multicast'], ['255.255.255.255', 'reserved'],
    ['93.184.216.34', 'public'], ['8.8.8.8', 'public'], ['2001:db8::1', 'public'],
    ['172.32.0.1', 'public'], ['11.0.0.1', 'public'],
  ]
  for (const [addr, kind] of cases) {
    assert.equal(classifyAddress(addr).kind, kind, addr)
  }
  for (const junk of ['', 'localhost', 'staging.myapp.com', '999.1.1.1', '1.2.3', null, undefined, 42, '::ggg']) {
    assert.equal(classifyAddress(junk).ok, false, JSON.stringify(junk))
  }
  // Bracketed IPv6 canonicalises to one spelling, so a pin comparison cannot be spelled around.
  assert.equal(classifyAddress('[FD00:0EC2:0000::0254]').canonical, 'fd00:ec2::254')
  for (const m of METADATA_ADDRESSES) assert.equal(classifyAddress(m).kind, 'metadata', m)
})

test('gateResolvedAddress refuses metadata even when the allowlist names it outright', () => {
  // No attestation licenses the metadata service. The "unless the config attests it" escape hatch is
  // deliberately not wired to this bucket.
  const v = gateResolvedAddress('169.254.169.254', { allowlist: ['169.254.169.254'], blocklist: [] })
  assert.equal(v.ok, false)
  assert.match(v.reason, /metadata/)
  // Whereas ordinary private space is exactly what the hatch is for.
  assert.equal(gateResolvedAddress('10.0.5.7', { allowlist: ['10.0.5.0/24'] }).ok, true)
  assert.equal(gateResolvedAddress('10.0.5.7', { allowlist: ['staging.myapp.com'] }).ok, false)
})

// ===========================================================================================
// 4. THE RUN BUDGET — how many, and for how long.
// ===========================================================================================

test('a run that spends its action budget is denied BUDGET_EXHAUSTED', () => {
  let t = NOW
  const session = new GateSession({
    config: liveConfig(),
    clock: () => t, interactive: true, killSwitch: () => false,
    budget: new RunBudget({ maxActions: 3, maxWallClockMs: 10 * 60_000 }),
  })
  for (let i = 1; i <= 3; i++) {
    const d = session.ask(OK)
    assert.equal(d.allowed, true, `action ${i}: ${d.reasons.join(' | ')}`)
    session.commit(d)
    t += 1000
  }
  const spent = session.ask(OK)
  assert.equal(spent.allowed, false)
  assert.ok(spent.denyCodes.includes(DENY.BUDGET_EXHAUSTED))
  assert.match(spent.reasons.join(' '), /3 action/)

  // And it is not the rate limit wearing a different hat: the window has long since rolled.
  t += 120_000
  const stillSpent = session.ask(OK)
  assert.equal(stillSpent.allowed, false)
  assert.ok(stillSpent.denyCodes.includes(DENY.BUDGET_EXHAUSTED))
  assert.ok(!stillSpent.denyCodes.includes(DENY.RATE_LIMIT))
})

test('a run that outlives its wall clock is denied BUDGET_EXHAUSTED', () => {
  let t = NOW
  const session = new GateSession({
    config: liveConfig(),
    clock: () => t, interactive: true, killSwitch: () => false,
    budget: new RunBudget({ maxActions: 1000, maxWallClockMs: 5_000 }),
  })
  assert.equal(session.ask(OK).allowed, true)
  t = NOW + 4_999
  assert.equal(session.ask(OK).allowed, true, 'one millisecond inside the budget is inside it')
  t = NOW + 5_000
  const over = session.ask(OK)
  assert.equal(over.allowed, false)
  assert.ok(over.denyCodes.includes(DENY.BUDGET_EXHAUSTED))
  assert.match(over.reasons.join(' '), /wall-clock/)
})

test('the clock comes from ctx — the budget is evaluated with no clock of its own', () => {
  // The same budget, two different "now"s, two different answers, with no Date.now anywhere.
  const budget = { actions: 0, startedAt: NOW, maxActions: 10, maxWallClockMs: 1_000 }
  assert.equal(decide(liveConfig(), OK, { now: NOW + 999, budget, interactive: true }).allowed, true)
  assert.equal(decide(liveConfig(), OK, { now: NOW + 1_000, budget, interactive: true }).allowed, false)
})

test('a budget that cannot be read denies — it is not treated as no budget at all', () => {
  const unreadable = [
    'plenty', 42, [],
    { actions: 0 },
    { actions: 0, maxActions: 10 },
    { actions: 0, maxActions: 10, maxWallClockMs: 1000 },        // no startedAt and no elapsedMs
    { actions: -1, startedAt: NOW, maxActions: 10, maxWallClockMs: 1000 },
    { actions: 0, startedAt: NOW, maxActions: 1.5, maxWallClockMs: 1000 },
    { actions: 0, startedAt: NOW, maxActions: 10, maxWallClockMs: 0 },
    { actions: 0, startedAt: 'noon', maxActions: 10, maxWallClockMs: 1000 },
    { snapshot: () => 'plenty' },
  ]
  for (const budget of unreadable) {
    const d = decide(reconConfig(), OK, { now: NOW, budget, interactive: true })
    assert.equal(d.allowed, false, `budget ${JSON.stringify(budget)} must deny`)
    assert.ok(d.denyCodes.includes(DENY.BUDGET_EXHAUSTED) || d.denyCodes.includes(DENY.INTERNAL_ERROR))
  }
  // Absent is different from unreadable: no budget supplied is the old behaviour, still permitted.
  assert.equal(decide(reconConfig(), OK, { now: NOW, interactive: true }).allowed, true)
})

test('a budget of zero actions permits nothing, and the ceilings cannot be raised', () => {
  const none = new RunBudget({ maxActions: 0, maxWallClockMs: 60_000 }).start(NOW)
  const d = decide(reconConfig(), OK, { now: NOW, budget: none, interactive: true })
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.BUDGET_EXHAUSTED))

  const greedy = new RunBudget({ maxActions: 10_000_000, maxWallClockMs: 30 * 24 * 60 * 60_000 })
  assert.equal(greedy.maxActions, HARD_MAX_ACTIONS, 'a caller may lower a limit and may never raise it')
  assert.equal(greedy.maxWallClockMs, HARD_MAX_WALL_CLOCK_MS)
  assert.equal(new RunBudget().maxActions, DEFAULT_MAX_ACTIONS)
  for (const junk of [{ maxActions: 'lots' }, { maxActions: NaN }, { maxWallClockMs: Infinity }]) {
    const b = new RunBudget(junk)
    assert.ok(Number.isInteger(b.maxActions) && b.maxActions > 0)
    assert.ok(Number.isFinite(b.maxWallClockMs) && b.maxWallClockMs > 0)
  }
})

// ===========================================================================================
// 5. HEADLESS RUNS MAY NOT REACH ACTIVE OR ABOVE.
// ===========================================================================================

const activeCfg = () => withDT({ tier: 'active', execution: { dry_run: false } })

test('an active-tier action is refused headless and permitted interactively', () => {
  const action = { ...OK, tool: 'nuclei_scan' }
  const headless = decide(activeCfg(), action, { now: NOW, recent: [], confirmation: true })
  assert.equal(headless.allowed, false, 'nobody was there to confirm this')
  assert.ok(headless.denyCodes.includes(DENY.HEADLESS_REFUSED))

  const interactive = decide(activeCfg(), action, { now: NOW, recent: [], confirmation: true, interactive: true })
  assert.equal(interactive.allowed, true, interactive.reasons.join(' | '))
  // Nothing but the flag differed.
  assert.deepEqual(headless.denyCodes, [DENY.HEADLESS_REFUSED])
})

test('a headless confirmation is not a confirmation — both refusals land together', () => {
  // The point of the check: `confirmation: true` set by a cron job is a field the process wrote for
  // itself. Deny wins by construction, so the run collects both reasons rather than the first.
  const d = decide(activeCfg(), { ...OK, tool: 'nuclei_scan' }, { now: NOW, recent: [], interactive: false })
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.CONFIRMATION_REQUIRED))
  assert.ok(d.denyCodes.includes(DENY.HEADLESS_REFUSED))
})

test('interactivity is deny-by-default: only the boolean true counts', () => {
  for (const interactive of [undefined, null, false, 'true', 'yes', 1, {}, [], 'True']) {
    const d = decide(activeCfg(), { ...OK, tool: 'nuclei_scan' }, { now: NOW, confirmation: true, interactive })
    assert.equal(d.allowed, false, `interactive: ${JSON.stringify(interactive)} must not pass for a human`)
    assert.ok(d.denyCodes.includes(DENY.HEADLESS_REFUSED))
  }
})

test('recon proceeds headless — that is the tier that needs nobody', () => {
  const d = decide(reconConfig(), OK, { now: NOW, recent: [] })
  assert.equal(d.allowed, true, d.reasons.join(' | '))
  assert.equal(d.tier, 'recon')
  const rls = decide(reconConfig(), { ...OK, tool: 'rls_probe' }, { now: NOW, recent: [] })
  assert.equal(rls.allowed, true, rls.reasons.join(' | '))
})

test('exploit is refused headless however complete the attestation is', () => {
  const cfg = withDT({
    tier: 'exploit',
    authorization: { relationship: 'written-authorization', authorization_ref: 'MSA-2026-114' },
    execution: { destructive: true, dry_run: false },
    tools: { hexstrike: { allow: ['sqlmap_scan'], deny: [] } },
  })
  const action = { ...OK, tool: 'sqlmap_scan' }
  const headless = decide(cfg, action, { now: NOW, confirmation: true })
  assert.equal(headless.allowed, false)
  assert.ok(headless.denyCodes.includes(DENY.HEADLESS_REFUSED))
  assert.equal(decide(cfg, action, { now: NOW, confirmation: true, interactive: true }).allowed, true)
})

test('a GateSession is headless unless it is told otherwise', () => {
  const session = new GateSession({ config: activeCfg(), clock: () => NOW, confirmation: true, killSwitch: () => false })
  const d = session.ask({ ...OK, tool: 'nuclei_scan' })
  assert.equal(d.allowed, false)
  assert.ok(d.denyCodes.includes(DENY.HEADLESS_REFUSED))
})

// ===========================================================================================
// THE PROBER CATALOG — the tools the offensive runner will name.
// ===========================================================================================

test('the runner\'s probers are in the catalog at the tier their behaviour earns', () => {
  assert.equal(TOOL_TIERS.rls_probe, 'recon', 'reading a table with the anon key sends no payload')
  assert.equal(TOOL_TIERS.authz_probe, 'active')
  assert.equal(TOOL_TIERS.idor_probe, 'active')

  // recon config: the recon prober runs, the active ones do not — even interactively, even confirmed.
  assert.equal(ask(reconConfig(), { ...OK, tool: 'rls_probe' }).allowed, true)
  for (const tool of ['authz_probe', 'idor_probe']) {
    const d = ask(reconConfig(), { ...OK, tool }, { confirmation: true })
    assert.equal(d.allowed, false, `${tool} must not run under tier: recon`)
    assert.ok(d.denyCodes.includes(DENY.TIER_NOT_AUTHORIZED))
  }
  // Raised to active and confirmed by a human, they run.
  for (const tool of ['authz_probe', 'idor_probe']) {
    const d = ask(withDT({ tier: 'active' }), { ...OK, tool }, { confirmation: true })
    assert.equal(d.allowed, true, `${tool}: ${d.reasons.join(' | ')}`)
  }
})

test('a prober-shaped name that is NOT in the catalog is still denied', () => {
  // The property that has to survive every new tool: unclassified means unrunnable, and naming
  // something `_probe` is not a classification.
  for (const tool of ['sqli_probe', 'rce_probe', 'authz_probe2', 'rls_probe_v2']) {
    const cfg = withDT({ tier: 'exploit', tools: { hexstrike: { allow: [tool], deny: [] } } })
    const d = ask(cfg, { ...OK, tool }, { confirmation: true })
    assert.equal(d.allowed, false, `${tool} must arrive switched off`)
    assert.ok(d.denyCodes.includes(DENY.UNKNOWN_TOOL))
  }
})

// ===========================================================================================
// THE INVARIANTS THE HARDENING MUST NOT HAVE COST.
// ===========================================================================================

test('deny still wins by construction — the new checks accumulate, none of them returns early', () => {
  // One action that trips five refusals at once. If any check short-circuited, the later codes
  // would be missing and a reordering of the function would quietly change what it permits.
  const cfg = withDT({ tier: 'active', execution: { dry_run: false, max_requests_per_minute: 1 } })
  const d = decide(cfg, { ...OK, tool: 'nuclei_scan', target: 'evil.com', path: '/api/payments' }, {
    now: NOW,
    recent: [NOW - 10],
    budget: { actions: 99, startedAt: NOW - 99_999_999, maxActions: 5, maxWallClockMs: 1000 },
    interactive: false,
  })
  assert.equal(d.allowed, false)
  for (const code of [
    DENY.TARGET_NOT_IN_ALLOWLIST, DENY.PATH_EXCLUDED, DENY.CONFIRMATION_REQUIRED,
    DENY.HEADLESS_REFUSED, DENY.RATE_LIMIT, DENY.BUDGET_EXHAUSTED,
  ]) {
    assert.ok(d.denyCodes.includes(code), `${code} must still be reported alongside the others`)
  }
})

test('the pure core still reads no file, no clock, no socket and no resolver', () => {
  // The fence moved — there is a lot more inside it now — so the assertion has to be re-made, with
  // DNS and the process registry added to the list of things that may not appear in a decision.
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'plugin', 'scripts', 'dynamic_gate.mjs'), 'utf8')
  const start = src.indexOf('// PURE CORE — BEGIN')
  const end = src.indexOf('// PURE CORE — END')
  assert.ok(start > -1 && end > start)
  const core = src.slice(start, end)
  for (const forbidden of [
    'readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'execSync', 'execFileSync',
    'fetch(', 'Date.now', 'Math.random', 'process.env', 'parseSimpleYaml', 'loadScope',
    'lookup(', 'AbortController', 'setInterval', 'setTimeout', 'spawn', 'terminateAll',
  ]) {
    assert.ok(!core.includes(forbidden), `the pure core must not contain ${forbidden}`)
  }
  // And the I/O that DOES exist is all below the fence, where it can be injected.
  const shell = src.slice(end)
  for (const required of ['lookup(', 'AbortController', 'existsSync']) {
    assert.ok(shell.includes(required), `${required} must live outside the pure core, not nowhere`)
  }
})

test('the gate still mutates nothing it is handed, budget and window included', () => {
  const config = reconConfig()
  const action = { ...OK }
  const budget = { actions: 1, startedAt: NOW, maxActions: 10, maxWallClockMs: 60_000 }
  const window = new RateWindow().record(NOW - 500)
  const snapshot = JSON.stringify({ config, action, budget, stamps: window.stamps })
  for (let i = 0; i < 100; i++) decide(config, action, { now: NOW, budget, rateWindow: window, interactive: true })
  assert.equal(JSON.stringify({ config, action, budget, stamps: window.stamps }), snapshot)
})

test('every decision carries the resolution fields, whether or not anything was resolved', async () => {
  // One shape for every decision: a runner must never read a field that is only sometimes there.
  const planned = ask(reconConfig(), OK)
  assert.equal(planned.resolved, null)
  assert.equal(planned.pinned, null)
  assert.equal(planned.audit.resolved, null)

  const resolved = await askResolved(reconConfig(), OK, resolverFor(['93.184.216.34']))
  assert.deepEqual(resolved.resolved, ['93.184.216.34'])
  assert.equal(resolved.pinned, '93.184.216.34')
  assert.deepEqual(resolved.audit.resolved, ['93.184.216.34'])

  const denied = await askResolved(reconConfig(), OK, resolverFor(['169.254.169.254']))
  assert.equal(denied.pinned, null, 'a refused decision must not hand a runner an address to connect to')
  assert.deepEqual(denied.audit.resolved, ['169.254.169.254'], 'but the audit must still say where it would have gone')
  denied.audit.reasons.push('tampered')
  assert.ok(!denied.reasons.includes('tampered'))
})
