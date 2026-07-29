import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { gateSupabaseProject, isNeverTouch, gateTier1 } from '../plugin/scripts/_scope.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// `live_probe.mjs` gates its main `--url` and then, for the optional Supabase RLS spot-check, did
// this:
//
//     const su = normalizeHost(args['supabase-url'])          // computed…
//     // still respect the gate: the supabase host must not be blocked-by-target-rules?
//     //                                             It's the user's own project.
//     const q = `${args['supabase-url']…}/rest/v1/${args.table}?select=*&limit=1`
//     await fetch(q, { headers: { apikey: KEY, Authorization: 'Bearer ' + KEY } })
//
// `su` was never used. The comment beside it is the right question, unanswered, shipped. The fetch
// used the RAW argument and carried the user's anon key in two headers, so naming any host on the
// command line sent that credential there while the gate had approved a different one entirely.
// An external review found it; a listener on an unauthorised host received the key verbatim.
//
// This is the same checked-versus-used gap as the `@`-userinfo bypass, on a second parameter — and
// worse, because this one hands over a secret rather than merely contacting the wrong machine.
//
// It could not be fixed by calling gateTier1: every Supabase host is in DEFAULT_BLOCKED, so Tier 1
// refuses the one host class this check exists to probe. That is presumably why the gate was
// skipped rather than fixed. So the user's own project gets its own attestation, and the request is
// built from the ATTESTED value rather than the argument.
// ---------------------------------------------------------------------------

const base = { enabled: true, i_own_or_control_these_targets: true }
const scopeFor = project => ({
  targets: ['app.example.com'],
  never_touch: [],
  passive_live: { ...base, supabase_project: project },
})
const OWN = 'https://abcdefgh.supabase.co'

test('THE BYPASS: a host the caller names but never attested is refused', () => {
  const g = gateSupabaseProject('http://127.0.0.1:9127', scopeFor(OWN))
  assert.equal(g.allowed, false)
  assert.equal(g.origin, null, 'and no origin is handed back for a request to be built from')
})

test('a userinfo prefix cannot disguise the destination', () => {
  // `https://abcdefgh.supabase.co@evil.com` reaches evil.com. Same family as the Tier-1 bypass.
  const g = gateSupabaseProject(`${OWN}@evil.com`, scopeFor(OWN))
  assert.equal(g.allowed, false)
})

test('a lookalike suffix is not the attested project', () => {
  const g = gateSupabaseProject('https://abcdefgh.supabase.co.evil.com', scopeFor(OWN))
  assert.equal(g.allowed, false)
})

test('a DIFFERENT project on the same provider is still refused', () => {
  // Being Supabase is not the qualification; being THE attested project is.
  const g = gateSupabaseProject('https://someoneelse.supabase.co', scopeFor(OWN))
  assert.equal(g.allowed, false)
  assert.ok(g.reasons.join(' ').includes('attests'), 'and the reason names the mismatch')
})

test('with no attestation the check simply does not run', () => {
  const g = gateSupabaseProject(OWN, { targets: [], never_touch: [], passive_live: base })
  assert.equal(g.allowed, false)
  assert.match(g.reasons.join(' '), /supabase_project/)
})

test('listing the project under `targets` does NOT authorise it', () => {
  // The shortcut that would have dissolved DEFAULT_BLOCKED for every provider at once. A provider
  // host in `targets` is exactly what that list exists to refuse, so it must not be a way in.
  const scope = { targets: ['abcdefgh.supabase.co'], never_touch: [], passive_live: base }
  assert.equal(gateSupabaseProject(OWN, scope).allowed, false)
  // And Tier 1 still refuses it too, which is the behaviour that made a separate gate necessary.
  assert.equal(gateTier1('abcdefgh.supabase.co', scope).allowed, false)
})

test('never_touch beats the user\'s own attestation', () => {
  const scope = {
    targets: [], never_touch: ['abcdefgh.supabase.co'],
    passive_live: { ...base, supabase_project: OWN },
  }
  assert.equal(isNeverTouch('abcdefgh.supabase.co', scope), true)
  assert.equal(gateSupabaseProject(OWN, scope).allowed, false, 'an explicit refusal always wins')
})

test('the Tier-1 preconditions still apply', () => {
  const off = { targets: [], never_touch: [], passive_live: { enabled: false, i_own_or_control_these_targets: true, supabase_project: OWN } }
  assert.equal(gateSupabaseProject(OWN, off).allowed, false)

  const unowned = { targets: [], never_touch: [], passive_live: { enabled: true, i_own_or_control_these_targets: false, supabase_project: OWN } }
  assert.equal(gateSupabaseProject(OWN, unowned).allowed, false)
})

test('garbage input fails closed rather than throwing', () => {
  for (const bad of [null, undefined, '', 'not a url', 'javascript:alert(1)', 'file:///etc/passwd', '://']) {
    const g = gateSupabaseProject(bad, scopeFor(OWN))
    assert.equal(g.allowed, false, `${JSON.stringify(bad)} must be refused`)
  }
})

test('CONTROL: the attested project IS allowed, and yields a canonical origin', () => {
  // A suite that passes by refusing everything is worthless.
  for (const form of [OWN, `${OWN}/`, `${OWN}/rest/v1`, 'HTTPS://ABCDEFGH.SUPABASE.CO']) {
    const g = gateSupabaseProject(form, scopeFor(OWN))
    assert.equal(g.allowed, true, `${form} is the user's own attested project`)
    assert.equal(g.origin, OWN, 'and the origin is canonical, whatever form was passed in')
  }
})

test('the request is built from the ATTESTED value, not from the argument', () => {
  // The property that makes checked-and-used the same string by construction: whatever extra path,
  // query or casing the argument carried, `origin` comes from the scope file.
  const g = gateSupabaseProject(`${OWN}/rest/v1/other?select=*`, scopeFor(OWN))
  assert.equal(g.allowed, true)
  assert.equal(g.origin, OWN)
})

// ---------------------------------------------------------------------------
// End to end: prove no credential leaves the machine for a refused host.
// ---------------------------------------------------------------------------

test('END TO END: a refused destination receives nothing at all', async () => {
  let received = null
  const server = createServer((req, res) => {
    received = { apikey: req.headers.apikey, auth: req.headers.authorization }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end('[]')
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  try {
    const scope = scopeFor(OWN)
    const gate = gateSupabaseProject(`http://127.0.0.1:${port}`, scope)
    assert.equal(gate.allowed, false)
    // This is the shape live_probe.mjs now uses: no origin, no request. The old code built the URL
    // from the argument regardless and sent the key.
    if (gate.allowed) {
      await fetch(`${gate.origin}/rest/v1/t?select=*&limit=1`,
        { headers: { apikey: 'fake', Authorization: 'Bearer fake' } })
    }
    assert.equal(received, null, 'an unauthorised host must not receive a request, let alone a key')
  } finally {
    await new Promise(r => server.close(r))
  }
})
