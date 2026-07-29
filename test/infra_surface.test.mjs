import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-infra-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}
const gradeRepo = files => grade(modelOf(files))
const idsOf = r => r.findings.map(f => f.id)
const find = (r, id) => r.findings.find(f => f.id === id)

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS — audit fix C.
//
// The engine DISCOVERED workflows, Dockerfiles, compose files, Terraform and Firebase rules, and
// listed them as paths. No rule read any of them and no ledger set covered them, so a repository
// that hands its secrets to any stranger who opens a pull request produced a report identical to
// one that did not: clean. Non-Next routers were worse than that — an Express app enumerated zero
// routes, LAW 2 was still satisfied because 0 === 0, and the coverage table printed a confident
// "routes: 0" over an HTTP surface nobody had looked at.
//
// The principle these tests pin is GRADE OR DECLARE: every artifact class the engine can see either
// gets a rule, or gets a row saying it was seen and not graded. Silence is the one output that is
// never allowed, because a reader cannot tell it apart from safety.
// ---------------------------------------------------------------------------

// ===========================================================================
// THE CRY-WOLF TEST for this surface.
//
// This project's thesis is that a tool which fires at correct code loses its audience, and this
// audience cannot tell a false P0 from a real one. So: a correct workflow, a correct Dockerfile, a
// correct compose file, correct Terraform, correct Firebase rules and a correctly-guarded Express
// app. EVERY finding produced here is a false positive by construction.
// ===========================================================================

const CORRECT_INFRA = {
  'package.json': JSON.stringify({ name: 'ok', dependencies: { express: '4.19.2' } }),

  // Triggered only by push, least-privilege token, secrets passed through env rather than
  // interpolated into the shell, and the untrusted event value quoted through an env var.
  '.github/workflows/ci.yml': `name: ci
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - env:
          TITLE: \${{ github.event.head_commit.message }}
        run: echo "$TITLE"
      - run: npm ci && npm test
`,

  'Dockerfile': `FROM node:22.11.0-alpine@sha256:f2dc6eea95f787e25f173ba9904c9d0647ab2506178c7b5b7c5a3d02bc4af145
WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev
USER node
CMD ["node", "server.js"]
`,

  // A placeholder is not a secret, and a database bound to localhost is not exposed.
  'docker-compose.yml': `services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
  api:
    build: .
    depends_on: [db]
`,

  'infra/main.tf': `resource "aws_security_group_rule" "web" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "db" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  security_groups   = [aws_security_group.app.id]
}

resource "aws_db_instance" "main" {
  publicly_accessible = false
  password            = var.db_password
}
`,

  'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /users/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /{document=**} { allow read, write: if false; }
  }
}
`,

  // Auth is applied as app-level middleware before any route is registered, which is the
  // recommended Express pattern and the direct analogue of Next's middleware.ts.
  'server.js': `import express from 'express'
import rateLimit from 'express-rate-limit'
import { z } from 'zod'
import { requireAuth } from './auth.js'

const app = express()
app.use(requireAuth)
app.use(rateLimit({ windowMs: 60000, max: 30 }))

const OrderSchema = z.object({ item: z.string() })

app.get('/api/orders', async (req, res) => {
  res.json(await db.forUser(req.user.id))
})

app.post('/api/orders', async (req, res) => {
  const body = OrderSchema.parse(req.body)
  res.json(await db.insert({ ...body, user_id: req.user.id }))
})

app.listen(3000)
`,

  'auth.js': `export function requireAuth(req, res, next) {
  const session = getServerSession(req)
  if (!session) return res.status(401).end()
  req.user = session.user
  next()
}
`,
}

test('CRY WOLF: a correct workflow, Dockerfile, compose, Terraform and Firebase ruleset produce no findings', () => {
  const r = gradeRepo(CORRECT_INFRA)
  const noisy = r.findings.filter(f => /^CG-(CI|IAC|FB)-/.test(f.id))
  assert.deepEqual(noisy.map(f => `${f.id} ${f.subject}`), [],
    'every finding here is a false positive by construction')
})

test('CRY WOLF: correct infrastructure passes rather than merely producing no finding', () => {
  // Producing no finding is not the same as being accounted for. A `pass` row is what proves the
  // rule actually walked the subject, which is the whole point of the ledger.
  const r = gradeRepo(CORRECT_INFRA)
  assert.equal(r.coverage.ciWorkflows.counts.pass, 1)
  assert.equal(r.coverage.ciWorkflows.counts.fail, 0)
  assert.equal(r.coverage.iacFiles.counts.fail, 0)
  assert.equal(r.coverage.iacFiles.counts.pass, 3, 'Dockerfile, compose and terraform each pass')
  assert.equal(r.coverage.firebaseRules.counts.pass, 1)
})

test('CRY WOLF: a public 443 ingress rule is not a finding — that is what a web server is for', () => {
  const r = gradeRepo(CORRECT_INFRA)
  assert.equal(find(r, 'CG-IAC-010'), undefined,
    'flagging 0.0.0.0/0 on 443 would fire on every correctly-deployed web service')
})

test('CRY WOLF: app-level auth middleware protects the routes registered after it', () => {
  const r = gradeRepo(CORRECT_INFRA)
  const noAuth = r.findings.filter(f => f.id === 'CG-WEB-001')
  assert.deepEqual(noAuth.map(f => f.subject), [],
    'app.use(requireAuth) is the recommended Express pattern; reporting every route as unauthenticated would bury a real one')
})

// ===========================================================================
// CI/CD — the detections
// ===========================================================================

const PWN_WORKFLOW = {
  'package.json': JSON.stringify({ name: 'x' }),
  '.github/workflows/danger.yml': `name: danger
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
`,
}

test('pull_request_target that checks out and runs fork code is a confirmed P0', () => {
  // The single most dangerous shape in GitHub Actions, and entirely readable from the file: the
  // trigger grants the base repo's secrets, and the checkout replaces the code with the fork's.
  const r = grade(modelOf(PWN_WORKFLOW))
  const f = find(r, 'CG-CI-001')
  assert.ok(f, 'the fork-secret-theft pattern must be detected')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed', 'both halves are read from the file, so nothing is inferred')
  assert.equal(r.verdict.level, 'critical')
})

test('pull_request_target with no execution step after the checkout is held to likely', () => {
  // Honest gradation: the untrusted code is on disk, but nothing was identified that runs it.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: pull_request_target
permissions: { contents: read }
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
  }))
  const f = find(r, 'CG-CI-001')
  assert.ok(f)
  assert.equal(f.confidence, 'likely')
  assert.ok(f.assumption, 'the weaker claim must name what would make it wrong')
})

test('an injectable event field in a run: script is a confirmed P1', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: issues
permissions: { contents: read }
jobs:
  a:
    steps:
      - run: echo "Title: \${{ github.event.issue.title }}"
`,
  }))
  const f = find(r, 'CG-CI-002')
  assert.ok(f, 'issue titles are attacker-written and are substituted before the shell parses them')
  assert.equal(f.severity, 'P1')
  assert.equal(f.confidence, 'confirmed')
})

test('a NON-injectable event field is not reported', () => {
  // github.event.pull_request.number is an integer nobody can inject through. Flagging every
  // github.event.* reference would bury the one line that matters.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: pull_request
permissions: { contents: read }
jobs:
  a:
    steps:
      - run: echo "PR #\${{ github.event.pull_request.number }}"
`,
  }))
  assert.equal(find(r, 'CG-CI-002'), undefined)
})

test('an unpinned THIRD-PARTY action is reported and a first-party one is not', () => {
  // The realistic attack is a compromised independent maintainer. Reporting actions/checkout@v4 in
  // every repository on earth would train people to skim past this section.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: push
permissions: { contents: read }
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
      - uses: some-vendor/magic@v1
`,
  }))
  const f = find(r, 'CG-CI-003')
  assert.ok(f)
  assert.match(f.title_en, /some-vendor\/magic/)
  assert.doesNotMatch(f.title_en, /actions\/checkout/)
})

test('a SHA-pinned third-party action is not reported', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: push
permissions: { contents: read }
jobs:
  a:
    steps:
      - uses: some-vendor/magic@1e204e9a9253d643386038d443f96446fa156a97
`,
  }))
  assert.equal(find(r, 'CG-CI-003'), undefined)
})

test('a missing permissions block is needs-review, because the real default is not in the repo', () => {
  // The effective scope is an org/repo setting we cannot read. Claiming `definitive` here would be
  // asserting something the file does not say.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': "on: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
  }))
  const f = find(r, 'CG-CI-005')
  assert.ok(f)
  assert.equal(f.confidence, 'needs-review')
  assert.notEqual(r.verdict.level, 'critical')
})

test('a run: step in a DIFFERENT job does not upgrade the checkout finding to confirmed', () => {
  // Scope matters because it decides the badge. A `run:` in another job never touches this job's
  // working copy, so counting it would manufacture a definitive P0 out of a strong one — and a
  // wrong `confirmed` is the single error this project cannot afford.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: pull_request_target
permissions: { contents: read }
jobs:
  fetch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
  unrelated:
    runs-on: ubuntu-latest
    steps:
      - run: echo "this job never saw the fork's code"
`,
  }))
  const f = find(r, 'CG-CI-001')
  assert.ok(f)
  assert.equal(f.confidence, 'likely', 'the other job\'s run step must not strengthen this claim')
})

test('the quoted `"on":` key is still read as a trigger', () => {
  // YAML 1.1 reads a bare `on` as the boolean true, so many files quote it. Missing that spelling
  // would make a pull_request_target workflow look like it has no trigger at all.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `"on":
  pull_request_target:
    types: [opened]
permissions: { contents: read }
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci
`,
  }))
  const f = find(r, 'CG-CI-001')
  assert.ok(f, 'a quoted on: key must not hide the trigger')
  assert.equal(f.confidence, 'confirmed')
})

test('a trigger option is not collected as a trigger', () => {
  // `types:` under `pull_request_target:` is an option, not a trigger. Collecting it would put
  // noise in the model and could make an unrelated rule match the wrong thing.
  const m = modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': "on:\n  pull_request_target:\n    types: [opened]\n    branches: [main]\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
  })
  assert.deepEqual(m.ci[0].triggers, ['pull_request_target'])
})

test('a ref: belonging to a LATER step is not attributed to the checkout', () => {
  // Window bleed, in YAML. A safe checkout followed by an unrelated action that happens to take a
  // ref must not be read as checking out the fork's code — that would be a manufactured P0 on a
  // workflow that is doing nothing wrong.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: pull_request_target
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some/labeler@v1
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`,
  }))
  assert.equal(find(r, 'CG-CI-001'), undefined,
    'the checkout took no ref; the next step is a different subject')
})

test('a commented-out dangerous workflow step is not a finding', () => {
  // The comment-mask rule, applied to YAML. A decoy comment must never manufacture a P0, and the
  // same masking is what stops a comment from HIDING one elsewhere.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/w.yml': `on: push
permissions: { contents: read }
jobs:
  a:
    steps:
      # - run: echo "\${{ github.event.issue.title }}"
      - run: npm test
`,
  }))
  assert.equal(find(r, 'CG-CI-002'), undefined)
})

// ===========================================================================
// IaC — the detections
// ===========================================================================

test('a live credential baked into an image is a confirmed P0, a placeholder is not', () => {
  // A NAME plus a real VALUE in a committed file is a value match, which is what LAW 3 requires
  // before severity may go high. A template full of placeholders is the file done RIGHT.
  const real = grade(modelOf({
    'package.json': '{}',
    'Dockerfile': 'FROM node:22-alpine@sha256:aaaa\nUSER node\nENV STRIPE_SECRET_KEY=sk_live_51H8xQ2eZvKYlo2Cabcd\n',
  }))
  const f = find(real, 'CG-IAC-001')
  assert.ok(f)
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(f.evidence.nameOnly, false, 'a value match is never name-only')

  const placeholder = grade(modelOf({
    'package.json': '{}',
    'Dockerfile': 'FROM node:22-alpine@sha256:aaaa\nUSER node\nENV STRIPE_SECRET_KEY=changeme\nARG DB_PASSWORD=${DB_PASSWORD}\n',
  }))
  assert.equal(find(placeholder, 'CG-IAC-001'), undefined,
    'placeholders and interpolations are what a correct template is made of')
})

test('a database port published to every interface is a confirmed P1', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n',
  }))
  const f = find(r, 'CG-IAC-007')
  assert.ok(f, 'a published database port is how an unauthenticated database ends up on the internet')
  assert.equal(f.severity, 'P1')
  assert.match(f.title_en, /postgres/)
})

test('a localhost-bound database port is not a finding', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n',
  }))
  assert.equal(find(r, 'CG-IAC-007'), undefined)
})

test('open ingress is judged by the port range in its OWN block, not a nearby one', () => {
  // The window-bleed defect the SQL parser was fixed for, in a new format: a neighbouring rule's
  // ports must never decide this rule's verdict. Here the 443 rule is correct and the 22 rule is
  // not, and exactly one finding may result.
  const r = grade(modelOf({
    'package.json': '{}',
    'infra/main.tf': `resource "aws_security_group" "a" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
  }))
  const open = r.findings.filter(f => f.id === 'CG-IAC-010')
  assert.equal(open.length, 1, 'exactly the SSH rule, never the HTTPS one')
  assert.match(open[0].title_en, /22/)
})

test('an egress rule open to the world is not reported', () => {
  // Near-universal and not an exposure. Reporting it would be pure volume.
  const r = grade(modelOf({
    'package.json': '{}',
    'infra/main.tf': 'resource "aws_security_group" "a" {\n  egress {\n    from_port   = 0\n    to_port     = 0\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
  }))
  assert.equal(find(r, 'CG-IAC-010'), undefined)
})

test('a committed Terraform state file is a confirmed P0', () => {
  // No secret-scanner rule is shaped to catch these: the values have no recognisable prefix.
  const r = grade(modelOf({
    'package.json': '{}',
    'infra/terraform.tfstate': '{"version":4,"resources":[{"instances":[{"attributes":{"password":"hunter2"}}]}]}',
  }))
  const f = find(r, 'CG-IAC-014')
  assert.ok(f)
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
})

test('a commented-out privileged service is not a finding', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'docker-compose.yml': 'services:\n  a:\n    image: nginx\n    # privileged: true\n',
  }))
  assert.equal(find(r, 'CG-IAC-006'), undefined)
})

// ===========================================================================
// Firebase rules — the detections
// ===========================================================================

test('`allow read, write: if true` is a confirmed P0', () => {
  // The Firebase equivalent of RLS disabled. The config object ships in every client bundle by
  // design, so "anyone with the config" means anyone at all.
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /d/{x} {\n    allow read, write: if true;\n  }\n}\n",
  }))
  const f = find(r, 'CG-FB-001')
  assert.ok(f)
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(r.verdict.level, 'critical')
})

test('`if request.auth != null` is a P1 cross-tenant leak, not a pass', () => {
  // The single most common Firebase mistake, and it reads as safe because the word auth is in it.
  // Anyone can create an account — that is what a sign-up form is.
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /orders/{id} {\n    allow read, write: if request.auth != null;\n  }\n}\n",
  }))
  const f = find(r, 'CG-FB-002')
  assert.ok(f, 'signed-in is not authorization')
  assert.equal(f.severity, 'P1')
  assert.match(f.impact, /cross-tenant|every/i)
})

test('owner-scoped Firebase rules pass', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /users/{uid} {\n    allow read, write: if request.auth != null && request.auth.uid == uid;\n  }\n}\n",
  }))
  assert.equal(find(r, 'CG-FB-001'), undefined)
  assert.equal(find(r, 'CG-FB-002'), undefined)
  assert.equal(find(r, 'CG-FB-003'), undefined)
  assert.equal(r.coverage.firebaseRules.counts.pass, 1)
})

test('the "test mode" time-lock is a P0, not a structural pass (CG-FB-003)', () => {
  // The Firebase console default: `allow ...: if request.time < timestamp.date(...)`. It used to fall
  // through to a PASS because it is neither `true` nor the bare signed-in check — so a database left
  // in test mode graded green. Until the date it is wide open to anyone. `likely`, not `confirmed`,
  // because the grader is clock-free and cannot know whether the date has passed.
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /{document=**} {\n    allow read, write: if request.time < timestamp.date(2025, 6, 1);\n  }\n}\n",
  }))
  const f = find(r, 'CG-FB-003')
  assert.ok(f, 'test-mode rules must be caught, not passed')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'likely', 'clock-free: we cannot prove the date is still in the future')
  assert.equal(r.coverage.firebaseRules.counts.pass, 0, 'it must NOT be a structural pass')
  assert.equal(r.coverage.firebaseRules.counts.fail, 1)
  // An unproven P0 open → not a false green, and not a false red either.
  assert.equal(r.verdict.level, 'unknown')
})

test('a time-lock that ALSO checks identity is not caught by CG-FB-003 (it has an auth component)', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /u/{uid} {\n    allow read: if request.auth != null && request.time < timestamp.date(2025, 6, 1);\n  }\n}\n",
  }))
  assert.equal(find(r, 'CG-FB-003'), undefined, 'the auth component takes it out of the pure time-lock shape')
})

test('a commented-out open rule does not fire, and does not hide a real one', () => {
  const r = grade(modelOf({
    'package.json': '{}',
    'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /a/{x} {
    // allow read, write: if true;
    allow read, write: if request.auth.uid == x;
  }
}
`,
  }))
  assert.equal(find(r, 'CG-FB-001'), undefined, 'a comment must not manufacture a P0')
  assert.equal(r.coverage.firebaseRules.counts.pass, 1)
})

// ===========================================================================
// Non-Next routers
// ===========================================================================

test('Express routes are enumerated as individual subjects', () => {
  // Before this, an Express app enumerated zero routes and the coverage table printed a confident
  // "routes: 0" over an HTTP surface nobody had looked at.
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { express: '4.19.2' } }),
    'server.js': `import express from 'express'
const app = express()
app.get('/health', (req, res) => res.send('ok'))
app.post('/api/orders', async (req, res) => { await db.insert(req.body) })
app.delete('/api/orders/:id', async (req, res) => { await db.remove(req.params.id) })
`,
  }))
  const subjects = r.coverage.routes.fail.concat(r.coverage.routes.undeterminable).map(s => s.subject)
  assert.equal(r.coverage.routes.enumerated, 3)
  assert.ok(subjects.includes('route:server.js:GET /health'))
  assert.ok(subjects.includes('route:server.js:POST /api/orders'))
  assert.ok(subjects.includes('route:server.js:DELETE /api/orders/:id'))
})

test('an Express route with an auth guard is undeterminable, never pass (LAW 1)', () => {
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { express: '4.19.2' } }),
    'server.js': `import express from 'express'
const app = express()
app.get('/me', requireAuth, (req, res) => res.json(req.user))
`,
  }))
  assert.equal(r.coverage.routes.counts.pass, 0, 'LAW 1: a token is not a proof')
  assert.equal(r.coverage.routes.counts.undeterminable, 1)
})

test('a client-side api.get() is not mistaken for a route definition', () => {
  // The precision guard. An axios call in a React component is not an HTTP endpoint, and inventing
  // routes out of client fetches would be worse than missing them.
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { react: '18.3.0', axios: '1.7.0' } }),
    'src/api.ts': `import axios from 'axios'
const api = axios.create({ baseURL: '/api' })
export const getUsers = () => api.get('/users')
export const createUser = (u) => api.post('/users', u)
`,
  }))
  assert.equal(r.coverage.routes.enumerated, 0)
})

test('Fastify, Hono and NestJS routes are enumerated too', () => {
  const fastify = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { fastify: '4.28.0' } }),
    'server.js': "import Fastify from 'fastify'\nconst app = Fastify()\napp.get('/ping', async () => 'pong')\n",
  }))
  assert.equal(fastify.coverage.routes.enumerated, 1)

  const hono = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { hono: '4.6.0' } }),
    'server.ts': "import { Hono } from 'hono'\nconst app = new Hono()\napp.post('/submit', (c) => c.json({}))\n",
  }))
  assert.equal(hono.coverage.routes.enumerated, 1)

  const nest = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { '@nestjs/common': '10.4.0' } }),
    'src/orders.controller.ts': `import { Controller, Get, Post } from '@nestjs/common'
@Controller('orders')
export class OrdersController {
  @Get(':id')
  findOne() {}
  @Post()
  create() {}
}
`,
  }))
  assert.equal(nest.coverage.routes.enumerated, 2)
})

test('registering the same Express route twice does not crash the grade', () => {
  // Two ledger rows with one subject is a LAW 2 violation, and LAW 2 answers with a throw. A
  // duplicate registration is a bug in the app; it must produce a report, not an exception.
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { express: '4.19.2' } }),
    'server.js': "import express from 'express'\nconst app = express()\napp.get('/dup', a)\napp.get('/dup', b)\n",
  }))
  assert.equal(r.coverage.routes.enumerated, 1)
})

// ===========================================================================
// Grade or declare — the safety net
// ===========================================================================

test('a server framework with no routes found is DECLARED, not silently zero', () => {
  // The honest version of the original defect. Either the app registers routes somewhere this pass
  // cannot follow, or it has none — and we cannot tell which, so it becomes a visible coverage hole.
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { express: '4.19.2' } }),
    'src/index.ts': "export const handler = () => 'not a route'\n",
  }))
  const row = r.coverage.ungradedSurfaces.undeterminable.find(s => s.subject === 'route-framework:express')
  assert.ok(row, 'express in package.json with zero routes must be declared')
  assert.match(row.note, /no route definitions were enumerated/)
})

test('an Electron main file is declared as not graded rather than passing silently', () => {
  const r = grade(modelOf({
    'package.json': JSON.stringify({ dependencies: { electron: '32.0.0' } }),
    'main.js': "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } })\n",
  }))
  const row = r.coverage.ungradedSurfaces.undeterminable.find(s => s.subject.startsWith('electron:'))
  assert.ok(row, 'a discovered-but-ungraded class must still be accounted for')
  assert.match(row.note, /does not grade/)
})

test('a Kubernetes manifest is detected by content and declared as not graded', () => {
  // Identified by content, not by path: `deploy/app.yaml` and `k8s/prod/web.yml` are equally
  // common and neither name is reliable. There are no rules for these yet, so the point of finding
  // them is to declare the gap rather than let a Kubernetes-deployed repo read as fully examined.
  const r = grade(modelOf({
    'package.json': '{}',
    'deploy/app.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          securityContext:
            privileged: true
`,
  }))
  const row = r.coverage.ungradedSurfaces.undeterminable.find(s => s.subject === 'k8s:deploy/app.yaml')
  assert.ok(row, 'a Kubernetes manifest must be declared even though no rule grades it')
  assert.match(row.note, /does not grade/)
})

test('a workflow is not also declared as an ungraded Kubernetes manifest', () => {
  // Both are YAML. A file that a rule already walked must not appear a second time as ungraded,
  // or the coverage table double-counts and the declaration stops meaning anything.
  const r = grade(modelOf({
    'package.json': '{}',
    '.github/workflows/ci.yml': 'on: push\npermissions: { contents: read }\njobs:\n  a:\n    steps:\n      - run: echo hi\n',
  }))
  assert.equal(r.coverage.ungradedSurfaces.enumerated, 0)
  assert.equal(r.coverage.ciWorkflows.counts.pass, 1)
})

test('every new subject set obeys LAW 2', () => {
  const r = grade(modelOf({ ...CORRECT_INFRA, 'firestore.rules': "match /a/{x} { allow read: if true; }" }))
  for (const name of ['ciWorkflows', 'iacFiles', 'firebaseRules', 'ungradedSurfaces', 'routes']) {
    const set = r.coverage[name]
    assert.ok(set, `${name} must be a declared subject set`)
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${name}"`)
  }
})

test('the new sets honour the user allowlist', () => {
  const model = modelOf({
    'package.json': '{}',
    'firestore.rules': "match /a/{x} { allow read, write: if true; }",
  })
  const r = grade(model, { allowlist: ['firebase-rules:firestore.rules'] })
  assert.equal(find(r, 'CG-FB-001'), undefined)
  assert.equal(r.coverage.firebaseRules.counts.allowlisted, 1)
})

test('every new finding carries a guard link and a bilingual title', () => {
  // A finding without a fix link spends the reader's attention and returns nothing, and this
  // audience reads the Hebrew.
  const r = grade(modelOf({
    ...PWN_WORKFLOW,
    'Dockerfile': 'FROM node:latest\nENV DATABASE_URL=postgres://u:realpassword123@h/db\n',
    'docker-compose.yml': 'services:\n  a:\n    privileged: true\n',
    'firestore.rules': 'match /a/{x} { allow read, write: if true; }',
  }))
  const mine = r.findings.filter(f => /^CG-(CI|IAC|FB)-/.test(f.id))
  assert.ok(mine.length >= 5)
  for (const f of mine) {
    assert.match(f.guard, /^guard-recipes\/.+#?/, `${f.id} must cite a guard recipe`)
    assert.ok(f.title_he && f.title_he !== f.title_en, `${f.id} must have a Hebrew title`)
    assert.ok(f.exploit && f.impact, `${f.id} must say how it is exploited and what it costs`)
  }
})
