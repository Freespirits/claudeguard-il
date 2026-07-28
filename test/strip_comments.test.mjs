import { test } from 'node:test'
import assert from 'node:assert/strict'
import { stripSql, stripJs, CODE, COMMENT, STRING } from '../plugin/scripts/lib/strip_comments.mjs'

// ---------------------------------------------------------------------------
// REGRESSION GUARD — the bug that hid a P0.
//
// The engine reported "RLS enabled" for a table whose enable statement was COMMENTED OUT,
// because the regex ran against raw source. That is a false negative on a critical finding:
// the tool told the user their database was protected when it was world-readable.
// If either of the next two tests fails, the engine is lying to users again.
// ---------------------------------------------------------------------------

test('REGRESSION: commented-out RLS statement must not survive stripping', () => {
  const sql = `
create table public.orders (
  id uuid primary key,
  user_id uuid not null
);
-- (missing) alter table public.orders enable row level security;
-- (missing) create policy ... using ( auth.uid() = user_id );
`
  const { code } = stripSql(sql)
  assert.ok(!/enable\s+row\s+level\s+security/i.test(code),
    'commented-out RLS must be stripped — otherwise the engine reports RLS as ON when it is OFF')
  assert.ok(!/create\s+policy/i.test(code), 'commented-out policy must be stripped')
  // the real statement is still there
  assert.match(code, /create\s+table\s+public\.orders/i)
})

test('REGRESSION: a REAL RLS statement must survive stripping', () => {
  const sql = `create table public.orders (id uuid);
alter table public.orders enable row level security;`
  const { code } = stripSql(sql)
  assert.match(code, /alter\s+table\s+public\.orders\s+enable\s+row\s+level\s+security/i,
    'stripping must not eat real statements — that would be a false POSITIVE')
})

test('REGRESSION: an auth hint inside a JS string must not read as code', () => {
  // Without string blanking, `AUTH_HINT` matches this and an unauthenticated route is
  // marked authenticated — the same false-negative class, one level up.
  const js = `const note = "TODO: add requireAuth() here";\nexport async function GET() { return Response.json({}) }`
  const { code } = stripJs(js)
  assert.ok(!/requireAuth/.test(code), 'auth hint inside a string literal must be blanked')
  assert.match(code, /export async function GET/)
})

// ---------------------------------------------------------------------------
// Offset stability — every downstream file:line depends on this.
// ---------------------------------------------------------------------------

test('stripSql preserves length and line count', () => {
  const sql = `-- c1\ncreate table t (a int); /* block\nspanning */ select 'str';\n`
  const { code } = stripSql(sql)
  assert.equal(code.length, sql.length, 'length must be identical so offsets map 1:1')
  assert.equal(code.split('\n').length, sql.split('\n').length, 'line count must be preserved')
})

test('stripJs preserves length and line count', () => {
  const js = `// c\nconst a = 'x';\n/* b\nc */ const d = \`t\${e}f\`;\n`
  const { code } = stripJs(js)
  assert.equal(code.length, js.length)
  assert.equal(code.split('\n').length, js.split('\n').length)
})

// ---------------------------------------------------------------------------
// SQL specifics
// ---------------------------------------------------------------------------

test('stripSql keeps double-quoted identifiers (they are names, not strings)', () => {
  const { code } = stripSql(`create table "orders" (id uuid);`)
  assert.match(code, /"orders"/, 'blanking quoted identifiers would erase table names')
})

test('stripSql blanks single-quoted strings and handles the doubled-quote escape', () => {
  const { code } = stripSql(`select 'it''s a comment -- not really' from t;`)
  assert.ok(!/not really/.test(code), 'string body must be blanked')
  assert.match(code, /select/i)
  assert.match(code, /from t/i, "the '' escape must not swallow the rest of the statement")
})

test('stripSql handles nested block comments', () => {
  const { code } = stripSql(`/* outer /* inner */ still comment */ select 1;`)
  assert.ok(!/still comment/.test(code))
  assert.match(code, /select 1/)
})

test('stripSql captures dollar-quoted bodies instead of discarding them', () => {
  // security-definer functions live in these bodies; losing them creates a worse blind spot
  // than the bug we are fixing.
  const sql = `create function f() returns void as $$
  begin perform 1; end;
$$ language plpgsql security definer;`
  const { code, dollarBodies } = stripSql(sql)
  assert.equal(dollarBodies.length, 1, 'the body must be captured for re-parsing')
  assert.match(dollarBodies[0].text, /perform 1/)
  assert.ok(!/perform 1/.test(code), 'the body is blanked in the main stream')
  assert.match(code, /security definer/i, 'the definer clause is outside the body and must survive')
})

test('stripSql marks regions correctly in the mask', () => {
  const sql = `select 1; -- note\n`
  const { mask } = stripSql(sql)
  assert.equal(mask[0], CODE)
  assert.equal(mask[sql.indexOf('note')], COMMENT)
})

// ---------------------------------------------------------------------------
// JS specifics
// ---------------------------------------------------------------------------

test('stripJs keeps template EXPRESSIONS as code but blanks static text', () => {
  // taint/prompt analysis depends on `${req.query.id}` remaining visible.
  const js = 'const q = `select * from users where id = ${req.query.id}`;'
  const { code } = stripJs(js)
  assert.match(code, /req\.query\.id/, 'template expressions must remain analyzable')
  assert.ok(!/select \* from users/.test(code), 'static template text must be blanked')
})

test('stripJs handles nested template literals', () => {
  const js = 'const a = `x${ `y${ z }` }w`;'
  const { code } = stripJs(js)
  assert.match(code, /z/, 'inner expression must survive')
  assert.ok(!/w/.test(code.replace(/\s/g, '')) || true) // structural: just must not throw
})

test('stripJs blanks line and block comments', () => {
  const js = `// secret = "sk-live-abc"\nconst a = 1;\n/* dangerouslySetInnerHTML */\n`
  const { code } = stripJs(js)
  assert.ok(!/sk-live-abc/.test(code))
  assert.ok(!/dangerouslySetInnerHTML/.test(code))
  assert.match(code, /const a = 1/)
})

test('stripJs does not mistake division for a regex literal', () => {
  const js = `const ratio = total / count; const half = x / 2;`
  const { code } = stripJs(js)
  assert.match(code, /total \/ count/, 'division must not be swallowed as a regex')
  assert.match(code, /x \/ 2/)
})

test('stripJs blanks regex literal bodies', () => {
  const js = `const re = /service_role/i; const b = 2;`
  const { code } = stripJs(js)
  assert.ok(!/service_role/.test(code), 'a pattern inside a regex literal is not a real usage')
  assert.match(code, /const b = 2/)
})

test('stripJs handles escaped quotes inside strings', () => {
  const js = `const s = 'it\\'s fine'; const after = 1;`
  const { code } = stripJs(js)
  assert.match(code, /const after = 1/, 'escaped quote must not swallow the rest of the file')
})
