// The ONE comment/string stripper. Every security regex in ClaudeGuardIL runs against the
// output of this module — never against raw source.
//
// WHY THIS EXISTS: a regex matching inside a comment produced a FALSE NEGATIVE that hid a P0.
// The line
//     -- (missing) alter table public.orders enable row level security;
// made the engine report RLS as ENABLED on a table that has none. A security tool that says
// "you're fine" when you are not is worse than no tool. Four divergent strippers were proposed
// during design; divergence between the module that finds a fact and the module that suppresses
// it is a silent-false-negative generator. So: one stripper, one contract, all callers.
//
// CONTRACT
//   strip*(src) -> { code, mask, ... }
//     code : same LENGTH as src. Non-code regions replaced by spaces, NEWLINES PRESERVED, so
//            every offset and line number in `code` maps 1:1 onto `src`.
//     mask : Uint8Array parallel to src. 0 = CODE, 1 = COMMENT, 2 = STRING.
//   Callers decide whether mask===STRING counts as code for their rule. (A secret VALUE lives in
//   a string and must be scanned; an auth-token HINT inside a string must NOT count as auth.)

export const CODE = 0
export const COMMENT = 1
export const STRING = 2

const blank = ch => (ch === '\n' ? '\n' : ch === '\r' ? '\r' : ' ')

/**
 * Strip SQL comments and string literals.
 * Postgres specifics handled: `--` line comments, NESTABLE block comments, '' escapes inside
 * single-quoted strings, and $tag$ dollar-quoted bodies.
 *
 * Double-quoted regions are NOT blanked: in SQL `"orders"` is a quoted IDENTIFIER, not a string.
 * Blanking it would erase table names.
 *
 * @returns {{code:string, mask:Uint8Array, dollarBodies:{start:number,end:number,tag:string,text:string}[]}}
 *   dollarBodies is returned rather than discarded because `create function ... $$ ... $$` bodies
 *   are where `security definer` privilege-escalation bugs live. Stripping and forgetting them
 *   would trade one blind spot for a worse one; callers re-parse them.
 */
export function stripSql(src) {
  const n = src.length
  const out = new Array(n)
  const mask = new Uint8Array(n)
  const dollarBodies = []
  let i = 0

  const wipe = (from, to, kind) => {
    for (let k = from; k < to && k < n; k++) { out[k] = blank(src[k]); mask[k] = kind }
  }

  while (i < n) {
    const c = src[i]

    // -- line comment
    if (c === '-' && src[i + 1] === '-') {
      const start = i
      while (i < n && src[i] !== '\n') i++
      wipe(start, i, COMMENT)
      continue
    }

    // /* block comment */  (Postgres allows nesting)
    if (c === '/' && src[i + 1] === '*') {
      const start = i
      let depth = 0
      while (i < n) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; i += 2; continue }
        if (src[i] === '*' && src[i + 1] === '/') { depth--; i += 2; if (depth === 0) break; continue }
        i++
      }
      wipe(start, i, COMMENT)
      continue
    }

    // $tag$ dollar-quoted body $tag$
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(src.slice(i, i + 128))
      if (m) {
        const tag = m[0]
        const bodyStart = i + tag.length
        const close = src.indexOf(tag, bodyStart)
        const bodyEnd = close === -1 ? n : close
        dollarBodies.push({ start: bodyStart, end: bodyEnd, tag, text: src.slice(bodyStart, bodyEnd) })
        const stop = close === -1 ? n : close + tag.length
        wipe(i, stop, STRING)
        i = stop
        continue
      }
    }

    // 'single-quoted string'  ('' is an escaped quote)
    if (c === "'") {
      const start = i
      i++
      while (i < n) {
        if (src[i] === "'" && src[i + 1] === "'") { i += 2; continue }
        if (src[i] === "'") { i++; break }
        i++
      }
      wipe(start, i, STRING)
      continue
    }

    out[i] = c
    mask[i] = CODE
    i++
  }

  return { code: out.join(''), mask, dollarBodies }
}

/**
 * Strip JS/TS comments and string literals.
 *
 * Template literals: the STATIC TEXT is blanked but `${ ... }` EXPRESSIONS remain code, so
 * `` `...${req.query.id}...` `` stays analyzable. Nesting is handled via a state stack.
 *
 * Strings ARE blanked (mask=STRING). This is deliberate and differs from an earlier draft:
 * without it, `const s = "TODO: add requireAuth"` would satisfy an auth-hint regex and mark an
 * unauthenticated route as authenticated.
 *
 * @returns {{code:string, mask:Uint8Array, templateExprs:{start:number,end:number}[]}}
 */
export function stripJs(src) {
  const n = src.length
  const out = new Array(n)
  const mask = new Uint8Array(n)
  const templateExprs = []
  let i = 0

  // Decide whether a '/' starts a regex literal or is division, by looking back at the last
  // significant character. Wrong guesses are non-fatal (worst case a division tail is blanked).
  const regexAllowedAfter = /[(,=:[!&|?{};+\-*%~^<>]$/
  const keywordBefore = /\b(return|typeof|case|in|of|instanceof|new|delete|void|do|else|yield|await|throw)\s*$/
  const prevSignificant = pos => {
    let k = pos - 1
    while (k >= 0 && /\s/.test(out[k] ?? src[k])) k--
    return k
  }

  const wipe = (from, to, kind) => {
    for (let k = from; k < to && k < n; k++) { out[k] = blank(src[k]); mask[k] = kind }
  }

  // stack of template states so nested `${ `inner` }` works
  const tplStack = []

  while (i < n) {
    const c = src[i]

    // inside a template expression, a '}' may close it
    if (tplStack.length && tplStack[tplStack.length - 1].inExpr) {
      const top = tplStack[tplStack.length - 1]
      if (c === '{') { top.depth++; out[i] = c; mask[i] = CODE; i++; continue }
      if (c === '}') {
        top.depth--
        if (top.depth === 0) {
          top.inExpr = false
          templateExprs.push({ start: top.exprStart, end: i })
          out[i] = blank(c); mask[i] = STRING; i++
          continue
        }
        out[i] = c; mask[i] = CODE; i++; continue
      }
      // fall through: expression content is normal code (handled by the rest of the loop)
    }

    // inside template text (not expression)
    if (tplStack.length && !tplStack[tplStack.length - 1].inExpr) {
      const top = tplStack[tplStack.length - 1]
      if (c === '\\') { wipe(i, i + 2, STRING); i += 2; continue }
      if (c === '`') { out[i] = blank(c); mask[i] = STRING; i++; tplStack.pop(); continue }
      if (c === '$' && src[i + 1] === '{') {
        out[i] = blank(c); mask[i] = STRING
        out[i + 1] = blank(src[i + 1]); mask[i + 1] = STRING
        top.inExpr = true; top.depth = 1; top.exprStart = i + 2
        i += 2
        continue
      }
      out[i] = blank(c); mask[i] = STRING; i++
      continue
    }

    // // line comment
    if (c === '/' && src[i + 1] === '/') {
      const start = i
      while (i < n && src[i] !== '\n') i++
      wipe(start, i, COMMENT)
      continue
    }

    // /* block comment */
    if (c === '/' && src[i + 1] === '*') {
      const start = i
      i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++
      i = Math.min(i + 2, n)
      wipe(start, i, COMMENT)
      continue
    }

    // ' or " string
    if (c === "'" || c === '"') {
      const quote = c
      const start = i
      i++
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue }
        if (src[i] === quote) { i++; break }
        if (src[i] === '\n') break // unterminated; bail at EOL
        i++
      }
      wipe(start, i, STRING)
      continue
    }

    // ` template literal
    if (c === '`') {
      out[i] = blank(c); mask[i] = STRING
      tplStack.push({ inExpr: false, depth: 0, exprStart: -1 })
      i++
      continue
    }

    // regex literal
    if (c === '/') {
      const k = prevSignificant(i)
      const before = k < 0 ? '' : (out.slice(0, k + 1).join('') || src.slice(0, k + 1))
      const isRegex = k < 0 || regexAllowedAfter.test(before) || keywordBefore.test(before)
      if (isRegex) {
        const start = i
        i++
        let inClass = false
        while (i < n) {
          if (src[i] === '\\') { i += 2; continue }
          if (src[i] === '[') inClass = true
          else if (src[i] === ']') inClass = false
          else if (src[i] === '/' && !inClass) { i++; break }
          else if (src[i] === '\n') break
          i++
        }
        while (i < n && /[a-z]/.test(src[i])) i++ // flags
        wipe(start, i, STRING)
        continue
      }
    }

    out[i] = c
    mask[i] = CODE
    i++
  }

  return { code: out.join(''), mask, templateExprs }
}

/**
 * Strip comments from the CONFIG formats: YAML (workflows, compose), Dockerfile, and HCL
 * (Terraform). Handles `#` line comments plus HCL's `//` and block comments.
 *
 * ONE DELIBERATE DIFFERENCE from stripSql/stripJs: quoted regions are marked STRING in the mask
 * but are NOT blanked in `code`. In these formats the payload IS the string — `uses:
 * "actions/checkout@v4"`, `cidr_blocks = ["0.0.0.0/0"]`, `run: "echo ${{ github.event.issue.title
 * }}"`. Blanking them would erase the exact values every rule here reads. Quotes are still tracked
 * so a `#` inside a quoted scalar is not mistaken for a comment start, which is also YAML's own
 * rule: `#` only opens a comment at the start of a line or after whitespace.
 *
 * @returns {{code:string, mask:Uint8Array}}
 */
export function stripHash(src) {
  const n = src.length
  const out = new Array(n)
  const mask = new Uint8Array(n)
  let i = 0

  const wipe = (from, to, kind) => {
    for (let k = from; k < to && k < n; k++) { out[k] = blank(src[k]); mask[k] = kind }
  }
  const keep = (from, to, kind) => {
    for (let k = from; k < to && k < n; k++) { out[k] = src[k]; mask[k] = kind }
  }

  while (i < n) {
    const c = src[i]

    // `#` opens a comment only at line start or after whitespace. `image: nginx#1` is a value.
    if (c === '#' && (i === 0 || /\s/.test(src[i - 1]))) {
      const start = i
      while (i < n && src[i] !== '\n') i++
      wipe(start, i, COMMENT)
      continue
    }

    // HCL line comment. Same leading rule, so a `//` inside a URL stays part of the value.
    if (c === '/' && src[i + 1] === '/' && (i === 0 || /\s/.test(src[i - 1]))) {
      const start = i
      while (i < n && src[i] !== '\n') i++
      wipe(start, i, COMMENT)
      continue
    }

    // HCL block comment.
    if (c === '/' && src[i + 1] === '*') {
      const start = i
      i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++
      i = Math.min(i + 2, n)
      wipe(start, i, COMMENT)
      continue
    }

    // Quoted scalar: preserved as text, marked STRING. Unterminated quotes bail at EOL so a lone
    // apostrophe in a comment-free YAML value cannot swallow the rest of the file.
    if (c === "'" || c === '"') {
      const quote = c
      const start = i
      i++
      while (i < n) {
        if (src[i] === '\\' && quote === '"') { i += 2; continue }
        if (src[i] === quote) { i++; break }
        if (src[i] === '\n') break
        i++
      }
      keep(start, i, STRING)
      continue
    }

    out[i] = c
    mask[i] = CODE
    i++
  }

  return { code: out.join(''), mask }
}

/** Convenience: true if every char in [start,end) is CODE. */
export function isCode(mask, start, end) {
  for (let i = start; i < end; i++) if (mask[i] !== CODE) return false
  return true
}
