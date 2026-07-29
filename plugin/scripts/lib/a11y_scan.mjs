// The accessibility element scanner — a small JSX/HTML tokenizer for the compliance pillar.
//
// WHY A DEDICATED SCANNER: the shared stripper (strip_comments.mjs, stripJs) blanks string
// literals AND guesses regex literals from the previous significant character. Both are exactly
// wrong for JSX: `</button>` and `/>` put a `/` right after `<` or `=`, which stripJs reads as the
// start of a regex and blanks to end-of-line — shredding the very tags we need to read. So this
// module masks comments and strings WITHOUT any regex-literal guessing (a `/` is just a `/` here),
// then reads tags with a quote- and brace-aware scan so a `>` inside an attribute string or a
// `{jsx expression}` never ends a tag early.
//
// It EMITS FACTS, never verdicts. For each accessibility-relevant element it records which
// attributes are present (not their values — a missing `alt` is the finding, an empty `alt=""` is
// valid for decorative images, and both have the `alt` token), whether the tag carries a
// `{...spread}` (which could supply any attribute, so the grader must abstain, per LAW 1), and, for
// the container checks, a best-effort read of the children. The grader owns every severity and every
// false-positive trap; this file only says what the markup is.
//
// Heuristic and deterministic, like the rest of the engine: same text in, same facts out. It does
// not resolve components (`<Button>` may or may not render a real <button>), so it stays conservative
// and matches raw HTML tag names plus the two framework aliases that are unambiguous in this
// audience's stack (`<Image>` from next/expo, `<Html>` from next/document).

// tag name -> the accessibility check family it belongs to. Case-sensitive: `Image`/`Html` are the
// framework components; everything else is a lowercase HTML element. A `<Button>`/`<Input>` wrapper
// is deliberately NOT matched — resolving whether it renders a real control needs the component
// source, and guessing is how a cry-wolf false positive gets made. Those are declared, not graded.
const TAG_KIND = new Map([
  ['img', 'image'], ['Image', 'image'],
  ['input', 'formControl'], ['select', 'formControl'], ['textarea', 'formControl'],
  ['button', 'iconable'], ['a', 'iconable'],
  ['video', 'media'], ['audio', 'media'],
  ['div', 'clickable'], ['span', 'clickable'],
  ['html', 'htmlRoot'], ['Html', 'htmlRoot'],
])

// Container kinds whose children we read (for an accessible name / a captions track). Void and
// leaf kinds are never opened.
const READS_CHILDREN = new Set(['iconable', 'media'])

const MAX_ELEMENTS = 600           // bound the model on a huge generated UI
const MAX_CHILD_SPAN = 20000       // runaway guard when a close tag is never found

/**
 * Mask comments and strings in JSX/TS source, with NO regex-literal detection.
 *   mask[i]: 0 = code, 1 = comment, 2 = string.
 * Template literals: the static text is masked STRING, `${...}` expressions stay CODE (depth-tracked
 * so nested braces close correctly). We only ever CONSULT this mask to decide whether a `<` we found
 * is real or sits inside a comment/string — we never rewrite the source, so tag reading below runs on
 * raw text and a `>` inside a masked region is skipped by construction.
 */
export function maskJsx(src) {
  const n = src.length
  const mask = new Uint8Array(n)
  let i = 0
  const tpl = [] // stack of {inExpr, depth}
  const fill = (from, to, k) => { for (let j = from; j < to && j < n; j++) mask[j] = k }

  while (i < n) {
    const c = src[i]

    if (tpl.length && tpl[tpl.length - 1].inExpr) {
      const top = tpl[tpl.length - 1]
      if (c === '{') { top.depth++; i++; continue }
      if (c === '}') { top.depth--; if (top.depth === 0) top.inExpr = false; i++; continue }
      // else fall through and treat expression content as ordinary code below
    } else if (tpl.length) {
      const top = tpl[tpl.length - 1]
      if (c === '\\') { fill(i, i + 2, 2); i += 2; continue }
      if (c === '`') { mask[i] = 2; i++; tpl.pop(); continue }
      if (c === '$' && src[i + 1] === '{') { mask[i] = 2; mask[i + 1] = 2; top.inExpr = true; top.depth = 1; i += 2; continue }
      mask[i] = 2; i++; continue
    }

    if (c === '/' && src[i + 1] === '/') { const s = i; while (i < n && src[i] !== '\n') i++; fill(s, i, 1); continue }
    if (c === '/' && src[i + 1] === '*') { const s = i; i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++; i = Math.min(i + 2, n); fill(s, i, 1); continue }
    if (c === '"' || c === "'") {
      const q = c; const s = i; i++
      while (i < n) { if (src[i] === '\\') { i += 2; continue } if (src[i] === q) { i++; break } if (src[i] === '\n') break; i++ }
      fill(s, i, 2); continue
    }
    if (c === '`') { mask[i] = 2; tpl.push({ inExpr: false, depth: 0 }); i++; continue }

    i++ // ordinary code char (mask already 0)
  }
  return mask
}

/**
 * Read one tag starting at `<` (openIdx). Quote- and brace-aware, so the closing `>` is the real
 * one. Returns null when `openIdx` does not begin a tag name (`</`, `<3`, `< `).
 * @returns {{name:string, attrsRaw:string, selfClosing:boolean, endIdx:number}|null}
 */
export function readTag(src, openIdx) {
  const n = src.length
  let i = openIdx + 1
  const m = /^[A-Za-z][A-Za-z0-9]*/.exec(src.slice(i, i + 60))
  if (!m) return null
  const name = m[0]
  i += name.length
  const attrsStart = i
  while (i < n) {
    const c = src[i]
    if (c === '"' || c === "'") { const q = c; i++; while (i < n && src[i] !== q) { if (src[i] === '\\') i++; i++ } i++; continue }
    if (c === '`') { i++; while (i < n && src[i] !== '`') { if (src[i] === '\\') i++; i++ } i++; continue }
    if (c === '{') {
      let depth = 0
      do {
        const d = src[i]
        if (d === '{') depth++
        else if (d === '}') depth--
        else if (d === '"' || d === "'" || d === '`') { const q = d; i++; while (i < n && src[i] !== q) { if (src[i] === '\\') i++; i++ } }
        i++
      } while (i < n && depth > 0)
      continue
    }
    if (c === '>') {
      let attrsRaw = src.slice(attrsStart, i)
      const selfClosing = /\/\s*$/.test(attrsRaw)
      attrsRaw = attrsRaw.replace(/\/\s*$/, '')
      return { name, attrsRaw, selfClosing, endIdx: i }
    }
    i++
  }
  return null
}

/**
 * Parse a tag's attribute region into the names present, whether a `{...spread}` is there, and the
 * raw source of a few values the grader inspects (`role`, `tabIndex`). Values are otherwise ignored
 * on purpose: presence is the fact, and reading a value would tempt a token-equals-pass shortcut that
 * LAW 1 forbids.
 * @returns {{names:Set<string>, spread:boolean, values:Map<string,string>}}
 */
export function parseAttrs(s) {
  const names = new Set()
  const values = new Map()
  let spread = false
  let i = 0
  const n = s.length
  const skipBraces = () => {
    let depth = 0
    do {
      const d = s[i]
      if (d === '{') depth++
      else if (d === '}') depth--
      else if (d === '"' || d === "'" || d === '`') { const q = d; i++; while (i < n && s[i] !== q) { if (s[i] === '\\') i++; i++ } }
      i++
    } while (i < n && depth > 0)
  }
  while (i < n) {
    const c = s[i]
    if (/\s/.test(c)) { i++; continue }
    if (c === '{') { if (/^\{\s*\.\.\./.test(s.slice(i, i + 8))) spread = true; skipBraces(); continue }
    const nm = /^[A-Za-z_][\w:-]*/.exec(s.slice(i))
    if (!nm) { i++; continue }
    const name = nm[0].toLowerCase()
    i += nm[0].length
    while (i < n && /\s/.test(s[i])) i++
    let raw = null
    if (s[i] === '=') {
      i++
      while (i < n && /\s/.test(s[i])) i++
      const q = s[i]
      if (q === '"' || q === "'") { const st = i + 1; i++; while (i < n && s[i] !== q) i++; raw = s.slice(st, i); i++ }
      else if (q === '{') { const st = i; skipBraces(); raw = s.slice(st, i) } // includes the braces → expression
      else { const st = i; while (i < n && !/\s/.test(s[i]) && s[i] !== '>') i++; raw = s.slice(st, i) }
    }
    names.add(name)
    if (raw !== null && !values.has(name)) values.set(name, raw)
  }
  return { names, spread, values }
}

// `tabIndex={2}` / `tabindex="2"` / `tabIndex={-1}` -> integer; `{expr}` / a variable -> '(dynamic)';
// absent -> null. A positive value is the only accessibility problem (2.4.3); -1 and 0 are fine.
function parseTabIndex(values) {
  if (!values.has('tabindex')) return null
  const raw = values.get('tabindex').trim().replace(/^\{|\}$/g, '').trim()
  return /^-?\d+$/.test(raw) ? parseInt(raw, 10) : '(dynamic)'
}

// A static role string, or '(dynamic)' when it comes from an expression, or null when absent.
function parseRole(values) {
  if (!values.has('role')) return null
  const raw = values.get('role').trim()
  if (raw.startsWith('{')) return '(dynamic)'
  return raw
}

/**
 * Read the children of a container tag from just past its `>` to the matching `</name>`, tracking
 * same-name nesting. `known:false` when no clean close is found (self-closing sibling, truncation) —
 * the grader treats an unknown body as undeterminable, never as an accessible-name pass.
 */
function readChildren(src, from, name) {
  const n = src.length
  let i = from
  let depth = 1
  const openRe = new RegExp(`^<${name}[\\s/>]`, 'i')
  const closeRe = new RegExp(`^</${name}\\s*>`, 'i')
  while (i < n && i - from < MAX_CHILD_SPAN) {
    if (src[i] === '<') {
      const rest = src.slice(i, i + name.length + 4)
      if (closeRe.test(rest)) { depth--; if (depth === 0) return { raw: src.slice(from, i), known: true } }
      else if (openRe.test(rest)) depth++
    }
    i++
  }
  return { raw: src.slice(from, Math.min(i, from + MAX_CHILD_SPAN)), known: false }
}

// Does the children source carry a human-readable accessible name?
function summariseChildren(raw) {
  const hasChildExpr = /\{[^}]*\}/.test(raw)                 // {children} / {label} — dynamic, undeterminable
  const stripped = raw.replace(/<[^>]*>/g, ' ').replace(/\{[^}]*\}/g, ' ')
  const hasStaticText = /\S/.test(stripped)
  const hasNestedImgAlt = /<(?:img|Image)\b[^>]*\balt\s*=/i.test(raw)
  const hasNestedAria = /\baria-label(?:ledby)?\s*=|\btitle\s*=/i.test(raw)
  return { hasChildExpr, hasStaticText, hasNestedImgAlt, hasNestedAria }
}

// A captions/subtitles track among a media element's children (WCAG 1.2.2). A `{expr}` kind is
// undeterminable, not a pass.
function hasCaptions(raw) {
  const re = /<track\b[^>]*\bkind\s*=\s*(["']?)(captions|subtitles)\1/i
  if (re.test(raw)) return true
  if (/<track\b[^>]*\bkind\s*=\s*\{/i.test(raw)) return '(dynamic)'
  return false
}

/**
 * Scan one file's source for accessibility-relevant elements.
 * @returns {{elements:Array, truncated:boolean}}
 */
export function scanA11yElements(src) {
  const mask = maskJsx(src)
  const lineStarts = [0]
  for (let k = 0; k < src.length; k++) if (src[k] === '\n') lineStarts.push(k + 1)
  const lineOf = idx => {
    let lo = 0, hi = lineStarts.length - 1
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1 }
    return lo + 1
  }

  const elements = []
  let truncated = false
  const n = src.length
  for (let i = 0; i < n; i++) {
    if (src[i] !== '<') continue
    if (mask[i] !== 0) continue                 // a `<` inside a comment or a string is not a tag
    if (src[i + 1] === '/' || src[i + 1] === '!') continue
    const tag = readTag(src, i)
    if (!tag) continue
    const kind = TAG_KIND.get(tag.name)
    if (!kind) { i = tag.endIdx; continue }

    const { names, spread, values } = parseAttrs(tag.attrsRaw)
    // A clickable div/span is only interesting when it actually has an onClick — otherwise every
    // layout div would flood the coverage ledger with meaningless passes.
    if (kind === 'clickable' && !names.has('onclick')) { i = tag.endIdx; continue }

    // Attribute names whose value is a `{jsx expression}` rather than a literal. The grader uses this
    // for the checks where a dynamic value cannot be confirmed (a `lang={locale}` that might not
    // resolve to a valid code), while treating mere presence as enough elsewhere.
    const dynamicAttrs = [...values].filter(([, v]) => v.trim().startsWith('{')).map(([k]) => k)
    const el = {
      line: lineOf(i),
      tag: tag.name,
      kind,
      attrs: [...names].sort(),
      dynamicAttrs,
      hasSpread: spread,
      role: parseRole(values),
      tabIndex: parseTabIndex(values),
      selfClosing: tag.selfClosing,
    }
    // `<input type>` decides whether a text label is even required: `hidden`/`submit`/`button`/
    // `reset`/`image` get their name elsewhere, so the grader must not demand a label of them.
    if (kind === 'formControl') {
      const t = values.get('type')
      el.type = t == null ? null : (t.trim().startsWith('{') ? '(dynamic)' : t.trim().toLowerCase())
    }

    if (READS_CHILDREN.has(kind) && !tag.selfClosing) {
      const ch = readChildren(src, tag.endIdx + 1, tag.name)
      el.childrenKnown = ch.known
      if (kind === 'iconable') Object.assign(el, summariseChildren(ch.raw))
      if (kind === 'media') el.hasCaptionsTrack = hasCaptions(ch.raw)
    } else if (READS_CHILDREN.has(kind)) {
      el.childrenKnown = true // self-closing container has no children
      if (kind === 'iconable') Object.assign(el, { hasChildExpr: false, hasStaticText: false, hasNestedImgAlt: false, hasNestedAria: false })
      if (kind === 'media') el.hasCaptionsTrack = false
    }

    elements.push(el)
    if (elements.length >= MAX_ELEMENTS) { truncated = true; break }
    i = tag.endIdx
  }
  return { elements, truncated }
}

// ---------------------------------------------------------------------------
// Repo-level signals: the accessibility statement (legally mandatory) and a third-party
// accessibility widget (informational). Both are read GENEROUSLY — the finding is the statement's
// ABSENCE, so a missed present-statement would be a false positive, the one thing to avoid.
// ---------------------------------------------------------------------------

// Hebrew + English terms that name an accessibility statement or an accessibility page.
const STMT_TERMS = [
  'accessibility-statement', 'accessibility_statement', 'accessibilitystatement',
  'accessibility', 'הצהרת נגישות', 'הצהרת-נגישות', 'נגישות', 'a11y',
]
// Known accessibility-overlay / toolbar vendors (EqualWeb/Nagich/UserWay/accessiBe/Enable…).
const WIDGET_VENDORS = [
  'equalweb', 'nagich', 'userway', 'accessibe', 'aioa', 'allyable', 'enable.co.il',
  'hachash', 'negishut', 'user1st', 'audioeye', 'maxaccess',
]

/**
 * Statement signals in one file. `route` = the file path itself is an accessibility page; `href` =
 * a link points at one; `text` = visible link/nav text names it. Any one is enough for the grader to
 * count the statement as present.
 */
// The accessibility token as a whole path SEGMENT or page basename — `app/accessibility/page.tsx`,
// `pages/נגישות.tsx`, `public/accessibility-statement.html` — but NOT a substring of a larger
// identifier like `AccessibilityProvider.tsx`, which is a component, not the statement page.
export const STMT_PATH_RE = /(?:^|\/)(?:accessibility|a11y|הצהרת-נגישות|נגישות)(?:[-_./]|$)/i

export function scanStatementSignals(src, path) {
  const ev = []
  if (STMT_PATH_RE.test(path)) ev.push({ kind: 'route', at: path })
  // A link whose href OR visible text names accessibility. Runs on raw text so Hebrew and the href
  // value (a string the JS stripper would blank) both survive.
  const hrefRe = /(?:href|to)\s*=\s*(["'`])([^"'`]*?(?:accessibility|נגישות|a11y|הצהרת)[^"'`]*?)\1/gi
  let m
  while ((m = hrefRe.exec(src))) ev.push({ kind: 'href', at: m[2].slice(0, 80) })
  const textRe = />\s*([^<>{}]*?(?:accessibility statement|accessibility|הצהרת נגישות|נגישות)[^<>{}]*?)\s*</gi
  while ((m = textRe.exec(src))) ev.push({ kind: 'text', at: m[1].trim().slice(0, 80) })
  return ev
}

/** Accessibility-widget vendor signals in one file (raw text — vendor names live in script URLs). */
export function scanWidgetSignals(src) {
  const found = []
  const low = src.toLowerCase()
  for (const v of WIDGET_VENDORS) if (low.includes(v)) found.push(v)
  return found
}

export { STMT_TERMS, WIDGET_VENDORS, TAG_KIND }
