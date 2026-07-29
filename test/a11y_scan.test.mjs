import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  scanA11yElements, scanStatementSignals, scanWidgetSignals, maskJsx, readTag, parseAttrs,
} from '../plugin/scripts/lib/a11y_scan.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// The accessibility tokenizer is the compliance pillar's engine. It reads JSX/HTML the way the
// shared stripper (stripJs) cannot: stripJs guesses regex literals from the previous character, and
// `</button>` / `/>` put a `/` right after `<` or `=`, which it blanks to end-of-line — shredding the
// tags. So this module masks comments/strings with NO regex guessing and reads tags with a quote- and
// brace-aware scan. These tests pin exactly the cases that break a naive scanner, because a wrong read
// here becomes a cry-wolf compliance finding, the one thing the pillar must not produce.
// ---------------------------------------------------------------------------

const only = (src, pred) => scanA11yElements(src).elements.filter(pred)
const first = (src, tag) => scanA11yElements(src).elements.find(e => e.tag === tag)

test('the stripJs killer: closing tags and a self-close on ONE line are read correctly', () => {
  const { elements } = scanA11yElements(`<button>Click</button><img src="x"/><a href="/x">Home</a>`)
  assert.deepEqual(elements.map(e => e.tag), ['button', 'img', 'a'])
  assert.equal(elements[0].hasStaticText, true, 'the button text survives')
  assert.deepEqual(elements[1].attrs, ['src'], 'the img in the middle is not swallowed')
})

test('comments and strings never produce a phantom tag', () => {
  const src = [
    '// <img src="fake">  line comment',
    '/* <button>fake</button> block */',
    'const s = "<img src=x>"',           // a tag inside a double-quoted string
    'const t = `<video></video>`',        // a tag inside a template literal
    '<img src="real.png" alt="real"/>',   // the only real one
  ].join('\n')
  const els = scanA11yElements(src).elements
  assert.equal(els.length, 1, 'only the real <img> is seen — comment, string, and template are ignored')
  assert.equal(els[0].tag, 'img')
  assert.equal(els[0].line, 5)
})

test('alt: missing vs empty vs dynamic vs spread', () => {
  const els = scanA11yElements(`
    <img src="a"/>
    <img src="b" alt=""/>
    <img src="c" alt="cat"/>
    <img src="d" alt={caption}/>
    <img {...props}/>
  `).elements
  assert.deepEqual(els[0].attrs.includes('alt'), false, 'missing alt')
  assert.deepEqual(els[1].attrs.includes('alt'), true, 'empty alt="" still carries the token (valid decorative)')
  assert.deepEqual(els[2].attrs.includes('alt'), true)
  assert.deepEqual(els[3].attrs.includes('alt'), true, 'dynamic alt is still present')
  assert.equal(els[4].hasSpread, true, 'a spread is flagged so the grader abstains')
})

test('tabIndex parses to a number, and only positive is the problem', () => {
  const els = scanA11yElements(`
    <div onClick={a} tabIndex={-1}>a</div>
    <div onClick={a} tabIndex={0}>b</div>
    <div onClick={a} tabIndex={3}>c</div>
    <div onClick={a} tabindex="5">d</div>
    <div onClick={a} tabIndex={x}>e</div>
  `).elements
  assert.equal(els[0].tabIndex, -1)
  assert.equal(els[1].tabIndex, 0)
  assert.equal(els[2].tabIndex, 3)
  assert.equal(els[3].tabIndex, 5, 'string tabindex is parsed too')
  assert.equal(els[4].tabIndex, '(dynamic)', 'an expression tabIndex is undeterminable, not a number')
})

test('a clickable div is only emitted when it actually has onClick', () => {
  const els = scanA11yElements(`
    <div className="wrap">plain</div>
    <div onClick={f}>bad</div>
  `).elements
  assert.equal(els.length, 1, 'the plain layout div is not enumerated')
  assert.equal(els[0].tag, 'div')
  assert.deepEqual(els[0].attrs, ['onclick'])
})

test('iconable name: text, aria, nested img alt, and the dynamic-child trap', () => {
  const bare = first(`<button onClick={f}><svg/></button>`, 'button')
  assert.equal(bare.hasStaticText, false)
  assert.equal(bare.hasNestedImgAlt, false)

  const labelled = first(`<button aria-label="Close" onClick={f}><svg/></button>`, 'button')
  assert.ok(labelled.attrs.includes('aria-label'))

  const nested = first(`<a href="/x"><img src="i.png" alt="Home"/></a>`, 'a')
  assert.equal(nested.hasNestedImgAlt, true, 'a nested <img alt> gives the link its name')

  const dyn = first(`<button onClick={f}>{label}</button>`, 'button')
  assert.equal(dyn.hasChildExpr, true)
  assert.equal(dyn.hasStaticText, false)

  const text = first(`<button onClick={f}>Save</button>`, 'button')
  assert.equal(text.hasStaticText, true)
})

test('media captions: present, absent, and dynamic kind', () => {
  const none = first(`<video src="v.mp4"></video>`, 'video')
  assert.equal(none.hasCaptionsTrack, false)
  const capt = first(`<video src="v.mp4"><track kind="captions" src="c.vtt"/></video>`, 'video')
  assert.equal(capt.hasCaptionsTrack, true)
  const dyn = first(`<video src="v.mp4"><track kind={k}/></video>`, 'video')
  assert.equal(dyn.hasCaptionsTrack, '(dynamic)', 'a dynamic kind cannot be confirmed as captions')
})

test('html root lang: present, absent, dynamic (via dynamicAttrs)', () => {
  const withLang = first(`<html lang="he" dir="rtl"><body/></html>`, 'html')
  assert.ok(withLang.attrs.includes('lang'))
  assert.equal(withLang.dynamicAttrs.includes('lang'), false)

  const noLang = first(`<html><body/></html>`, 'html')
  assert.equal(noLang.attrs.includes('lang'), false)

  const dynLang = first(`<Html lang={locale}><body/></Html>`, 'Html')
  assert.ok(dynLang.attrs.includes('lang'))
  assert.equal(dynLang.dynamicAttrs.includes('lang'), true, 'a dynamic lang is marked so the grader abstains, not fires')
})

test('form control type is captured so non-labelable types can be excluded', () => {
  const hidden = scanA11yElements(`<input type="hidden" name="csrf"/>`).elements[0]
  assert.equal(hidden.type, 'hidden')
  const email = scanA11yElements(`<input type="email"/>`).elements[0]
  assert.equal(email.type, 'email')
  const dyn = scanA11yElements(`<input type={t}/>`).elements[0]
  assert.equal(dyn.type, '(dynamic)')
})

test('statement signals: path, href, and Hebrew link text', () => {
  assert.deepEqual(scanStatementSignals('export default function P(){}', 'app/accessibility/page.tsx'),
    [{ kind: 'route', at: 'app/accessibility/page.tsx' }])
  const links = scanStatementSignals(`<a href="/accessibility">הצהרת נגישות</a>`, 'components/Footer.tsx')
  assert.ok(links.some(e => e.kind === 'href'))
  assert.ok(links.some(e => e.kind === 'text'), 'the Hebrew link text is detected')
})

test('a component named AccessibilityProvider is NOT mistaken for a statement page', () => {
  // The finding is the statement's ABSENCE, so a false "present" would hide a real gap. But a
  // provider component is not a statement page — the path check keys on a whole segment, not a substring.
  assert.deepEqual(scanStatementSignals('export const x = 1', 'src/components/AccessibilityProvider.tsx'), [])
})

test('widget vendors are detected from a script URL', () => {
  assert.deepEqual(scanWidgetSignals(`<script src="https://cdn.userway.org/widget.js"></script>`), ['userway'])
  assert.deepEqual(scanWidgetSignals(`import nagich from 'nagich-widget'`), ['nagich'])
})

test('maskJsx marks comments and strings but leaves JSX `/` alone (regression on the stripJs bug)', () => {
  const src = `<a href="/x"/>` // the /> must not start a regex that eats the rest
  const mask = maskJsx(src)
  // the closing `/>` characters are CODE (0), not swallowed into a string/regex region
  assert.equal(mask[src.length - 2], 0, 'the / in /> is code')
})

test('readTag and parseAttrs handle a brace value containing a >', () => {
  const t = readTag(`<div data-x={a > b ? 1 : 2} onClick={f}>`, 0)
  assert.equal(t.name, 'div')
  const { names } = parseAttrs(t.attrsRaw)
  assert.ok(names.has('onclick'), 'the > inside {a > b} did not end the tag early')
})
