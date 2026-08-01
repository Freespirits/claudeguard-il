import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inflateRawSync } from 'node:zlib'
import { zipDir, crc32 } from '../scripts/zipdir.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// The skill archive is the project's Windows blind spot: Compress-Archive (Windows PowerShell
// 5.1) wrote entry names with backslashes, which APPNOTE 4.4.17.1 forbids, and claude.ai's
// uploader (Python zipfile) then saw "references\findings.md" as ONE flat name — the skill
// shipped with its knowledge tree silently flattened, on exactly the platform CI never runs.
// zipdir.mjs is the fix, so these tests parse the archive BACK with an independent reader
// (not the writer's own bookkeeping) and pin the properties the shell-out versions broke:
// forward-slash names, SKILL.md at the root, intact bytes, and reproducibility.
// ---------------------------------------------------------------------------

function makeTree() {
  const root = mkdtempSync(join(tmpdir(), 'cgzip-'))
  const src = join(root, 'skill')
  mkdirSync(join(src, 'references', 'checks'), { recursive: true })
  const files = {
    'SKILL.md': '# skill root\n',
    'references/findings.md': 'ממצאים בעברית — UTF-8 content\n',
    'references/checks/web.md': 'a'.repeat(5000), // large enough that deflate actually compresses
  }
  for (const [rel, body] of Object.entries(files)) writeFileSync(join(src, ...rel.split('/')), body)
  return { root, src, files }
}

// Independent reader: walk the local headers from byte 0, then the central directory from the
// EOCD, and cross-check the two views agree. Shares no state with the writer.
function readZip(path) {
  const buf = readFileSync(path)
  const entries = new Map()
  let off = 0
  while (buf.readUInt32LE(off) === 0x04034b50) {
    const method = buf.readUInt16LE(off + 8)
    const crc = buf.readUInt32LE(off + 14)
    const compLen = buf.readUInt32LE(off + 18)
    const rawLen = buf.readUInt32LE(off + 22)
    const nameLen = buf.readUInt16LE(off + 26)
    const extraLen = buf.readUInt16LE(off + 28)
    const name = buf.subarray(off + 30, off + 30 + nameLen).toString('utf8')
    const dataStart = off + 30 + nameLen + extraLen
    const raw = method === 8
      ? inflateRawSync(buf.subarray(dataStart, dataStart + compLen))
      : buf.subarray(dataStart, dataStart + compLen)
    assert.equal(raw.length, rawLen, `${name}: uncompressed size header lies`)
    assert.equal(crc32(raw), crc, `${name}: CRC mismatch`)
    entries.set(name, raw)
    off = dataStart + compLen
  }
  // Central directory starts where the local run ended, and the EOCD closes the file.
  assert.equal(buf.readUInt32LE(off), 0x02014b50, 'central directory does not follow the data')
  const eocd = buf.length - 22
  assert.equal(buf.readUInt32LE(eocd), 0x06054b50, 'missing end-of-central-directory record')
  assert.equal(buf.readUInt16LE(eocd + 10), entries.size, 'EOCD entry count disagrees with the data')
  assert.equal(buf.readUInt32LE(eocd + 16), off, 'EOCD central-directory offset disagrees with the data')
  return entries
}

test('entry names use forward slashes only, with SKILL.md at the archive root', () => {
  const { root, src } = makeTree()
  const zip = join(root, 'out.zip')
  try {
    zipDir(src, zip)
    const names = [...readZip(zip).keys()]
    assert.ok(names.every(n => !n.includes('\\')), `backslash in entry names: ${names}`)
    assert.ok(names.includes('SKILL.md'), 'SKILL.md must sit at the archive root')
    assert.ok(names.includes('references/checks/web.md'), 'nested paths keep their hierarchy')
    assert.deepEqual(names, [...names].sort(), 'entries are written in sorted order (deterministic)')
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('every entry round-trips byte-identical, UTF-8 content included', () => {
  const { root, src, files } = makeTree()
  const zip = join(root, 'out.zip')
  try {
    zipDir(src, zip)
    const entries = readZip(zip)
    for (const [rel, body] of Object.entries(files)) {
      assert.equal(entries.get(rel).toString('utf8'), body, `${rel} content changed in transit`)
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('the archive is byte-reproducible: same tree in, same bytes out', () => {
  const { root, src } = makeTree()
  const a = join(root, 'a.zip')
  const b = join(root, 'b.zip')
  try {
    zipDir(src, a)
    zipDir(src, b)
    assert.ok(readFileSync(a).equals(readFileSync(b)), 'two builds of the same tree differ')
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('deflate actually engages on compressible content (guards a silent store-mode regression)', () => {
  const { root, src } = makeTree()
  const zip = join(root, 'out.zip')
  try {
    zipDir(src, zip)
    const rawTotal = 5000 // the repetitive file alone
    assert.ok(readZip(zip).get('references/checks/web.md').length === rawTotal)
    assert.ok(readFileSync(zip).length < rawTotal, 'archive is not smaller than its compressible input')
  } finally { rmSync(root, { recursive: true, force: true }) }
})
