#!/usr/bin/env node
// Pure-Node ZIP writer for the claude.ai skill archive.
//
// Why this exists: the build used to shell out — PowerShell Compress-Archive on Windows, the
// `zip` binary everywhere else. Windows PowerShell 5.1 writes entry names with BACKSLASHES,
// which the ZIP spec forbids (APPNOTE 4.4.17.1: "the path stored MUST not contain a drive or
// device letter... all slashes MUST be forward slashes"), and Python's zipfile then reads
// "references\findings.md" as one flat filename — the uploaded skill arrives with its knowledge
// tree silently flattened. One pure-Node path also means CI (Linux) exercises the exact code a
// Windows maintainer runs, and the archive becomes byte-reproducible: same input, same bytes.
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { deflateRawSync } from 'node:zlib'

// Standard CRC-32 (ISO 3309), table built once.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

export function crc32(buf) {
  let c = 0xFFFFFFFF
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8)
  return (c ^ 0xFFFFFFFF) >>> 0
}

// Fixed DOS timestamp (2024-01-01 00:00:00). Real mtimes would make every build a different
// archive; the grader's promise is "run it twice, get the same answer", and the artifact the
// project ships should behave the same way.
const DOS_DATE = ((2024 - 1980) << 9) | (1 << 5) | 1
const DOS_TIME = 0

const FLAG_UTF8 = 0x0800          // entry names are UTF-8 (bit 11)
const METHOD_DEFLATE = 8

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) yield* walk(p)
    else yield p
  }
}

/**
 * Write every file under srcDir into outFile as a ZIP, entry names relative to srcDir with
 * forward slashes (so SKILL.md sits at the archive root). Returns the sorted entry names.
 */
export function zipDir(srcDir, outFile) {
  const parts = []
  const central = []
  const names = []
  let offset = 0

  for (const abs of walk(srcDir)) {
    const name = relative(srcDir, abs).split(sep).join('/')
    if (name.includes('\\')) throw new Error(`zip entry name still contains a backslash: ${name}`)
    const nameBuf = Buffer.from(name, 'utf8')
    const data = readFileSync(abs)
    const compressed = deflateRawSync(data, { level: 9 })
    const crc = crc32(data)

    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)           // local file header signature
    local.writeUInt16LE(20, 4)                   // version needed
    local.writeUInt16LE(FLAG_UTF8, 6)
    local.writeUInt16LE(METHOD_DEFLATE, 8)
    local.writeUInt16LE(DOS_TIME, 10)
    local.writeUInt16LE(DOS_DATE, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(compressed.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuf.length, 26)
    local.writeUInt16LE(0, 28)                   // no extra field
    parts.push(local, nameBuf, compressed)

    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0)           // central directory signature
    entry.writeUInt16LE(20, 4)                   // version made by
    entry.writeUInt16LE(20, 6)                   // version needed
    entry.writeUInt16LE(FLAG_UTF8, 8)
    entry.writeUInt16LE(METHOD_DEFLATE, 10)
    entry.writeUInt16LE(DOS_TIME, 12)
    entry.writeUInt16LE(DOS_DATE, 14)
    entry.writeUInt32LE(crc, 16)
    entry.writeUInt32LE(compressed.length, 20)
    entry.writeUInt32LE(data.length, 24)
    entry.writeUInt16LE(nameBuf.length, 28)
    // no extra, no comment, disk 0, no attrs
    entry.writeUInt32LE(0, 38)                   // external attributes
    entry.writeUInt32LE(offset, 42)              // local header offset
    central.push(Buffer.concat([entry, nameBuf]))

    names.push(name)
    offset += 30 + nameBuf.length + compressed.length
  }

  const cdOffset = offset
  const cd = Buffer.concat(central)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)              // end of central directory signature
  eocd.writeUInt16LE(names.length, 8)            // entries on this disk
  eocd.writeUInt16LE(names.length, 10)           // total entries
  eocd.writeUInt32LE(cd.length, 12)
  eocd.writeUInt32LE(cdOffset, 16)

  writeFileSync(outFile, Buffer.concat([...parts, cd, eocd]))
  return names
}
