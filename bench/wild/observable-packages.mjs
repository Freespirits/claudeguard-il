// The npm package names the engine can OBSERVE in a `package.json`.
//
// WHY THIS LIST EXISTS. The wild corpus vendors real third-party source (see each case's
// `truth.json` `source_url`). Vendoring a real `package.json` puts that manifest into GitHub's
// dependency graph, which then raises a Dependabot ALERT for every outdated transitive dependency
// of a fixture that is never installed, built, run or shipped. At its peak that was ~120 alerts,
// none of them reachable from anything this tool ships, all of them competing for attention with
// the findings a security tool exists to surface. A security project whose own alert list is
// ~100% noise has trained its readers to ignore alert lists.
//
// THE RULE, and why it is not arbitrary. `plugin/scripts/project_model.mjs` reads a manifest
// exactly twice — framework detection (`const deps = …; const has = n => …`) and
// `SERVER_FRAMEWORKS[*].pkgs` — and both consult a CLOSED, hard-coded set of names. Every other
// pass keys off imports in the source, never the manifest. So a dependency whose name is not in
// that set is, to this engine, INVISIBLE: removing it cannot change a single finding.
//
// The vendored manifests therefore keep exactly the dependencies below, at their upstream-pinned
// versions, and omit the rest. Nothing is BUMPED — a version that is present is the real one — and
// nothing the engine can read is removed. `test/wild_manifest_hygiene.test.mjs` enforces both
// halves: no vendored manifest may declare a name outside this set, and every name here must still
// appear in the engine source (so an upstream rename is caught rather than silently narrowing
// what the corpus exercises).
//
// This is a FIDELITY TRADE, stated rather than hidden: the vendored `package.json` files are a
// subset of upstream, as the vendored file trees already were — no wild case was ever a full
// clone. The trade buys back the repository's own alert list. It is recorded as ERR-007 in
// ERRATA.md.

/** Names read by framework detection in project_model.mjs (`framework = { … }`). */
export const FRAMEWORK_PACKAGES = [
  'next', 'react', 'vue', 'svelte', 'vite', 'expo',
  'react-native', '@capacitor/core', '@capacitor/cli',
  'cordova', 'cordova-android', 'cordova-ios',
  'electron',
  '@supabase/supabase-js', '@supabase/ssr',
  'firebase', 'firebase-admin',
  // framework.llm
  'openai', '@anthropic-ai/sdk', '@google/generative-ai', 'ai', '@ai-sdk/openai',
  'cohere-ai', 'replicate',
  // framework.validators
  'zod', 'yup', 'joi', 'valibot', 'superstruct', 'ajv',
  // framework.ratelimit
  '@upstash/ratelimit', 'express-rate-limit', 'rate-limiter-flexible', 'p-ratelimit',
]

/** Names read by SERVER_FRAMEWORKS[*].pkgs — drives routes and `routeFrameworkGaps`. */
export const SERVER_FRAMEWORK_PACKAGES = [
  'express', 'fastify', 'hono',
  'koa', '@koa/router', 'koa-router',
  '@nestjs/common', '@nestjs/core',
  '@hapi/hapi',
]

/** Everything the engine can see. A name outside this set is invisible to every pass. */
export const OBSERVABLE_PACKAGES = new Set([...FRAMEWORK_PACKAGES, ...SERVER_FRAMEWORK_PACKAGES])
