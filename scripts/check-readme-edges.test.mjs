#!/usr/bin/env node
// check-readme-edges.test.mjs: self-test for check-readme-edges.mjs. Run: node scripts/check-readme-edges.test.mjs
//
// Why: on 2026-10-20 repid-engine added a LOCAL_MODE log message that contains "http://127.0.0.1:<port>"
// (src/config/prover.ts:66). The checker read it as a prover URL and failed every pull request here, even
// though the engine still names exactly one prover deployment. This test pins both sides:
//   1. a loopback URL in the engine's source is NOT a prover deployment (it must not fail the check);
//   2. any other host on a prover line still IS drift (the fix must not blind the check).
//
// It builds a tiny stand-in for the engine's src/ in a temp dir, runs the real checker against it with
// REPID_ENGINE_DIR, and reads the one line that is about the engine. The README and Rust source it checks
// are this repo's own; only the engine side is faked. No dependencies. Node 18+.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), 'check-readme-edges.mjs');
const DOMAIN = 'zkp-postcard-production.up.railway.app';
const CHECK = '"Called by" matches DealAppSeo/repid-engine source';

// Verbatim from repid-engine src/config/prover.ts:66 (the line that broke the checker).
const LOCAL_MODE_LINE = "    'Set ZKP_SERVICE_URL to a loopback prover (http://127.0.0.1:<port>) to prove locally.';";

function fakeEngine(proverLines) {
  const dir = mkdtempSync(join(tmpdir(), 'readme-edges-'));
  const put = (rel, text) => {
    mkdirSync(dirname(join(dir, 'src', rel)), { recursive: true });
    writeFileSync(join(dir, 'src', rel), text);
  };
  // The two callers the README names: the scoring pipeline and the proof-drain service.
  put('scoring/pipeline.ts',
    `const PINNED_PROVER_URL = 'https://${DOMAIN}';\nawait fetch(\`\${prover}/zkp/repid-proof\`, { method: 'POST' });\n`);
  put('services/proof-drain-service.ts', 'await httpFetch(`${proverUrl}/zkp/repid-proof`, { method: \'POST\' });\n');
  put('config/prover.ts', proverLines.join('\n') + '\n');
  return dir;
}

// Returns { outcome, detail } for the one check that reads the engine's source.
function engineCheck(engineDir) {
  const run = spawnSync(process.execPath, [SCRIPT], {
    env: { ...process.env, REPID_ENGINE_DIR: engineDir },
    encoding: 'utf8',
  });
  const lines = (run.stdout || '').split(/\r?\n/);
  const i = lines.findIndex((l) => l.includes(CHECK));
  assert.ok(i >= 0, `checker printed no line for: ${CHECK}\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`);
  return { outcome: lines[i].slice(0, 11).trim(), detail: (lines[i + 1] || '').trim() };
}

function withEngine(proverLines, fn) {
  const dir = fakeEngine(proverLines);
  try { fn(engineCheck(dir)); } finally { rmSync(dir, { recursive: true, force: true }); }
}

let cases = 0;
const test = (name, fn) => { fn(); cases++; console.log(`ok   ${name}`); };

test('loopback URLs in the engine (127.0.0.1, localhost, [::1]) are not prover deployments', () => {
  withEngine([
    LOCAL_MODE_LINE,
    "  const lan = 'http://localhost:8080'; // prover (local)",
    "  const v6 = 'http://[::1]:8080'; // prover (local)",
  ], (r) => assert.equal(r.outcome, 'VERIFIED', `${r.outcome}: ${r.detail}`));
});

test('another host on a prover line is still drift', () => {
  withEngine([
    LOCAL_MODE_LINE,
    "  const other = 'https://prover.rogue.example';",
  ], (r) => {
    assert.equal(r.outcome, 'FAILED');
    assert.match(r.detail, /prover\.rogue\.example/);
  });
});

console.log(`check-readme-edges.test: PASS (${cases} cases)`);
