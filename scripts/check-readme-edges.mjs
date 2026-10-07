#!/usr/bin/env node
// check-readme-edges.mjs: checks the edges README.md names against the code that makes them true.
//
// README.md says what the prover (services/zkp-postcard) calls, what calls it, and which routes
// it serves. Prose drifts away from code without anyone noticing. This script reads the Rust
// source, Cargo.lock and README.md and fails when they disagree. When REPID_ENGINE_DIR points at
// a DealAppSeo/repid-engine checkout, it also checks the "Called by" edge against the caller's
// source.
//
// It checks edges, not a picture: routes and which of them need the auth token, outbound
// requests, env vars, the one deployment domain, and the map link. `#[cfg(test)]` modules are
// skipped: a test's stand-in server and HTTP client are not edges of the running service.
//
// Exit codes. There are three outcomes, never two:
//   0  VERIFIED     every check ran and passed
//   1  FAILED       at least one check ran and failed
//   2  NOT CHECKED  nothing failed, but at least one check could not run
//
// No dependencies. Node 18+.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README_PATH = join(ROOT, 'README.md');
const SRC_DIR = join(ROOT, 'services/zkp-postcard/src');
const MAIN_PATH = join(SRC_DIR, 'main.rs');
const LOCK_PATH = join(ROOT, 'services/zkp-postcard/Cargo.lock');

const DOMAIN = 'zkp-postcard-production.up.railway.app';
const CALLER = 'DealAppSeo/repid-engine';
const MAP_LINK = 'https://github.com/DealAppSeo/hyperdag-protocol/blob/main/BUILDERS.md#how-the-pieces-fit';
const WHERE_HEADING = '## Where this sits';
const PARTS = ['**Calls:**', '**Called by:**', '**The whole map:**'];
const METHODS = 'GET|POST|PUT|PATCH|DELETE|HEAD';

// Outbound mechanisms other than the reqwest client. If any of these appears in the source,
// the README's "Calls" list cannot be complete, so the checker fails rather than guessing.
const OTHER_OUTBOUND = [
  /reqwest::get\s*\(/, /reqwest::blocking/, /TcpStream::connect/, /UdpSocket/, /hyper::Client/,
  /\bureq::/, /\bsurf::/, /\bisahc\b/, /Command::new/, /tokio_postgres|sqlx::|diesel::/,
];

const results = [];
const record = (outcome, name, detail = '') => results.push({ outcome, name, detail });
const verified = (n, d) => record('VERIFIED', n, d);
const failed = (n, d) => record('FAILED', n, d);
const notChecked = (n, d) => record('NOT CHECKED', n, d);

const read = (p) => readFileSync(p, 'utf8');
const lineOf = (text, index) => text.slice(0, index).split('\n').length;
const rel = (p) => relative(ROOT, p) || p;

// Replace Rust comments with spaces, keeping string literals and line numbers intact, so that
// "https://..." inside a string is still seen and prose inside a comment is not.
function stripRustComments(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '/' && n === '/') {
      while (i < src.length && src[i] !== '\n') { out += ' '; i++; }
    } else if (c === '/' && n === '*') {
      let depth = 1; out += '  '; i += 2;
      while (i < src.length && depth > 0) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; out += '  '; i += 2; continue; }
        if (src[i] === '*' && src[i + 1] === '/') { depth--; out += '  '; i += 2; continue; }
        out += src[i] === '\n' ? '\n' : ' '; i++;
      }
    } else if (c === 'r' && (n === '"' || (n === '#' && /^r#+"/.test(src.slice(i, i + 10))))) {
      const hashes = src.slice(i + 1).match(/^#*/)[0];
      const close = '"' + hashes;
      const start = i;
      i += 1 + hashes.length + 1;
      const end = src.indexOf(close, i);
      i = end === -1 ? src.length : end + close.length;
      out += src.slice(start, i);
    } else if (c === '"') {
      const start = i; i++;
      while (i < src.length && src[i] !== '"') { if (src[i] === '\\') i++; i++; }
      i++;
      out += src.slice(start, i);
    } else if (c === "'" && /^'(\\.|[^\\'\n])'/.test(src.slice(i, i + 4))) {
      const m = src.slice(i).match(/^'(\\.|[^\\'\n])'/)[0];
      out += m; i += m.length;
    } else {
      out += c; i++;
    }
  }
  return out;
}

// Blank out every `#[cfg(test)] mod name { ... }` block (input already comment-stripped), keeping
// newlines so line numbers hold. The edges this script checks are what the SERVICE does at runtime;
// a test's own stand-in server and HTTP client are not routes or outbound calls of the prover.
// Braces inside string and char literals are skipped, so `format!("{}", x)` cannot unbalance it.
function stripTestModules(code) {
  const blank = (s) => s.replace(/[^\n]/g, ' ');
  let out = code;
  for (const m of [...code.matchAll(/#\[cfg\(test\)\]\s*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/g)].reverse()) {
    let i = m.index + m[0].length;
    let depth = 1;
    while (i < code.length && depth > 0) {
      const c = code[i];
      const prev = code[i - 1] ?? '';
      if (c === 'r' && /^r#*"/.test(code.slice(i, i + 10)) && (prev === 'b' || !/[A-Za-z0-9_]/.test(prev))) {
        const hashes = code.slice(i + 1).match(/^#*/)[0];
        const end = code.indexOf('"' + hashes, i + 2 + hashes.length);
        i = end === -1 ? code.length : end + 1 + hashes.length;
      } else if (c === '"') {
        i++;
        while (i < code.length && code[i] !== '"') { if (code[i] === '\\') i++; i++; }
        i++;
      } else if (c === "'" && /^'(\\.|[^\\'\n])'/.test(code.slice(i, i + 4))) {
        i += code.slice(i).match(/^'(\\.|[^\\'\n])'/)[0].length;
      } else {
        if (c === '{') depth++;
        else if (c === '}') depth--;
        i++;
      }
    }
    out = out.slice(0, m.index) + blank(out.slice(m.index, i)) + out.slice(i);
  }
  return out;
}

function section(md, heading) {
  const start = md.indexOf(`\n${heading}\n`);
  if (start === -1) return null;
  const body = md.slice(start + heading.length + 2);
  const next = body.search(/\n## /);
  return next === -1 ? body : body.slice(0, next);
}

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === '__tests__' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, files);
    else if (name.endsWith('.ts') && !name.endsWith('.test.ts') && !name.endsWith('.d.ts')) files.push(p);
  }
  return files;
}

// ---------------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------------
for (const p of [README_PATH, MAIN_PATH, LOCK_PATH]) {
  if (!existsSync(p)) {
    failed('inputs exist', `${rel(p)} is missing`);
  }
}
if (results.some((r) => r.outcome === 'FAILED')) finish();

const readme = read(README_PATH);
const mainRaw = read(MAIN_PATH);
const main = stripTestModules(stripRustComments(mainRaw));
const srcFiles = readdirSync(SRC_DIR).filter((f) => f.endsWith('.rs')).map((f) => join(SRC_DIR, f));
const srcs = srcFiles.map((p) => ({ path: p, raw: read(p), code: stripTestModules(stripRustComments(read(p))) }));

// ---------------------------------------------------------------------------------------------
// Code side: the router
// ---------------------------------------------------------------------------------------------
const routeRe = new RegExp(String.raw`\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|patch|delete|head)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)`, 'g');
const codeRoutes = [];
for (const m of main.matchAll(routeRe)) {
  codeRoutes.push({ method: m[2].toUpperCase(), path: m[1], handler: m[3], line: lineOf(main, m.index), index: m.index });
}
const routeCalls = [...main.matchAll(/\.route\(/g)].length;
if (routeCalls !== codeRoutes.length || codeRoutes.length === 0) {
  failed('router is parseable',
    `main.rs has ${routeCalls} .route( calls but ${codeRoutes.length} matched the form .route("path", method(handler)). ` +
    'Extend this checker before trusting it.');
}
for (const shape of ['.nest(', '.merge(', '.route_service(', '.nest_service(', '.fallback(']) {
  if (main.includes(shape)) failed('router is parseable', `main.rs uses ${shape} which this checker does not follow`);
}
const routeKey = (r) => `${r.method} ${r.path}`;
const codeRouteKeys = new Set(codeRoutes.map(routeKey));
const codePaths = new Set(codeRoutes.map((r) => r.path));
const handlerOf = (path) => codeRoutes.find((r) => r.path === path)?.handler;

// ---------------------------------------------------------------------------------------------
// README structure: "## Where this sits" with its three parts, in order
// ---------------------------------------------------------------------------------------------
const where = section(readme, WHERE_HEADING);
const parts = {};
if (where === null) {
  failed('README has "## Where this sits"', 'heading not found (it must be exactly "## Where this sits")');
} else {
  const idx = PARTS.map((p) => where.indexOf(p));
  if (idx.some((i) => i === -1) || !(idx[0] < idx[1] && idx[1] < idx[2])) {
    failed('"## Where this sits" has its three parts in order', `expected ${PARTS.join(', ')}`);
  } else {
    parts.calls = where.slice(idx[0], idx[1]);
    parts.calledBy = where.slice(idx[1], idx[2]);
    parts.map = where.slice(idx[2]);
    verified('"## Where this sits" has its three parts in order', PARTS.join(' / '));
  }
}

// ---------------------------------------------------------------------------------------------
// Edge 1: routes. The README endpoints table must equal the router, in both directions.
// ---------------------------------------------------------------------------------------------
const endpoints = section(readme, '## HTTP endpoints');
const tableRe = new RegExp(String.raw`^\|\s*\x60(${METHODS})\x60\s*\|\s*\x60([^\x60]+)\x60\s*\|(.*)$`, 'gm');
const readmeRows = endpoints ? [...endpoints.matchAll(tableRe)].map((m) => ({ method: m[1], path: m[2], text: m[3] })) : [];
if (!endpoints || readmeRows.length === 0) {
  failed('README endpoints table matches main.rs router', 'no "## HTTP endpoints" table rows found');
} else {
  const readmeKeys = new Set(readmeRows.map(routeKey));
  const missingInReadme = codeRoutes.filter((r) => !readmeKeys.has(routeKey(r)));
  const missingInCode = readmeRows.filter((r) => !codeRouteKeys.has(routeKey(r)));
  if (missingInReadme.length || missingInCode.length) {
    failed('README endpoints table matches main.rs router', [
      ...missingInReadme.map((r) => `main.rs:${r.line} ${routeKey(r)} is not in the README table`),
      ...missingInCode.map((r) => `README lists ${routeKey(r)}, which main.rs does not route`),
    ].join('; '));
  } else {
    verified('README endpoints table matches main.rs router',
      codeRoutes.map((r) => `${routeKey(r)} (main.rs:${r.line})`).join(', '));
  }

  // "same handler as `X`" claims
  for (const row of readmeRows) {
    const m = row.text.match(/same handler as \x60([^\x60]+)\x60/);
    if (!m) continue;
    const a = handlerOf(row.path);
    const b = handlerOf(m[1]);
    if (a && b && a === b) verified(`${row.path} is the same handler as ${m[1]}`, `both route to ${a}()`);
    else failed(`${row.path} is the same handler as ${m[1]}`, `main.rs routes them to ${a ?? 'nothing'}() and ${b ?? 'nothing'}()`);
  }

  // {param} routes under axum 0.7 do not route. The README must say so exactly when that is true.
  const lock = read(LOCK_PATH);
  const axum = lock.match(/name = "axum"\nversion = "(\d+)\.(\d+)\.(\d+)"/);
  const braceRoutes = codeRoutes.filter((r) => r.path.includes('{'));
  if (!axum) {
    failed('{param} route note matches the axum version', 'axum not found in Cargo.lock');
  } else if (braceRoutes.length) {
    const axumVer = `${axum[1]}.${axum[2]}.${axum[3]}`;
    const literalBraces = Number(axum[1]) === 0 && Number(axum[2]) < 8;
    for (const r of braceRoutes) {
      const row = readmeRows.find((x) => x.path === r.path);
      const saysBroken = !!row && /does not work/.test(row.text);
      if (literalBraces && !saysBroken) {
        failed(`${r.path} note matches axum ${axumVer}`, `axum ${axumVer} treats {braces} literally, so this route does not work; the README row must say "does not work"`);
      } else if (!literalBraces && saysBroken) {
        failed(`${r.path} note matches axum ${axumVer}`, `axum ${axumVer} supports {param} routes; the README "does not work" note is stale`);
      } else if (literalBraces && !readme.includes(axumVer)) {
        failed(`${r.path} note matches axum ${axumVer}`, `the README note must name the pinned axum version ${axumVer}`);
      } else {
        verified(`${r.path} note matches axum ${axumVer}`, literalBraces ? 'README says it does not work; axum < 0.8 treats {braces} literally' : 'route works and README does not say otherwise');
      }
    }
  }

  // Auth (F-10). The README's "Auth" column must match PUBLIC_PATHS in main.rs: "Public" for
  // those paths, "Bearer token" for every other row. And the auth layer must come AFTER every
  // .route(, because axum applies .layer only to routes added before it: a route added below the
  // layer would be served without a token while this table still said "Bearer token".
  const AUTH_CHECK = 'README "Auth" column matches main.rs, and the auth layer wraps every route';
  const pub = main.match(/const\s+PUBLIC_PATHS\s*:\s*&\[\s*&(?:'static\s+)?str\s*\]\s*=\s*&\[([^\]]*)\]/);
  const layer = [...main.matchAll(/\.layer\(\s*middleware::from_fn_with_state\([^;]*?require_bearer\s*\)\s*\)/g)];
  const authProblems = [];
  if (!pub) authProblems.push('const PUBLIC_PATHS not found in main.rs');
  if (!/env::var\(\s*"PROVER_AUTH_TOKEN"\s*\)/.test(main)) authProblems.push('main.rs does not read PROVER_AUTH_TOKEN');
  if (layer.length !== 1) authProblems.push(`expected one .layer(middleware::from_fn_with_state(.., require_bearer)) in main.rs, found ${layer.length}`);
  const publicPaths = new Set(pub ? [...pub[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : []);
  if (pub) {
    for (const p of publicPaths) if (!codePaths.has(p)) authProblems.push(`PUBLIC_PATHS names ${p}, which main.rs does not route`);
    for (const row of readmeRows) {
      const cell = row.text.split('|')[0].trim();
      const want = publicPaths.has(row.path) ? 'Public' : 'Bearer token';
      if (cell !== want) authProblems.push(`README row ${routeKey(row)} says "${cell}" in the Auth column; main.rs makes it "${want}"`);
    }
  }
  if (layer.length === 1) {
    for (const r of codeRoutes) {
      if (r.index > layer[0].index) authProblems.push(`main.rs:${r.line} ${routeKey(r)} is added after the auth layer (main.rs:${lineOf(main, layer[0].index)}), so it is served without a token`);
    }
  }
  if (authProblems.length) failed(AUTH_CHECK, authProblems.join('; '));
  else verified(AUTH_CHECK, `public: ${[...publicPaths].join(', ')}; every other route needs the bearer token; auth layer at main.rs:${lineOf(main, layer[0].index)}, after all ${codeRoutes.length} routes`);
}

// Every inline `METHOD /path` anywhere in the README must be a real route.
const inlineRe = new RegExp(String.raw`\x60(${METHODS}) (\/[^\x60\s]*)\x60`, 'g');
const inline = [...readme.matchAll(inlineRe)].map((m) => ({ method: m[1], path: m[2], line: lineOf(readme, m.index) }));
const badInline = inline.filter((r) => !codeRouteKeys.has(routeKey(r)));
if (badInline.length) {
  failed('every `METHOD /path` named in README is routed', badInline.map((r) => `README.md:${r.line} ${routeKey(r)}`).join('; '));
} else {
  verified('every `METHOD /path` named in README is routed', `${inline.length} mention(s)`);
}

// ---------------------------------------------------------------------------------------------
// Edge 2: Calls. The README "Calls" list must equal the outbound requests in the source.
// ---------------------------------------------------------------------------------------------
const codeCalls = [];
let sends = 0;
for (const f of srcs) {
  for (const m of f.code.matchAll(/\/rest\/v1\/([A-Za-z0-9_]+)/g)) {
    // The client call may come before the URL (`client.post(&format!(..))`) or after it
    // (`let url = format!(..); client.get(&url)`). Take the nearest one within a small window.
    const lo = Math.max(0, m.index - 300);
    const win = f.code.slice(lo, m.index + 600);
    let best = null;
    for (const c of win.matchAll(/http_client\s*\.\s*(get|post|put|patch|delete|head)\s*\(/g)) {
      const dist = Math.abs(lo + c.index - m.index);
      if (!best || dist < best.dist) best = { dist, method: c[1].toUpperCase() };
    }
    codeCalls.push({ method: best ? best.method : '?', table: m[1], where: `${rel(f.path)}:${lineOf(f.code, m.index)}` });
  }
  sends += [...f.code.matchAll(/\.send\(\s*\)/g)].length;
  for (const re of OTHER_OUTBOUND) {
    const m = f.code.match(re);
    if (m) failed('no outbound mechanism outside the README', `${rel(f.path)}:${lineOf(f.code, m.index)} uses ${m[0]}`);
  }
  for (const m of f.code.matchAll(/https?:\/\/[A-Za-z0-9.\-]+/g)) {
    failed('no hard-coded outbound URL outside the README', `${rel(f.path)}:${lineOf(f.code, m.index)} names ${m[0]}`);
  }
}
if (sends !== codeCalls.length) {
  failed('every outbound request is attributed', `${sends} .send() call(s) in services/zkp-postcard/src but ${codeCalls.length} attributed to a /rest/v1/ request`);
}
if (parts.calls !== undefined) {
  const readmeCalls = [...parts.calls.matchAll(new RegExp(String.raw`\x60(${METHODS}) \{SUPABASE_URL\}\/rest\/v1\/([A-Za-z0-9_]+)`, 'g'))]
    .map((m) => ({ method: m[1], table: m[2] }));
  const key = (c) => `${c.method} /rest/v1/${c.table}`;
  const a = new Set(codeCalls.map(key));
  const b = new Set(readmeCalls.map(key));
  const onlyCode = [...a].filter((k) => !b.has(k));
  const onlyReadme = [...b].filter((k) => !a.has(k));
  if (onlyCode.length || onlyReadme.length || codeCalls.some((c) => c.method === '?')) {
    failed('README "Calls" matches outbound requests in code', [
      ...onlyCode.map((k) => `code makes ${k}, README "Calls" does not name it`),
      ...onlyReadme.map((k) => `README "Calls" names ${k}, code does not make it`),
      ...codeCalls.filter((c) => c.method === '?').map((c) => `${c.where}: cannot tell the HTTP method`),
    ].join('; '));
  } else {
    verified('README "Calls" matches outbound requests in code',
      codeCalls.map((c) => `${key(c)} (${c.where})`).join(', ') + `; ${sends} .send() total`);
  }
}

// Env vars: every one the code reads must be named in the README, and every SUPABASE_* one
// must be named in "Calls", because those variables are the target and credential of that call.
const envRe = /(?:env::var(?:_os)?\(\s*"([A-Z0-9_]+)"\s*\)|(?:option_)?env!\(\s*"([A-Z0-9_]+)"\s*\))/g;
const codeEnv = new Map();
for (const f of srcs) {
  for (const m of f.code.matchAll(envRe)) codeEnv.set(m[1] ?? m[2], `${rel(f.path)}:${lineOf(f.code, m.index)}`);
}
const envMissing = [...codeEnv.keys()].filter((v) => !readme.includes('`' + v + '`'));
const envMissingCalls = parts.calls === undefined ? [] :
  [...codeEnv.keys()].filter((v) => v.startsWith('SUPABASE_') && !parts.calls.includes('`' + v + '`'));
if (envMissing.length || envMissingCalls.length) {
  failed('README names every env var the code reads', [
    ...envMissing.map((v) => `${v} (${codeEnv.get(v)}) is not named in README`),
    ...envMissingCalls.map((v) => `${v} (${codeEnv.get(v)}) is not named in "Calls"`),
  ].join('; '));
} else {
  verified('README names every env var the code reads', [...codeEnv.entries()].map(([v, w]) => `${v} (${w})`).join(', '));
}

// ---------------------------------------------------------------------------------------------
// Edge 3: Called by, the domain, and the map link
// ---------------------------------------------------------------------------------------------
const railwayHosts = [...new Set([...readme.matchAll(/[A-Za-z0-9-]+\.up\.railway\.app/g)].map((m) => m[0]))];
const otherHosts = railwayHosts.filter((h) => h !== DOMAIN);
if (!railwayHosts.includes(DOMAIN) || otherHosts.length) {
  failed('README names exactly one deployment domain, the one the engine calls',
    `found: ${railwayHosts.join(', ') || 'none'}; expected only ${DOMAIN}`);
} else {
  verified('README names exactly one deployment domain, the one the engine calls', DOMAIN);
}

let calledByRoutes = [];
if (parts.calledBy !== undefined) {
  calledByRoutes = [...parts.calledBy.matchAll(inlineRe)].map((m) => ({ method: m[1], path: m[2] }));
  const problems = [];
  if (!parts.calledBy.includes(CALLER)) problems.push(`does not name ${CALLER}`);
  if (!parts.calledBy.includes(DOMAIN)) problems.push(`does not name ${DOMAIN}`);
  if (!calledByRoutes.length) problems.push('names no `METHOD /path`');
  for (const r of calledByRoutes) if (!codeRouteKeys.has(routeKey(r))) problems.push(`${routeKey(r)} is not routed in main.rs`);
  if (problems.length) failed('"Called by" names the caller, the domain and a routed path', problems.join('; '));
  else {
    const lines = calledByRoutes.map((r) => `${routeKey(r)} (main.rs:${codeRoutes.find((c) => routeKey(c) === routeKey(r)).line})`);
    verified('"Called by" names the caller, the domain and a routed path', `${CALLER} -> ${DOMAIN} ${lines.join(', ')}`);
  }
}

if (parts.map !== undefined) {
  if (parts.map.includes(MAP_LINK)) verified('"The whole map" links to BUILDERS.md#how-the-pieces-fit', MAP_LINK);
  else failed('"The whole map" links to BUILDERS.md#how-the-pieces-fit', `expected ${MAP_LINK}`);
}

// ---------------------------------------------------------------------------------------------
// Edge 3, other end: the caller's source (optional; NOT CHECKED without it)
// ---------------------------------------------------------------------------------------------
const engineDir = process.env.REPID_ENGINE_DIR;
const ENGINE_CHECK = `"Called by" matches ${CALLER} source`;
if (!engineDir) {
  notChecked(ENGINE_CHECK, `set REPID_ENGINE_DIR to a ${CALLER} checkout to check it`);
} else if (!existsSync(join(engineDir, 'src'))) {
  failed(ENGINE_CHECK, `REPID_ENGINE_DIR=${engineDir} has no src/ directory`);
} else {
  // This reads the caller's source by what it DOES, not by how it is laid out: which prover
  // paths it appends to a base URL, from which files, and which prover URL literal it holds.
  // The engine is free to move its default around (it did, into one pinned constant, on
  // 2026-10-07) without breaking this check, as long as the edge itself still holds.
  const files = walk(join(engineDir, 'src'));
  const builtPaths = [];
  const proverLiterals = [];
  const problems = [];
  const PATH_RES = [/\$\{[^}]+\}(\/(?:zkp|prove)\/[A-Za-z0-9_\-]+)/g, /\+\s*['"](\/(?:zkp|prove)\/[A-Za-z0-9_\-]+)['"]/g];
  for (const p of files) {
    const relp = relative(engineDir, p).split('\\').join('/');
    read(p).split('\n').forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
      const where = `${relp}:${i + 1}`;
      let buildsPath = false;
      for (const re of PATH_RES) {
        for (const m of line.matchAll(re)) { builtPaths.push({ path: m[1], file: relp, where }); buildsPath = true; }
      }
      if (buildsPath || /prover|ZKP_SERVICE_URL/i.test(line)) {
        for (const m of line.matchAll(/https?:\/\/([A-Za-z0-9.\-]+)/g)) proverLiterals.push({ host: m[1], where });
      }
    });
  }
  for (const b of builtPaths) if (!codePaths.has(b.path)) problems.push(`${b.where} calls ${b.path}, which main.rs does not route`);
  for (const r of calledByRoutes) {
    const from = builtPaths.filter((b) => b.path === r.path);
    if (!from.length) problems.push(`README "Called by" names ${r.path} but no engine source builds that path`);
    if (!from.some((b) => /(^|\/)scoring\//.test(b.file))) problems.push(`nothing under src/scoring/ (the API scoring pipeline) calls ${r.path}`);
    if (!from.some((b) => /proof-drain/.test(b.file))) problems.push(`no proof-drain file calls ${r.path}`);
  }
  for (const l of proverLiterals) if (l.host !== DOMAIN) problems.push(`${l.where} names prover host ${l.host}, not ${DOMAIN}`);
  if (!proverLiterals.some((l) => l.host === DOMAIN)) problems.push(`engine source names no prover URL for ${DOMAIN}`);
  if (problems.length) failed(ENGINE_CHECK, problems.join('; '));
  else {
    const uniq = [...new Set(builtPaths.map((b) => b.path))];
    const callers = calledByRoutes.map((r) => `${r.path} from ${[...new Set(builtPaths.filter((b) => b.path === r.path).map((b) => b.file))].join(', ')}`);
    verified(ENGINE_CHECK,
      `engine appends ${uniq.join(', ')} to a prover base, all routed here; ${callers.join('; ')}; ` +
      `prover URL literal: https://${DOMAIN} at ${proverLiterals.map((l) => l.where).join(', ')}`);
  }
}

finish();

function finish() {
  const order = { FAILED: 0, 'NOT CHECKED': 1, VERIFIED: 2 };
  for (const r of results.sort((a, b) => order[a.outcome] - order[b.outcome])) {
    console.log(`${r.outcome.padEnd(11)}  ${r.name}${r.detail ? `\n             ${r.detail}` : ''}`);
  }
  const f = results.filter((r) => r.outcome === 'FAILED').length;
  const n = results.filter((r) => r.outcome === 'NOT CHECKED').length;
  const v = results.filter((r) => r.outcome === 'VERIFIED').length;
  const verdict = f ? 'FAILED' : n ? 'NOT CHECKED' : 'VERIFIED';
  console.log(`\nreadme-edges: ${verdict} (${v} verified, ${n} not checked, ${f} failed)`);
  process.exit(f ? 1 : n ? 2 : 0);
}
