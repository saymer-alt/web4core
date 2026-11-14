#!/usr/bin/env node
// kas-mini build (developer PC / CI only — no Node.js on routers, issue #425 Phase 0).
// Prefers esbuild from node_modules (npm ci path); falls back to $ESBUILD_BIN standalone binary.
// Usage: node kas-mini/build-mini.mjs
import { spawnSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const dist = path.join(here, 'dist');
mkdirSync(dist, { recursive: true });

const ext = process.platform === 'win32' ? '.cmd' : '';
const npmBin = path.join(root, 'node_modules', '.bin', 'esbuild' + ext);
const bin = process.env.ESBUILD_BIN || (existsSync(npmBin) ? npmBin : 'esbuild');

const res = spawnSync(bin, [
    path.join(here, 'entry-kas-mini.js'),
    '--bundle',
    '--format=esm',
    '--platform=browser',
    '--minify',
    '--charset=utf8',
    `--outfile=${path.join(dist, 'kas-mini.js')}`,
], { stdio: 'inherit' });

if (res.status !== 0) {
    console.error(`esbuild failed (exit ${res.status}); set ESBUILD_BIN to a standalone esbuild binary or run npm ci first`);
    process.exit(res.status || 1);
}

copyFileSync(path.join(here, 'index.html'), path.join(dist, 'index.html'));

const files = readdirSync(dist).map(f => {
    const p = path.join(dist, f);
    const bytes = statSync(p).size;
    const gzip = f.endsWith('.js') ? gzipSync(readFileSync(p)).length : null;
    return { file: f, bytes, gzip };
});

console.log(JSON.stringify({
    dist: path.relative(root, dist),
    files,
    totalBytes: files.reduce((a, f) => a + f.bytes, 0),
    totalGzip: files.reduce((a, f) => a + (f.gzip ?? 0), 0),
}, null, 2));
