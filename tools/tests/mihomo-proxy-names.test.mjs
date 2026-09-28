import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

const baseOpts = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const link = (host, name) => 'socks://user:pass@' + host + ':1080#' + encodeURIComponent(name);

function proxyNames(yaml) {
  const lines = yaml.split('\n');
  const start = lines.findIndex(line => line.trim() === 'proxies:');
  const end = lines.findIndex((line, i) => i > start && /^(proxy-groups|rules|listeners):/.test(line));
  if (start < 0) return [];
  const slice = lines.slice(start + 1, end > start ? end : lines.length);
  return slice
    .map(line => line.match(/^\s*- name: (.+)$/))
    .filter(Boolean)
    .map(m => m[1].replace(/^"|"$/g, ''));
}

test('generic Mihomo renames builtin and generated group collisions', () => {
  const input = [
    link('192.0.2.1', 'GLOBAL'),
    link('192.0.2.2', 'DIRECT'),
    link('192.0.2.3', 'REJECT'),
    link('192.0.2.4', '⚡ Fastest'),
    link('192.0.2.5', '🌐 static-health'),
  ].join('\n');
  const yaml = buildFromRequest({ core: 'mihomo', input, options: baseOpts }).data;
  const names = proxyNames(yaml);
  assert.equal(new Set(names).size, 5);
  for (const reserved of ['GLOBAL', 'DIRECT', 'REJECT', '⚡ Fastest', '🌐 static-health']) {
    assert.equal(names.includes(reserved), false, reserved);
  }
});

test('generic Mihomo keeps ordinary duplicate-name suffixing', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: link('192.0.2.10', 'Same') + '\n' + link('192.0.2.11', 'Same'),
    options: baseOpts,
  }).data;
  assert.deepEqual(proxyNames(yaml), ['Same', 'Same-2']);
});

test('per-proxy mode avoids collision with wrapper group names', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: link('192.0.2.20', 'A') + '\n' + link('192.0.2.21', '🔒 A'),
    options: { ...baseOpts, perProxyPort: true },
  }).data;
  const names = proxyNames(yaml);
  assert.equal(names.includes('A'), true);
  assert.equal(names.includes('🔒 A'), false);
  assert.equal(new Set(names).size, 2);
});

test('subscription extras avoid SUB provider groups and duplicate names', () => {
  const input = [
    'https://sub.example/path',
    link('192.0.2.30', 'SUB-sub.example'),
    link('192.0.2.31', 'Same'),
    link('192.0.2.32', 'Same'),
  ].join('\n');
  const yaml = buildFromRequest({
    core: 'mihomo',
    input,
    options: { ...baseOpts, mihomoSubscriptionMode: true, perProxyPort: true },
  }).data;
  const names = proxyNames(yaml);
  assert.equal(names.includes('SUB-sub.example'), false);
  assert.equal(new Set(names).size, names.length);
});
