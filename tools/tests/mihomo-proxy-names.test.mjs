import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoConfig, buildMihomoSubscriptionConfig } from '../../src/core/mihomo.js';
import { buildBeansFromInput } from '../../src/main.js';

const link = (host, name) => 'socks://user:pass@' + host + ':1080#' + encodeURIComponent(name);

test('generic Mihomo renames builtin and generated group collisions', () => {
  const beans = buildBeansFromInput([
    link('192.0.2.1', 'GLOBAL'),
    link('192.0.2.2', 'DIRECT'),
    link('192.0.2.3', 'REJECT'),
    link('192.0.2.4', '⚡ Fastest'),
    link('192.0.2.5', '🌐 static-health'),
  ].join('\n'));
  const cfg = buildMihomoConfig(beans, { addTun: false });
  const names = cfg.proxies.map(p => p.name);
  assert.equal(new Set(names).size, 5);
  for (const reserved of ['GLOBAL', 'DIRECT', 'REJECT', '⚡ Fastest', '🌐 static-health']) {
    assert.equal(names.includes(reserved), false, reserved);
  }
});

test('generic Mihomo keeps ordinary duplicate-name suffixing', () => {
  const beans = buildBeansFromInput(
    link('192.0.2.10', 'Same') + '\n' + link('192.0.2.11', 'Same')
  );
  const cfg = buildMihomoConfig(beans, { addTun: false });
  assert.deepEqual(cfg.proxies.map(p => p.name), ['Same', 'Same-2']);
});

test('per-proxy mode avoids collision with wrapper group names', () => {
  const beans = buildBeansFromInput(
    link('192.0.2.20', 'A') + '\n' + link('192.0.2.21', '🔒 A')
  );
  const cfg = buildMihomoConfig(beans, { addTun: false, perProxyPort: true });
  const names = cfg.proxies.map(p => p.name);
  assert.equal(names.includes('A'), true);
  assert.equal(names.includes('🔒 A'), false);
  assert.equal(new Set(names).size, 2);
  const groupNames = new Set(cfg['proxy-groups'].map(g => g.name));
  assert.ok(names.every(name => !groupNames.has(name)));
});

test('subscription extras avoid SUB provider groups and duplicate names', () => {
  const extraBeans = buildBeansFromInput([
    link('192.0.2.30', 'SUB-sub.example'),
    link('192.0.2.31', 'Same'),
    link('192.0.2.32', 'Same'),
  ].join('\n'));
  const cfg = buildMihomoSubscriptionConfig(
    ['https://sub.example/path'],
    extraBeans,
    { perProxyPort: true }
  );
  const names = cfg.proxies.map(p => p.name);
  assert.equal(names.includes('SUB-sub.example'), false);
  assert.equal(new Set(names).size, names.length);
  const groupNames = new Set(cfg.groups.map(g => g.name));
  assert.ok(names.every(name => !groupNames.has(name)));
});
