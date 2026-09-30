import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { parseWireGuardConf } from '../../src/core/wireguard.js';

const opts = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const UUID = '00000000-0000-4000-8000-000000000001';

const WARP_CONF = [
  '[Interface]',
  'PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
  'Address = 172.16.0.2/32',
  'DNS = 1.1.1.1',
  'MTU = 1280',
  '[Peer]',
  'PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
  'AllowedIPs = 0.0.0.0/0, ::/0',
  'Endpoint = 162.159.198.2:2408',
].join('\n');

const SE2_CONF = WARP_CONF
  .replace('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=', 'ERERERERERERERERERERERERERERERERERERERERERE=')
  .replace('AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=', 'MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=')
  .replace('172.16.0.2', '10.66.0.2')
  .replace('162.159.198.2:2408', '192.0.2.7:51820');

function build(input, wgConfs, extraOpts) {
  const beans = (wgConfs || []).map((entry, i) =>
    typeof entry === 'string'
      ? parseWireGuardConf(entry, `WARP${i || ''}`)
      : parseWireGuardConf(entry.conf, entry.name));
  return buildFromRequest({
    core: 'mihomo',
    input: input.join('\n'),
    wgBeans: beans,
    options: Object.assign({}, opts, extraOpts),
  }).data;
}

// Top-level proxy block: from the exact "name: X" line to the next top-level list item.
function proxyBlock(yaml, name) {
  const lines = yaml.split('\n');
  const startIdx = lines.findIndex((l) => {
    const t = l.trim().replace(/^- /, '');
    return t === `name: ${name}` || t === `name: "${name}"` || t === `name: '${name}'`;
  });
  assert.ok(startIdx !== -1, `proxy ${name} found in yaml`);
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^\s{2}- name:/.test(lines[i])) { endIdx = i; break; }
  }
  return lines.slice(startIdx, endIdx).join('\n');
}

test('wireguard without dialer-proxy: output unchanged (no dialer-proxy key)', () => {
  const yaml = build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF]);
  assert.ok(yaml.includes('type: wireguard'));
  assert.ok(!yaml.includes('dialer-proxy'));
});

test('byte parity: default build equals build with empty dialer options', () => {
  const input = ['trojan://pass@203.0.113.5:443#T1'];
  const a = buildFromRequest({ core: 'mihomo', input: input.join('\n'), wgBeans: [parseWireGuardConf(WARP_CONF, 'WARP')], options: opts }).data;
  const b = buildFromRequest({ core: 'mihomo', input: input.join('\n'), wgBeans: [parseWireGuardConf(WARP_CONF, 'WARP')], options: Object.assign({}, opts, { wgDialerProxy: '', wgDialerGroupMembers: [] }) }).data;
  assert.equal(a, b);
});

test('variant A: wireguard gets dialer-proxy referencing a link proxy', () => {
  const yaml = build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF], { wgDialerProxy: 'VPS-DK' });
  assert.ok(/dialer-proxy: VPS-DK/.test(proxyBlock(yaml, 'WARP')), 'WG proxy carries dialer-proxy');
  assert.ok(!proxyBlock(yaml, 'VPS-DK').includes('dialer-proxy'), 'target proxy untouched');
});

test('variant A: dialer-proxy may reference a group name', () => {
  const yaml = build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF], { wgDialerProxy: 'GLOBAL' });
  assert.ok(/dialer-proxy: GLOBAL/.test(yaml));
});

test('variant A: unknown target is rejected', () => {
  assert.throws(() => build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF], { wgDialerProxy: 'NO-SUCH' }),
    /dialer-proxy target "NO-SUCH" not found/);
});

test('variant B: select group is created and WG dials through it', () => {
  const yaml = build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK', 'trojan://p@203.0.113.6:443#VPS-EE'],
    [WARP_CONF], { wgDialerProxy: 'WARP-DIALER', wgDialerGroupMembers: ['VPS-DK', 'VPS-EE'] });
  assert.ok(/- name: WARP-DIALER\s*\n\s*type: select/.test(yaml), 'group emitted');
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')));
  const groupIdx = yaml.indexOf('- name: WARP-DIALER');
  const fastestIdx = yaml.indexOf('⚡ Fastest');
  assert.ok(groupIdx !== -1 && fastestIdx !== -1 && groupIdx < fastestIdx, 'dialer group before generated groups');
});

test('variant B: default group name when target omitted', () => {
  const yaml = build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF],
    { wgDialerProxy: '', wgDialerGroupMembers: ['VPS-DK'] });
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')));
});

test('variant B: unknown member rejected', () => {
  assert.throws(() => build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF],
    { wgDialerProxy: 'WARP-DIALER', wgDialerGroupMembers: ['GHOST'] }),
    /member\(s\) not found/);
});

test('variant B: group name conflict with existing proxy rejected', () => {
  assert.throws(() => build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF],
    { wgDialerProxy: 'VPS-DK', wgDialerGroupMembers: ['VPS-DK'] }),
    /conflicts with an existing proxy or group/);
});

test('transit WG profile (Keenetic-like SE2+WG) is exempt from dialer', () => {
  const yaml = build(['trojan://p@203.0.113.9:443#T9'], [{ conf: WARP_CONF, name: 'WARP' }, { conf: SE2_CONF, name: 'SE2' }],
    { wgDialerProxy: 'WARP-DIALER', wgDialerGroupMembers: ['SE2'] });
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')), 'WARP dials via group');
  assert.ok(!proxyBlock(yaml, 'SE2').includes('dialer-proxy'), 'SE2 (transit member) exempt');
});

test('self-named target is excluded and error surfaces when nothing qualifies', () => {
  assert.throws(() => build([], [WARP_CONF], { wgDialerProxy: 'WARP' }),
    /applies to no wireguard proxy/);
});

test('subscription path also emits dialer-proxy for wireguard beans', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: 'http://192.0.2.10/sub.yaml\ntrojan://p@203.0.113.11:443#VPS-DK',
    wgBeans: [parseWireGuardConf(WARP_CONF, 'WARP')],
    options: Object.assign({}, opts, { mihomoSubscriptionMode: true, wgDialerProxy: 'VPS-DK' }),
  }).data;
  assert.ok(/dialer-proxy: VPS-DK/.test(proxyBlock(yaml, 'WARP')));
});

test('AWL priority path also emits dialer-proxy for wireguard beans', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: 'trojan://p@203.0.113.12:443#PRIMARY-1',
    fallbackInput: 'trojan://p2@203.0.113.13:443#FALLBACK-1',
    wgBeans: [parseWireGuardConf(WARP_CONF, 'WARP')],
    options: Object.assign({}, opts, { autoWhitelist: true, wgDialerProxy: 'PRIMARY-1: PRIMARY-1' }),
  }).data;
  // AWL path prefixes final proxy names ("PRIMARY-1: PRIMARY-1"); the dialer
  // target must reference the FINAL generated name (fail-closed validation).
  assert.ok(/dialer-proxy: ["']?PRIMARY-1: PRIMARY-1["']?/.test(yaml));
});

// ---- Variant C: provider-backed dialer group (use:) ----

const GEO_URL = 'https://account.geodema.org/api/sub?token=test';
const GEO_URL2 = 'https://account.geodema.org/api/sub2?token=test';

const subBuild = (extraOpts) => buildFromRequest({
  core: 'mihomo',
  input: GEO_URL + '\n' + GEO_URL2 + '\ntrojan://p@203.0.113.20:443#VPS-SE',
  wgBeans: [parseWireGuardConf(WARP_CONF, 'WARP')],
  options: Object.assign({}, opts, { mihomoSubscriptionMode: true }, extraOpts),
}).data;

test('variant C: provider-backed group is created via use: and WG dials through it', () => {
  const yaml = subBuild({ wgDialerProxy: 'WARP-DIALER', wgDialerProviders: [GEO_URL] });
  assert.ok(/- name: WARP-DIALER\s*\n\s*type: select\s*\n\s*use:\s*\n\s*- account\.geodema\.org/.test(yaml), 'group with use: emitted');
  assert.ok(!/- name: WARP-DIALER[\s\S]*?proxies:/.test(yaml.slice(yaml.indexOf('- name: WARP-DIALER'), yaml.indexOf('- name: WARP-DIALER') + 200)), 'no static proxies in provider group');
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')));
});

test('variant C: multiple providers produce multiple use entries', () => {
  const yaml = subBuild({ wgDialerProxy: 'WARP-DIALER', wgDialerProviders: [GEO_URL, GEO_URL2] });
  const block = yaml.slice(yaml.indexOf('- name: WARP-DIALER'), yaml.indexOf('⚡ Fastest'));
  assert.equal((block.match(/^\s+- account\.geodema\.org(-2)?$/gm) || []).length, 2, 'two use entries');
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')));
});

test('variant C: members and providers combine into one group (proxies + use)', () => {
  const yaml = subBuild({ wgDialerProxy: 'WARP-DIALER', wgDialerGroupMembers: ['VPS-SE'], wgDialerProviders: [GEO_URL] });
  const block = yaml.slice(yaml.indexOf('- name: WARP-DIALER'), yaml.indexOf('⚡ Fastest'));
  assert.ok(block.includes('proxies:'), 'proxies present');
  assert.ok(block.includes('use:'), 'use present');
  assert.ok(/dialer-proxy: WARP-DIALER/.test(proxyBlock(yaml, 'WARP')));
  assert.ok(!proxyBlock(yaml, 'VPS-SE').includes('dialer-proxy'), 'transit member exempt');
});

test('variant C: default group name when target omitted', () => {
  const yaml = subBuild({ wgDialerProviders: [GEO_URL] });
  assert.ok(/- name: WARP-DIALER\s*\n\s*type: select\s*\n\s*use:/.test(yaml));
});

test('variant C: unknown provider URL fails closed', () => {
  assert.throws(() => subBuild({ wgDialerProxy: 'WARP-DIALER', wgDialerProviders: ['https://ghost.example.com/sub'] }),
    /dialer provider URL not found/);
});

test('variant C: provider URL without subscription mode fails closed', () => {
  assert.throws(() => build(['trojan://p@203.0.113.21:443#T21'], [WARP_CONF],
    { wgDialerProxy: 'WARP-DIALER', wgDialerProviders: [GEO_URL] }),
    /dialer provider URL not found/);
});

test('variant C: group name conflict still rejected', () => {
  assert.throws(() => subBuild({ wgDialerProxy: 'VPS-SE', wgDialerProviders: [GEO_URL] }),
    /conflicts with an existing proxy or group/);
});

test('variant C: provider-backed group cannot contain the WG proxy (no loop by construction)', () => {
  const yaml = subBuild({ wgDialerProxy: 'WARP-DIALER', wgDialerProviders: [GEO_URL] });
  // The only dialer user is the WG proxy itself; the group has no static proxies.
  const block = yaml.slice(yaml.indexOf('- name: WARP-DIALER'), yaml.indexOf('⚡ Fastest'));
  assert.ok(!/^s+- WARP$/m.test(block), 'WG name absent from provider group members');
});
