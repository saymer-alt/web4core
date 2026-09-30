import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { buildMihomoYaml } from '../../src/core/yaml.js';
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

test('variant A: auto-groups containing the WG proxy are rejected as a cycle', () => {
  // GLOBAL contains WARP (directly and via the Fastest group) - the handshake
  // route would return to its own outbound, so the graph detector rejects it.
  assert.throws(() => build(['vless://' + UUID + '@192.0.2.1:443#VPS-DK'], [WARP_CONF], { wgDialerProxy: 'GLOBAL' }),
    /circular dialer-proxy dependency for .WARP./);
  // A group that does NOT contain the WG proxy stays a valid target.
  const proxies = [
    { name: 'VPS-DK', type: 'trojan', server: '203.0.113.1', port: 443, password: 'p' },
    { name: 'WARP', type: 'wireguard', server: '162.159.198.2', port: 2408, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '172.16.0.2', 'dialer-proxy': 'HOP' },
  ];
  const yaml = buildMihomoYaml(proxies, [{ name: 'HOP', type: 'select', proxies: ['VPS-DK'] }, { name: 'GLOBAL', type: 'select', proxies: ['VPS-DK', 'WARP', 'REJECT'] }], null, ['MATCH,GLOBAL'], [], opts);
  assert.ok(/dialer-proxy: HOP/.test(yaml));
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

// ---- WireGuard-over-WireGuard chains and the dependency-graph cycle detector ----

const WG_A = WARP_CONF.replace('WARP', 'WG-A');
const wgConf = (name, endpoint, ip) => WARP_CONF
  .replace('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=', Buffer.alloc(32, name.length + 1).toString('base64'))
  .replace('AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=', Buffer.alloc(32, name.length + 41).toString('base64'))
  .replace('172.16.0.2', ip)
  .replace('162.159.198.2:2408', endpoint)
  .replace(/name: x/, 'name: ' + name);

test('variant A supports WG-over-WG: WARP-OUTER dials through WARP-INNER (valid chain)', () => {
  const inner = wgConf('WARP-INNER', '192.0.2.65:51820', '10.66.1.2');
  const outer = wgConf('WARP-OUTER', '162.159.198.2:2408', '172.16.0.2');
  const yaml = build(['trojan://p@203.0.113.30:443#T30'], [{ conf: inner, name: 'WARP-INNER' }, { conf: outer, name: 'WARP-OUTER' }],
    { wgDialerProxy: 'WARP-INNER' });
  const outerBlock = proxyBlock(yaml, 'WARP-OUTER');
  const innerBlock = proxyBlock(yaml, 'WARP-INNER');
  assert.ok(/dialer-proxy: WARP-INNER/.test(outerBlock), 'outer dials via inner');
  assert.ok(!innerBlock.includes('dialer-proxy'), 'inner (transit) dials directly');
});

test('3-node chain via manual per-proxy dialer fields is valid (no false rejection)', () => {
  const proxies = [
    { name: 'WG-C', type: 'wireguard', server: '192.0.2.71', port: 51820, 'private-key': Buffer.alloc(32, 3).toString('base64'), 'public-key': Buffer.alloc(32, 13).toString('base64'), ip: '10.66.3.2' },
    { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': Buffer.alloc(32, 2).toString('base64'), 'public-key': Buffer.alloc(32, 12).toString('base64'), ip: '10.66.2.2', 'dialer-proxy': 'WG-C' },
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'WG-B' },
  ];
  const yaml = buildMihomoYaml(proxies, [{ name: 'GLOBAL', type: 'select', proxies: ['WG-A', 'WG-B', 'WG-C', 'REJECT'] }], null, ['MATCH,GLOBAL'], [], opts);
  assert.ok(!/circular/.test(yaml));
});

test('group-mediated chain WG-A -> group -> WG-B -> WG-C is valid', () => {
  const proxies = [
    { name: 'WG-C', type: 'wireguard', server: '192.0.2.71', port: 51820, 'private-key': Buffer.alloc(32, 3).toString('base64'), 'public-key': Buffer.alloc(32, 13).toString('base64'), ip: '10.66.3.2' },
    { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': Buffer.alloc(32, 2).toString('base64'), 'public-key': Buffer.alloc(32, 12).toString('base64'), ip: '10.66.2.2', 'dialer-proxy': 'HOP-C' },
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'HOP-B' },
  ];
  const groups = [
    { name: 'HOP-C', type: 'select', proxies: ['WG-C'] },
    { name: 'HOP-B', type: 'select', proxies: ['WG-B'] },
    { name: 'GLOBAL', type: 'select', proxies: ['WG-A', 'REJECT'] },
  ];
  const yaml = buildMihomoYaml(proxies, groups, null, ['MATCH,GLOBAL'], [], opts);
  assert.ok(yaml.includes('name: HOP-B'));
});

test('self-loop is rejected by the graph detector', () => {
  const proxies = [{ name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'WG-A' }];
  assert.throws(() => buildMihomoYaml(proxies, [], null, [], [], opts), /circular dialer-proxy dependency for "WG-(A|B)"/);
});

test('2-node loop WG-A -> WG-B -> WG-A is rejected', () => {
  const proxies = [
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'WG-B' },
    { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': Buffer.alloc(32, 2).toString('base64'), 'public-key': Buffer.alloc(32, 12).toString('base64'), ip: '10.66.2.2', 'dialer-proxy': 'WG-A' },
  ];
  assert.throws(() => buildMihomoYaml(proxies, [], null, [], [], opts), /circular dialer-proxy dependency for "WG-(A|B)"/);
});

test('loop through a static group (WG-A -> group -> WG-A) is rejected', () => {
  const proxies = [{ name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'HOP' }];
  const groups = [{ name: 'HOP', type: 'select', proxies: ['WG-A', 'DIRECT'] }];
  assert.throws(() => buildMihomoYaml(proxies, groups, null, [], [], opts), /circular dialer-proxy dependency for "WG-(A|B)"/);
});

test('long loop through two groups is rejected', () => {
  const proxies = [
    { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': Buffer.alloc(32, 2).toString('base64'), 'public-key': Buffer.alloc(32, 12).toString('base64'), ip: '10.66.2.2', 'dialer-proxy': 'GROUP-B' },
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'GROUP-A' },
  ];
  const groups = [
    { name: 'GROUP-A', type: 'select', proxies: ['WG-B'] },
    { name: 'GROUP-B', type: 'select', proxies: ['WG-A'] },
  ];
  assert.throws(() => buildMihomoYaml(proxies, groups, null, [], [], opts), /circular dialer-proxy dependency for "WG-(A|B)"/);
});

test('cycle through a provider with override.dialer-proxy is rejected; without override it is a dead end', () => {
  const provider = { type: 'http', url: 'https://example.invalid/sub', override: { 'dialer-proxy': 'WG-A' } };
  const proxies = [{ name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': Buffer.alloc(32, 1).toString('base64'), 'public-key': Buffer.alloc(32, 11).toString('base64'), ip: '10.66.1.2', 'dialer-proxy': 'P-GROUP' }];
  const groups = [{ name: 'P-GROUP', type: 'select', use: ['prov'] }];
  assert.throws(() => buildMihomoYaml(proxies, groups, { prov: provider }, [], [], opts), /circular dialer-proxy dependency for "WG-(A|B)"/);
  const safeProvider = { type: 'http', url: 'https://example.invalid/sub' };
  const yaml = buildMihomoYaml(proxies, groups, { prov: safeProvider }, ['MATCH,GLOBAL'], [], opts);
  assert.ok(yaml.includes('P-GROUP'));
});

test('plain configs without dialer edges are unaffected by the detector', () => {
  const yaml = build(['trojan://p@203.0.113.31:443#T31'], [WARP_CONF]);
  assert.ok(yaml.includes('type: wireguard'));
  assert.ok(!yaml.includes('dialer-proxy'));
});

// ---- analyzeDialerGraph: centralized dependency-graph API for the page validator ----

import { analyzeDialerGraph } from '../../src/core/yaml.js';

const b64 = (n) => Buffer.alloc(32, n).toString('base64');

test('analyzeDialerGraph: valid chains return no cycles', () => {
  const doc = {
    proxies: [
      { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': b64(2), 'public-key': b64(12), ip: '10.66.2.2' },
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'WG-B' },
    ],
    'proxy-groups': [],
    'proxy-providers': {},
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 0);
  assert.equal(res.dynamicGroups.length, 0);
});

test('analyzeDialerGraph: cycle routes are readable end-to-end', () => {
  const doc = {
    proxies: [
      { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': b64(2), 'public-key': b64(12), ip: '10.66.2.2', 'dialer-proxy': 'GROUP-B' },
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'GROUP-A' },
    ],
    'proxy-groups': [
      { name: 'GROUP-A', type: 'select', proxies: ['WG-B'] },
      { name: 'GROUP-B', type: 'select', proxies: ['WG-A'] },
    ],
    'proxy-providers': {},
  };
  const res = analyzeDialerGraph(doc);
  // Both WGs are dialer roots in this fixture: the API reports the cycle from
  // each start (same shape, two entry points) with the full readable route.
  assert.equal(res.cycles.length, 2);
  for (const c of res.cycles) {
    const route = c.route.join(' -> ');
    assert.ok(route.startsWith(c.start) && route.endsWith(c.start), 'route returns to start: ' + route);
    assert.ok(route.includes('GROUP-A') && route.includes('GROUP-B'), 'route names every hop: ' + route);
  }
});

test('analyzeDialerGraph: provider-backed groups are flagged dynamic (not silently safe)', () => {
  const doc = {
    proxies: [
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'P-GROUP' },
    ],
    'proxy-groups': [{ name: 'P-GROUP', type: 'select', use: ['prov'] }],
    'proxy-providers': { prov: { type: 'http', url: 'https://example.invalid/sub' } },
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 0, 'no static cycle provable');
  assert.deepEqual(res.dynamicGroups, ['P-GROUP'], 'dynamic dependency surfaced');
});

test('analyzeDialerGraph: provider override.dialer-proxy closes the loop and is reported', () => {
  const doc = {
    proxies: [
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'P-GROUP' },
    ],
    'proxy-groups': [{ name: 'P-GROUP', type: 'select', use: ['prov'] }],
    'proxy-providers': { prov: { type: 'http', url: 'https://example.invalid/sub', override: { 'dialer-proxy': 'WG-A' } } },
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 1);
  assert.ok(res.cycles[0].route.includes('WG-A'));
});

test('analyzeDialerGraph: WG-A -> static group -> TUIC is a valid composition', () => {
  const doc = {
    proxies: [
      { name: 'TUIC-1', type: 'tuic', server: '203.0.113.40', port: 443, uuid: '00000000-0000-4000-8000-0000000000e1', password: 'p' },
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'TRANSIT' },
    ],
    'proxy-groups': [{ name: 'TRANSIT', type: 'select', proxies: ['TUIC-1', 'DIRECT'] }],
    'proxy-providers': {},
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 0);
  assert.equal(res.dynamicGroups.length, 0);
});

test('buildFromRequest still fails closed when a manual graph cycles', () => {
  const proxies = [
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'WG-B' },
    { name: 'WG-B', type: 'wireguard', server: '192.0.2.72', port: 51820, 'private-key': b64(2), 'public-key': b64(12), ip: '10.66.2.2', 'dialer-proxy': 'WG-A' },
  ];
  assert.throws(() => buildFromRequest({ core: 'mihomo', input: '', wgBeans: [], options: opts }), /No valid links/);
  // cycle via buildMihomoYaml directly
  assert.throws(() => buildMihomoYaml(proxies, [], null, [], [], opts), /circular dialer-proxy dependency/);
});


test('mixed proxies+use group without cycle is valid (both edge categories walkable)', () => {
  const doc = {
    proxies: [
      { name: 'TUIC-1', type: 'tuic', server: '203.0.113.40', port: 443, uuid: '00000000-0000-4000-8000-0000000000e1', password: 'p' },
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'MIXED' },
    ],
    'proxy-groups': [{ name: 'MIXED', type: 'select', proxies: ['TUIC-1'], use: ['prov'] }],
    'proxy-providers': { prov: { type: 'http', url: 'https://example.invalid/sub' } },
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 0, 'no cycle through the static member');
  assert.deepEqual(res.dynamicGroups, ['MIXED']);
  assert.deepEqual(res.dynamicProviders, ['prov'], 'provider without override is dynamic/unknown');
});

test('cycle through the static member of a mixed group is rejected', () => {
  const doc = {
    proxies: [
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'MIXED' },
    ],
    'proxy-groups': [{ name: 'MIXED', type: 'select', proxies: ['WG-A'], use: ['prov'] }],
    'proxy-providers': { prov: { type: 'http', url: 'https://example.invalid/sub' } },
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 1, 'static-member edge of a mixed group participates');
});

test('cycle through the provider override of a mixed group is rejected', () => {
  const doc = {
    proxies: [
      { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'MIXED' },
    ],
    'proxy-groups': [{ name: 'MIXED', type: 'select', proxies: ['TUIC-1'], use: ['prov'] }],
    'proxy-providers': { prov: { type: 'http', url: 'https://example.invalid/sub', override: { 'dialer-proxy': 'WG-A' } } },
  };
  const res = analyzeDialerGraph(doc);
  assert.equal(res.cycles.length, 1, 'use:-edge of a mixed group participates');
  assert.ok(res.cycles[0].route.includes('WG-A') && res.cycles[0].route.includes('MIXED'));
});

test('build gate also rejects the mixed-group provider-override cycle', () => {
  const proxies = [
    { name: 'TUIC-1', type: 'tuic', server: '203.0.113.40', port: 443, uuid: '00000000-0000-4000-8000-0000000000e1', password: 'p' },
    { name: 'WG-A', type: 'wireguard', server: '192.0.2.73', port: 51820, 'private-key': b64(1), 'public-key': b64(11), ip: '10.66.1.2', 'dialer-proxy': 'MIXED' },
  ];
  const groups = [{ name: 'MIXED', type: 'select', proxies: ['TUIC-1'], use: ['prov'] }];
  const providers = { prov: { type: 'http', url: 'https://example.invalid/sub', override: { 'dialer-proxy': 'WG-A' } } };
  assert.throws(() => buildMihomoYaml(proxies, groups, providers, [], [], opts), /circular dialer-proxy dependency/);
});
