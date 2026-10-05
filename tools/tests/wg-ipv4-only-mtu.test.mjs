import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseWireGuardConf, normalizeWireGuardIpv4Only, computeAmneziaTagJunkSize, analyzeWireGuardProfile } from '../../src/core/wireguard.js';
import { buildMihomoProxy } from '../../src/core/mihomo.js';

const dualStackConf = [
  '[Interface]',
  'PrivateKey = CkGOZHbIxJvSSWWGFlHpNkGt0HhRIcKbmTIrmA9TcHk=',
  'Address = 172.16.0.2, 2606:4700:110:8c37:c80c:139e:17a3:5dbe',
  'DNS = 192.0.2.10, 2606:4700:4700::1111',
  'MTU = 1200',
  '',
  '[Peer]',
  'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
  'AllowedIPs = 0.0.0.0/0, ::/0',
  'Endpoint = engage.cloudflareclient.com:2408',
].join('\n');

test('parser stays faithful: raw dual-stack data preserved in bean', () => {
  const bean = parseWireGuardConf(dualStackConf, 'warp.conf');
  assert.equal(bean.wireguard.mtu, 1200);
  assert.equal(bean.wireguard.ipv6, '2606:4700:110:8c37:c80c:139e:17a3:5dbe');
  assert.deepEqual(bean.wireguard.allowedIPs, ['0.0.0.0/0', '::/0']);
  assert.deepEqual(bean.wireguard.addresses.length, 2);
});

test('IPv4-only normalization: mihomo proxy emits no IPv6 anywhere', () => {
  const bean = parseWireGuardConf(dualStackConf, 'warp.conf');
  const p = buildMihomoProxy(bean, new Set());
  assert.equal(p.ipv6, undefined, 'ipv6 interface address не эмитится');
  assert.equal(p.ip, '172.16.0.2', 'IPv4 address сохранён');
  assert.deepEqual(p['allowed-ips'], ['0.0.0.0/0'], 'IPv6 allowed-ips отфильтрованы');
  const dumped = JSON.stringify(p);
  assert.ok(!dumped.includes('2606:4700'), 'никаких IPv6-строк в proxy');
  assert.equal(p.mtu, 1200, 'imported MTU передаётся без изменений');
});

test('normalizeWireGuardIpv4Only: single-stack bean unchanged in allowed-ips', () => {
  const norm = normalizeWireGuardIpv4Only({ ip: '10.0.0.2', allowedIPs: ['10.8.0.0/24'], peers: [{ server: '1.2.3.4', port: 51820, allowedIPs: ['0.0.0.0/0'] }] });
  assert.deepEqual(norm.allowedIPs, ['10.8.0.0/24']);
  assert.equal(norm.ipv6Removed, false);
  assert.deepEqual(norm.peers[0].allowedIPs, ['0.0.0.0/0']);
});

test('peers with only IPv6 allowed-ips: entries filtered, peer retained', () => {
  const norm = normalizeWireGuardIpv4Only({
    ip: '10.0.0.2',
    allowedIPs: ['0.0.0.0/0', '::/0'],
    peers: [{ server: '1.2.3.4', port: 51820, publicKey: 'k', allowedIPs: ['::/0', '2001:db8::/32'] }],
  });
  assert.deepEqual(norm.allowedIPs, ['0.0.0.0/0']);
  assert.deepEqual(norm.peers[0].allowedIPs, []);
  assert.equal(norm.ipv6Removed, true);
  assert.equal(norm.ipv6RemovedCount, 3);
});

test('MTU diagnostics: imported MTU passthrough, never increased', () => {
  const bean = parseWireGuardConf(dualStackConf, 'warp.conf');
  const info = analyzeWireGuardProfile(bean);
  assert.equal(info.importedMtu, 1200);
  assert.equal(info.effectiveMtu, 1200);
  assert.equal(info.mtuSource, 'imported');
  assert.ok(info.effectiveMtu <= info.importedMtu);
  assert.equal(info.engineDefaultMtu, 1408);
  assert.equal(info.ipv6Removed, true);
});

test('MTU diagnostics: missing MTU reports engine default without emitting mtu', () => {
  const conf = dualStackConf.split('\n').filter(l => !l.startsWith('MTU')).join('\n');
  const bean = parseWireGuardConf(conf, 'warp.conf');
  assert.equal(bean.wireguard.mtu, undefined);
  const info = analyzeWireGuardProfile(bean);
  assert.equal(info.importedMtu, null);
  assert.equal(info.mtuSource, 'engine-default');
  const p = buildMihomoProxy(bean, new Set());
  assert.equal(p.mtu, undefined, 'mtu в YAML не выдумывается');
  assert.ok(info.notes.some(n => n.text.includes('1408')));
});

test('AWG classification: S4 per-transport, S1-S3 handshake-only, H1-H4 length-neutral', () => {
  const bean = parseWireGuardConf([
    '[Interface]',
    'PrivateKey = CkGOZHbIxJvSSWWGFlHpNkGt0HhRIcKbmTIrmA9TcHk=',
    'Address = 10.7.1.2/32',
    'S1 = 15',
    'S2 = 16',
    'S3 = 17',
    'S4 = 20',
    'H1 = 1',
    'H2 = 2',
    '[Peer]',
    'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
    'AllowedIPs = 0.0.0.0/0',
    'Endpoint = 198.51.100.10:51820',
  ].join('\n'), 'awg.conf');
  const info = analyzeWireGuardProfile(bean);
  assert.equal(info.awg.s4, 20);
  assert.ok(info.notes.some(n => n.text.includes('S4 = 20') && n.text.includes('transport')));
  assert.ok(info.notes.some(n => n.text.includes('S1/S2/S3') && n.text.includes('handshake')));
  assert.ok(info.notes.some(n => n.text.includes('H1/H2') && n.text.includes('длину')));
});

test('AWG I-tag size math: exact computable size', () => {
  // b: 4 hex-байта; rc 13; t: 8; r 54 -> 79
  const spec = '<b 0xaabbccdd><rc 13><t><r 54>';
  const calc = computeAmneziaTagJunkSize(spec);
  assert.equal(calc.unknown.length, 0);
  assert.equal(calc.size, 4 + 13 + 8 + 54);
  // wt/wr не добавляют байт; неизвестный тег помечается
  assert.equal(computeAmneziaTagJunkSize('<wt 5><wr>').size, 0);
  const bad = computeAmneziaTagJunkSize('<b 0xzz><q 1>');
  assert.equal(bad.unknown.length, 2);
});

test('AWG diagnostics: random-trailers warns about no config-derived bound; I-size warns over budget', () => {
  const bean = parseWireGuardConf([
    '[Interface]',
    'PrivateKey = CkGOZHbIxJvSSWWGFlHpNkGt0HhRIcKbmTIrmA9TcHk=',
    'Address = 10.7.1.2/32',
    'Jc = 5',
    'Jmin = 100',
    'Jmax = 1500',
    'RandomTrailers = 1', // on/off нормализует consumer до парсера; парсер принимает канонический 1/0
    'ContentPaddingAddition = 10-100',
    'I1 = <b 0xc0000000010c230665d2171a7f265a92f63b09ec4a5ac692c18401701a886b046018e6bb1b55fd78d1ffd677165ffa24265dac520ced1709847d4e><rc 13><t><r 54>',
    '[Peer]',
    'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
    'AllowedIPs = 0.0.0.0/0',
    'Endpoint = 198.51.100.10:51820',
  ].join('\n'), 'awg31.conf');
  const info = analyzeWireGuardProfile(bean);
  assert.equal(info.awg.randomTrailers, true);
  assert.ok(info.notes.some(n => n.level === 'warn' && n.text.includes('RandomTrailers')));
  assert.ok(info.notes.some(n => n.level === 'warn' && n.text.includes('Jmax = 1500')));
  assert.ok(info.notes.some(n => n.text.includes('ContentPaddingAddition = 10-100') && n.text.includes('100')));
  const i1 = info.awg.iSizes.find(x => x.key === 'I1');
  assert.equal(i1.size, 59 + 13 + 8 + 54); // b-блоб 118 hex = 59 B
});
