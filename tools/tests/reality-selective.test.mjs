import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

// Synthetic fixtures only: TEST-NET hosts, dummy keys.
const vless = (host, port, name, extra = '') =>
  `vless://00000000-0000-4000-8000-000000000001@${host}:${port}?encryption=none&security=reality&pbk=TESTPBK&sid=ab&fp=chrome#${name}`;
const R1 = vless('pan1.example', 443, 'R1');
const R2 = vless('pan1.example', 8443, 'R2');
const R3 = vless('pan2.example', 443, 'R3');
const R4FF = `vless://00000000-0000-4000-8000-000000000001@pan1.example:2053?encryption=none&security=reality&pbk=TESTPBK&sid=ab&fp=firefox#R4FF`;
const PLAIN = `vless://00000000-0000-4000-8000-000000000001@pan1.example:2053?encryption=none#PLAIN`;
const TLS = `vless://00000000-0000-4000-8000-000000000001@pan1.example:2054?security=tls&sni=example.com#TLS1`;
const SUBS = 'https://sub1.example/a\nhttps://sub2.example/b';

const opts = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const build = (input, modernHosts, extra = {}) => buildFromRequest({
  core: 'mihomo', input, options: { ...opts, ...extra, mihomoRealityModernHosts: modernHosts },
}).data;
const proxies = yaml => {
  const doc = yaml;
  void doc;
  return null;
};
const yamlProxies = yaml => {
  const unquote = s => { try { return JSON.parse(s); } catch { return s; } };
  const out = [];
  const lines = yaml.split('\n');
  let inProxies = false;
  for (const line of lines) {
    if (/^proxies:/.test(line)) { inProxies = true; continue; }
    if (inProxies) {
      const m = line.match(/^  - name: (.+)$/);
      if (m) out.push({ name: unquote(m[1]), block: [] });
      else if (out.length && /^    /.test(line)) out[out.length - 1].block.push(line.trim());
      else if (out.length && !/^ /.test(line)) break;
    }
  }
  return out;
};
const find = (yaml, name) => yamlProxies(yaml).find(p => p.name === name);
const hasFlag = p => p && p.block.includes('support-x25519mlkem768: true');
const fpOf = p => { const l = p && p.block.find(x => x.startsWith('client-fingerprint:')); return l ? l.split(': ')[1] : undefined; };

test('empty/absent list keeps legacy output byte-for-byte', () => {
  const input = [R1, R3, PLAIN].join('\n');
  const legacy = buildFromRequest({ core: 'mihomo', input, options: { ...opts } }).data;
  assert.equal(build(input, []), legacy);
  assert.equal(build(input, undefined), legacy);
  assert.doesNotMatch(legacy, /support-x25519mlkem768/);
});

test('one host entry modernizes only that host REALITY nodes', () => {
  const yaml = build([R1, R2, R3, PLAIN, TLS].join('\n'), [{ host: 'pan1.example' }]);
  assert.equal(hasFlag(find(yaml, 'R1')), true);
  assert.equal(hasFlag(find(yaml, 'R2')), true);
  assert.equal(fpOf(find(yaml, 'R1')), 'chrome');
  assert.equal(hasFlag(find(yaml, 'R3')), false); // other host stays legacy
  assert.equal(hasFlag(find(yaml, 'PLAIN')), false); // plain vless untouched
  const tls = find(yaml, 'TLS1');
  assert.equal(hasFlag(tls), false);
  assert.ok(!tls.block.some(l => l.startsWith('reality-opts')), 'no reality-opts invented for TLS node');
  assert.notEqual(fpOf(find(yaml, 'PLAIN')), 'chrome');
});

test('host:port entry modernizes only the exact inbound', () => {
  const yaml = build([R1, R2].join('\n'), [{ host: 'pan1.example', port: 443 }]);
  assert.equal(hasFlag(find(yaml, 'R1')), true);
  assert.equal(hasFlag(find(yaml, 'R2')), false);
});

test('multiple hosts and same-host-different-ports are independent', () => {
  const yaml = build([R1, R2, R3].join('\n'), [{ host: 'pan1.example', port: 8443 }, { host: 'pan2.example' }]);
  assert.equal(hasFlag(find(yaml, 'R1')), false);
  assert.equal(hasFlag(find(yaml, 'R2')), true);
  assert.equal(hasFlag(find(yaml, 'R3')), true);
});

test('explicit non-chrome fingerprint is preserved (flag still set)', () => {
  const yaml = build(R4FF, [{ host: 'pan1.example' }]);
  assert.equal(hasFlag(find(yaml, 'R4FF')), true);
  assert.equal(fpOf(find(yaml, 'R4FF')), 'firefox');
});

test('providers carry override-expr for every host entry with reality guard and chrome-if-absent', () => {
  const yaml = build(SUBS, [{ host: 'pan1.example' }, { host: 'pan2.example', port: 8443 }], { mihomoSubscriptionMode: true });
  const exprs = [...yaml.matchAll(/override-expr: .*/g)];
  void exprs;
  const providersSeen = (yaml.match(/override-expr/g) || []).length;
  assert.equal(providersSeen, 2); // оба provider'а
  assert.ok(yaml.includes(String.raw`select(has(\"reality-opts\"))`), 'reality guard');
  assert.ok(yaml.includes(String.raw`select(.port == 8443)`), 'port selector');
  assert.ok(yaml.includes(String.raw`.\"reality-opts\".\"support-x25519mlkem768\") = true`), 'mlkem assignment');
  assert.ok(yaml.includes(String.raw`select(.client-fingerprint == null) | .client-fingerprint) = \"chrome\"`), 'chrome-if-absent');
});

test('direct + provider together (Sub Mode mixed input)', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: SUBS + '\n' + R1,
    options: { ...opts, mihomoSubscriptionMode: true, mihomoRealityModernHosts: [{ host: 'pan1.example' }] },
  }).data;
  assert.equal(hasFlag(find(yaml, 'R1')), true);
  assert.ok(yaml.includes(String.raw`.\"reality-opts\".\"support-x25519mlkem768\") = true`), 'provider expr present');
});

test('invalid entries fail loudly; duplicates deduplicate', () => {
  assert.throws(() => build(R1, [{ port: 443 }]), /missing host/);
  assert.throws(() => build(R1, [{ host: 'x.example', port: 70000 }]), /port 70000/);
  assert.throws(() => build(R1, [42]), /Invalid modern REALITY host entry/);
  const yaml = build(R1, [{ host: 'pan1.example' }, { host: 'pan1.example' }, 'pan1.example:443']);
  // dedup: {host} and 'host:443' are different entries (port-qualified vs host-wide)
  const matches = yaml.match(/support-x25519mlkem768: true/g) || [];
  assert.equal(matches.length, 1); // флаг на узле один — дубликаты не ломают вывод
});

test('IPv6 bracket entries parse to host + port', () => {
  const v6 = `vless://00000000-0000-4000-8000-000000000001@[2001:db8::1]:443?encryption=none&security=reality&pbk=TESTPBK&sid=ab&fp=chrome#V6`;
  const yaml = build(v6, ['[2001:db8::1]:443']);
  assert.equal(hasFlag(find(yaml, 'V6')), true);
  const other = build(v6, ['[2001:db8::1]']);
  assert.equal(hasFlag(find(other, 'V6')), true); // host-only тоже матчится
  const otherPort = build(v6, [{ host: '2001:db8::1', port: 8443 }]);
  assert.equal(hasFlag(find(otherPort, 'V6')), false);
});
