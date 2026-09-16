// Side-effect import first: the shipped bundle relies on globalThis.parseUri,
// so these tests exercise the same parse path as production.
import '../../src/parseuri.min.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { validateBean } from '../../src/main.js';

const opt = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const portsOf = yaml => [...yaml.matchAll(/^\s*port: (.*)$/gm)].map(m => m[1]);
const build = link => buildFromRequest({ core: 'mihomo', input: link, options: opt }).data;
const VLESS = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.3';

for (const [label, link, expectation] of [
    ['socks missing port keeps the scheme default', 'socks://user:pass@192.0.2.1#A', { ports: ['1080'] }],
    ['vless missing port keeps the scheme default', `${VLESS}#A`, { ports: ['443'] }],
    ['vless empty port value keeps the scheme default', `${VLESS}:#A`, { ports: ['443'] }],
    ['valid lower boundary', `${VLESS}:1#A`, { ports: ['1'] }],
    ['valid upper boundary', `${VLESS}:65535#A`, { ports: ['65535'] }],
    ['valid explicit port is preserved', 'socks://user:pass@192.0.2.1:8080#A', { ports: ['8080'] }],
    ['port 0 is rejected', `${VLESS}:0#A`, { throws: 'vless: invalid port' }],
    ['negative port is rejected', 'socks://user:pass@192.0.2.1:-1#A', { throws: 'invalid port' }],
    ['port above 65535 is rejected (mihomo)', `${VLESS}:65536#A`, { throws: 'vless: invalid port 65536' }],
    ['port above 65535 is rejected (trojan)', 'trojan://pass@192.0.2.4:70000#A', { throws: 'trojan: invalid port' }],
    ['port above 65535 is rejected (hy2)', 'hy2://pass@192.0.2.6:99999#A', { throws: 'hy2: invalid port' }],
    ['port above 65535 is rejected (ss)', 'ss://YWVzLTEyOC1nY206dGVzdA@192.0.2.5:65536#A', { throws: 'invalid port' }],
    ['non-numeric port never becomes a default (mihomo)', 'socks://user:pass@192.0.2.1:abc#A', { throws: 'socks: invalid port "abc"' }],
    ['non-numeric port never becomes a default (tuic)', 'tuic://u:p@192.0.2.8:abc#A', { throws: 'tuic: invalid port' }],
    ['non-integer port is rejected', `${VLESS}:44.5#A`, { throws: 'invalid port' }],
]) test(`outbound port: ${label}`, () => {
    if (expectation.throws) {
        assert.throws(() => build(link), new RegExp(expectation.throws.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    } else {
        assert.deepEqual(portsOf(build(link)), expectation.ports);
    }
});

test('outbound port: malformed vmess JSON port is rejected, absent keeps the default', () => {
    const vmess = o => {
        const json = Buffer.from(JSON.stringify({
            v: '2', ps: 'VM', add: '192.0.2.7', id: '00000000-0000-4000-8000-000000000001',
            aid: '0', net: 'tcp', type: 'none', tls: '', ...o,
        })).toString('base64');
        return `vmess://${json}`;
    };
    assert.throws(() => build(vmess({ port: 65536 })), /vmess: invalid port/);
    assert.throws(() => build(vmess({ port: 'abc' })), /vmess: invalid port/);
    assert.deepEqual(portsOf(build(vmess({ port: 443 }))), ['443']);
    assert.deepEqual(portsOf(build(vmess({}))), ['443']);
});

test('outbound port: validation covers subscription extra links too', () => {
    assert.throws(
        () => buildFromRequest({
            core: 'mihomo',
            input: 'https://example.invalid/sub\nsocks://user:pass@192.0.2.1:65536#BAD',
            options: { ...opt, mihomoSubscriptionMode: true },
        }),
        /invalid port/,
    );
});

test('outbound port: validateBean gate (direct API)', () => {
    assert.throws(() => validateBean({ proto: 'socks', host: '192.0.2.1', port: 65536 }), /expected 1\.\.65535/);
    assert.throws(() => validateBean({ proto: 'socks', host: '192.0.2.1', port: '8080x' }), /invalid port/);
    assert.doesNotThrow(() => validateBean({ proto: 'socks', host: '192.0.2.1', port: 1080 }));
    // mieru keeps its separate port-range semantics
    const mieruBase = { proto: 'mieru', host: '192.0.2.9', port: 443, mieru: { username: 'u', password: 'p' } };
    assert.doesNotThrow(() => validateBean({ ...mieruBase, port: 0, mieru: { ...mieruBase.mieru, server_ports: '20000-30000' } }));
    assert.throws(() => validateBean({ ...mieruBase, port: 70000 }), /expected 1\.\.65535/);
});
