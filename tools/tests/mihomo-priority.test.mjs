import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { buildMihomoPriorityConfig } from '../../src/core/mihomo.js';
import { buildBeansFromInput } from '../../src/main.js';

const a = 'socks://user:pass@192.0.2.1:1080#GLOBAL';
const b = 'socks://user:pass@192.0.2.2:1080#GLOBAL';
for (const [label, input, fallbackInput, sub] of [
    ['one each', a, b, false], ['several each', a + '\n' + b, a + '\n' + b, false],
    ['subscriptions', 'https://example.invalid/a', 'https://example.invalid/b', true],
    ['mixed', a + '\nhttps://example.invalid/a', b + '\nhttps://example.invalid/b', true],
    ['links with Sub Mode', a, b, true],
]) for (const stack of ['gvisor', 'mips']) {
    test(`${label}, ${stack}`, () => {
        const result = buildFromRequest({ core: 'mihomo', input, fallbackInput,
            options: { addTun: true, mihomoTunStack: stack, mihomoSubscriptionMode: sub } });
        assert.match(result.data, new RegExp('stack: ' + stack));
        assert.match(result.data, /name: GLOBAL\n\s+type: fallback/);
        assert.doesNotMatch(result.data, /name: (PRIMARY|FALLBACK)\n/);
        assert.match(result.data, /filter: "\^\(PRIMARY-\|primary-\)`\^\(FALLBACK-\|fallback-\)"/);
        assert.doesNotMatch(result.data, /listeners:|type: select|store-selected: false/);
        assert.match(result.data, /lazy: false/);
    });
}
test('independent names, membership, providers, no direct targets', () => {
    const side = { beans: buildBeansFromInput(a + '\n' + b), subUrls: ['https://example.invalid/a', 'https://example.invalid/b'] };
    const cfg = buildMihomoPriorityConfig(side, side, {});
    assert.equal(new Set(cfg.proxies.map(p => p.name)).size, 4);
    assert.equal(Object.keys(cfg.providers).length, 4);
    assert.equal(cfg.groups.length, 1);
    assert.deepEqual(cfg.groups[0].proxies, cfg.proxies.map(p => p.name));
    assert.deepEqual(cfg.groups[0].use, Object.keys(cfg.providers));
    assert.equal(cfg.groups[0].filter, '^(PRIMARY-|primary-)`^(FALLBACK-|fallback-)');
    assert.ok(cfg.groups.every(g => !g.proxies?.includes('DIRECT') && g['empty-fallback'] === 'REJECT' && g.lazy === false));
    assert.ok(Object.values(cfg.providers).every(p => p.override['additional-prefix'] && p['health-check'].lazy === false));
    for (const p of Object.values(cfg.providers)) {
        const hc = p['health-check'];
        assert.equal(hc.enable, true);
        assert.equal(hc.url, cfg.groups[0].url);
        assert.equal(hc.interval, 300);
        assert.equal(hc['expected-status'], cfg.groups[0]['expected-status']);
    }
});
test('reject incomplete/unsupported requests and per-proxy combinations', () => {
    const req = { core: 'mihomo', input: a, fallbackInput: b };
    for (const options of [{ mihomoPerProxyTun: true }, { perProxyPort: true }, { addTun: false, addSocks: false }]) {
        assert.throws(() => buildFromRequest({ ...req, options }));
    }
    for (const extra of [{ input: '' }, { fallbackInput: '' }, { fallbackInput: 'https://example.invalid/sub' }, { fallbackInput: 'socks4://192.0.2.2:1080' }]) {
        assert.throws(() => buildFromRequest({ ...req, ...extra }));
    }
    assert.doesNotMatch(buildFromRequest(req).data, /stack:|listeners:/);
});
