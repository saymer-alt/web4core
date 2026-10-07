import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { fetchSubscription } from '../../src/core/subscription.js';

const urls = ['https://example.com/one', 'https://example.org/two'];
const HWID_RE = /^[A-Za-z0-9=-]{10,64}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;

function providerHwids(yaml) {
    return [...yaml.matchAll(/^\s+x-hwid:\s*\n\s+- ([A-Za-z0-9=-]+)$/gm)].map(m => m[1]);
}

test('deviceHwid: one logical device -> every provider carries the same x-hwid', () => {
    const result = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options: { mihomoSubscriptionMode: true, deviceHwid: 'a'.repeat(32) } });
    assert.equal(result.kind, 'yaml');
    const hwids = providerHwids(result.data);
    assert.equal(hwids.length, 2);
    assert.deepEqual(hwids, ['a'.repeat(32), 'a'.repeat(32)]);
});

test('deviceHwid: rebuild of the same logical device keeps identity byte-identical', () => {
    const options = { mihomoSubscriptionMode: true, deviceHwid: 'b'.repeat(32) };
    const first = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options }).data;
    const second = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options }).data;
    assert.deepEqual(providerHwids(first), providerHwids(second));
    assert.equal(first, second);
});

test('invalid deviceHwid never reaches the YAML: fresh random identity instead', () => {
    for (const bad of ['', '   ', 'short', 'bad hwid with spaces', 'x'.repeat(65), null, undefined, 12345]) {
        const result = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options: { mihomoSubscriptionMode: true, deviceHwid: bad } });
        const hwids = providerHwids(result.data);
        assert.equal(hwids.length, 2);
        for (const hwid of hwids) {
            assert.ok(HEX32_RE.test(hwid), 'fallback identity must stay 32-hex, got: ' + JSON.stringify(hwid));
            assert.notEqual(hwid, String(bad ?? ''));
        }
    }
});

test('without deviceHwid the legacy behavior is preserved (random 32-hex per provider)', () => {
    const result = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options: { mihomoSubscriptionMode: true, deviceModel: 'Home-Router' } });
    const hwids = providerHwids(result.data);
    assert.equal(hwids.length, 2);
    for (const hwid of hwids) assert.ok(HEX32_RE.test(hwid));
    assert.ok(result.data.includes('x-device-model:'));
});

test('deviceHwid is forwarded through the priority (primary/fallback) path too', () => {
    const primary = urls.join('\n');
    const fallback = 'https://example.net/three';
    const result = buildFromRequest({ core: 'mihomo', input: primary, fallbackInput: fallback, options: { mihomoSubscriptionMode: true, deviceHwid: 'c'.repeat(32) } });
    const hwids = providerHwids(result.data);
    assert.ok(hwids.length >= 3, 'primary + fallback providers expected');
    assert.deepEqual(hwids, hwids.map(() => 'c'.repeat(32)));
});

test('non-browser fetch failure keeps the plain direct-error classification (no Fallback stage)', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = () => Promise.reject(new Error('NetworkError when attempting to fetch.'));
    try {
        await assert.rejects(
            () => fetchSubscription('https://example.com/sub'),
            (err) => err.message === 'Network error, check connection'
        );
    } finally {
        globalThis.fetch = originalFetch;
    }
});
