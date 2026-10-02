import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchSubscription } from '../../src/core/subscription.js';

const GOOD = 'vless://00000000-0000-0000-0000-000000000001@example.com:443?encryption=none&type=tcp#Synthetic';

function headerValue(init, name) {
    return new Headers(init && init.headers ? init.headers : {}).get(name);
}

async function withFetch(mock, fn) {
    const prevFetch = globalThis.fetch;
    const prevWindow = globalThis.window;
    globalThis.fetch = mock;
    try { return await fn(); }
    finally {
        globalThis.fetch = prevFetch;
        if (prevWindow === undefined) delete globalThis.window;
        else globalThis.window = prevWindow;
    }
}

test('fetchSubscription keeps legacy call free of device headers', async () => {
    await withFetch(async (_url, init) => {
        assert.equal(headerValue(init, 'x-hwid'), null);
        assert.equal(headerValue(init, 'x-device-model'), null);
        return new Response(GOOD, { status: 200 });
    }, async () => {
        assert.equal(await fetchSubscription('https://example.test/sub'), GOOD);
    });
});

test('fetchSubscription forwards only allowlisted device headers', async () => {
    await withFetch(async (_url, init) => {
        assert.equal(headerValue(init, 'x-hwid'), '0123456789abcdef0123456789abcdef');
        assert.equal(headerValue(init, 'x-device-model'), 'Saymer Link Generators Preview');
        assert.equal(headerValue(init, 'x-device-os'), 'Browser');
        assert.equal(headerValue(init, 'authorization'), null);
        return new Response(GOOD, { status: 200 });
    }, async () => {
        const result = await fetchSubscription('https://example.test/sub', { headers: {
            'X-HWID': ' 0123456789abcdef0123456789abcdef ',
            'x-device-model': ' Saymer Link Generators Preview ',
            'x-device-os': 'Browser',
            'Authorization': 'must-not-leave-caller'
        }});
        assert.equal(result, GOOD);
    });
});

test('browser retry keeps the same device identity', async () => {
    let calls = 0;
    await withFetch(async (_url, init) => {
        calls++;
        assert.equal(headerValue(init, 'x-hwid'), 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        if (calls === 1) return new Response('busy', { status: 503, statusText: 'Service Unavailable' });
        return new Response(GOOD, { status: 200 });
    }, async () => {
        globalThis.window = { document: {} };
        assert.equal(await fetchSubscription('https://example.test/sub', { headers: { 'x-hwid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } }), GOOD);
        assert.equal(calls, 2);
    });
});

test('browser fallback request carries the same allowlisted headers', async () => {
    const seen = [];
    await withFetch(async (url, init) => {
        seen.push({ url: String(url), hwid: headerValue(init, 'x-hwid'), model: headerValue(init, 'x-device-model') });
        if (seen.length === 1) throw new TypeError('Failed to fetch');
        return new Response(GOOD, { status: 200 });
    }, async () => {
        globalThis.window = { document: {} };
        const result = await fetchSubscription('https://example.test/sub', { headers: {
            'x-hwid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'x-device-model': 'Saymer Link Generators Preview'
        }});
        assert.equal(result, GOOD);
        assert(seen.length >= 2);
        assert.match(seen[1].url, /^https:\/\/sub\.web2core\.workers\.dev\//);
        assert.equal(seen[1].hwid, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
        assert.equal(seen[1].model, 'Saymer Link Generators Preview');
    });
});
