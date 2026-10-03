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
        assert.equal(headerValue(init, 'x-device-os'), null, 'x-device-os is not in the allowlist');
        assert.equal(headerValue(init, 'x-ver-os'), null, 'x-ver-os is not in the allowlist');
        assert.equal(headerValue(init, 'authorization'), null);
        assert.equal(headerValue(init, 'cookie'), null);
        return new Response(GOOD, { status: 200 });
    }, async () => {
        const result = await fetchSubscription('https://example.test/sub', { headers: {
            'X-HWID': ' 0123456789abcdef0123456789abcdef ',
            'x-device-model': ' Saymer Link Generators Preview ',
            'x-device-os': 'Browser',
            'x-ver-os': 'web',
            'Authorization': 'must-not-leave-caller',
            'Cookie': 'session=must-not-leave-caller'
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

test('fallback POST contract forwards device identity in the JSON body, degrades to GET on legacy worker', async () => {
    const seen = [];
    await withFetch(async (url, init) => {
        seen.push({ url: String(url), init });
        if (seen.length === 1) throw new TypeError('Failed to fetch'); // direct CORS failure
        if (String(url).startsWith('https://sub.web2core.workers.dev/')) {
            const method = (init && init.method) || 'GET';
            if (method === 'POST') {
                if (seen.length === 2) {
                    // legacy worker deployment without the POST contract
                    return new Response('Add ?url=URL', { status: 400 });
                }
                const body = JSON.parse(init.body);
                assert.equal(body.url, 'https://example.test/sub');
                assert.deepEqual(body.headers, {
                    'x-hwid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'x-device-model': 'Saymer Link Generators Preview'
                });
                assert.equal(body.headers.authorization, undefined);
                assert.equal(body.headers['x-device-os'], undefined);
                return new Response(GOOD, { status: 200 });
            }
            return new Response(GOOD, { status: 200 });
        }
        return new Response('nope', { status: 404 });
    }, async () => {
        globalThis.window = { document: {} };
        const result = await fetchSubscription('https://example.test/sub', { headers: {
            'x-hwid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'x-device-model': 'Saymer Link Generators Preview',
            'Authorization': 'keep-me-internal'
        }});
        assert.equal(result, GOOD);
        const workerCalls = seen.filter(s => String(s.url).startsWith('https://sub.web2core.workers.dev/'));
        assert.equal(workerCalls.length, 2, 'POST once, then legacy GET degradation');
        assert.equal(workerCalls[0].init.method, 'POST');
        assert.equal(workerCalls[1].init.method, 'GET');
        // Legacy GET — CORS simple request: никаких device headers и никаких
        // не-simple заголовков (иначе браузер сделает preflight, который
        // легаси-воркер не отвечает).
        const getHeaders = new Headers(workerCalls[1].init.headers || {});
        assert.equal(getHeaders.get('x-hwid'), null, 'legacy GET без x-hwid');
        assert.equal(getHeaders.get('x-device-model'), null, 'legacy GET без x-device-model');
        assert.equal(getHeaders.get('content-type'), null, 'legacy GET без application/json');
        assert.equal(getHeaders.get('authorization'), null);
        // Identity уходит в POST body, а не в заголовки POST-запроса.
        const postHeaders = new Headers(workerCalls[0].init.headers || {});
        assert.equal(postHeaders.get('content-type'), 'application/json');
        assert.equal(postHeaders.get('x-hwid'), null, 'POST: identity в body, не в заголовках');
    });
});

test('legacy GET fallback URL stays the legacy contract (?url=encoded)', async () => {
    const seen = [];
    await withFetch(async (url, init) => {
        seen.push({ url: String(url), method: (init && init.method) || 'GET' });
        if (seen.length === 1) throw new TypeError('Failed to fetch');
        // legacy worker: только GET, POST не поддерживает
        if (seen[seen.length - 1].method === 'POST') return new Response('Add ?url=URL', { status: 400 });
        return new Response(GOOD, { status: 200 });
    }, async () => {
        globalThis.window = { document: {} };
        const result = await fetchSubscription('https://example.test/sub', { headers: { 'x-hwid': 'dddddddddddddddddddddddddddddddd' } });
        assert.equal(result, GOOD);
        const last = seen[seen.length - 1];
        assert.match(last.url, /^https:\/\/sub\.web2core\.workers\.dev\/\?url=https%3A%2F%2Fexample\.test%2Fsub$/);
        assert.equal(last.method, 'GET');
    });
});

test('POST fallback carries the same HWID across worker retries', async () => {
    const posts = [];
    let postCalls = 0;
    await withFetch(async (url, init) => {
        if (String(url).startsWith('https://sub.web2core.workers.dev/') && init.method === 'POST') {
            postCalls++;
            const body = JSON.parse(init.body);
            posts.push(body.headers['x-hwid']);
            if (postCalls === 1) return new Response('busy', { status: 503 });
            return new Response(GOOD, { status: 200 });
        }
        throw new TypeError('Failed to fetch');
    }, async () => {
        globalThis.window = { document: {} };
        const result = await fetchSubscription('https://example.test/sub', { headers: {
            'x-hwid': 'cccccccccccccccccccccccccccccccc',
            'x-device-model': 'Saymer Link Generators Preview'
        }});
        assert.equal(result, GOOD);
        assert.ok(posts.length >= 2, 'worker POST retried: ' + JSON.stringify(posts));
        assert.ok(posts.every(h => h === 'cccccccccccccccccccccccccccccccc'), 'same HWID on every fallback attempt');
    });
});
