// Endpoint contract: production CORS fallback указывает на owner-controlled
// worker (sub.saymer-87.workers.dev), а не на legacy инфраструктуру.
// Regression: случайная подмена endpoint ломает identity-контракт preview
// (legacy GET-only воркер не пересылает x-hwid/x-device-model).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

test('CORS fallback endpoint is the owner-controlled worker', async () => {
    const source = readFileSync(join(here, '../../src/main.js'), 'utf8');
    assert.match(source, /https:\/\/sub\.saymer-87\.workers\.dev\/\?url=/, 'PRIMARY fallback = sub.saymer-87.workers.dev');
    assert.doesNotMatch(source, /https:\/\/sub\.web2core\.workers\.dev/, 'legacy web2core endpoint не используется как production dependency');
});

test('runtime bundle carries the same endpoint', async () => {
    const source = readFileSync(join(here, '../../src/web4core.runtime.js'), 'utf8');
    assert.match(source, /sub\.saymer-87\.workers\.dev/, 'runtime содержит production endpoint');
    assert.doesNotMatch(source, /sub\.web2core\.workers\.dev/, 'runtime не содержит legacy endpoint');
});

test('browser fetchSubscription fallback goes to the owner-controlled worker with device identity in POST body', async () => {
    const { fetchSubscription } = await import('../../src/core/subscription.js');
    const GOOD = 'vless://00000000-0000-0000-0000-000000000001@example.com:443?encryption=none&type=tcp#Synthetic';
    const seen = [];
    const prevFetch = globalThis.fetch;
    const prevWindow = globalThis.window;
    globalThis.fetch = async (url, init) => {
        seen.push({ url: String(url), method: (init && init.method) || 'GET', body: init && init.body });
        if (seen.length === 1) throw new TypeError('Failed to fetch'); // CORS fail → fallback
        return new Response(GOOD, { status: 200 });
    };
    globalThis.window = { document: {} };
    try {
        const result = await fetchSubscription('https://example.test/sub', {
            headers: { 'x-hwid': 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'x-device-model': 'Saymer Link Generators Preview' }
        });
        assert.equal(result, GOOD);
        const fallback = seen[seen.length - 1];
        assert.match(fallback.url, /^https:\/\/sub\.saymer-87\.workers\.dev\//, 'fallback идёт на owner-controlled worker');
        assert.doesNotMatch(fallback.url, /web2core/, 'legacy endpoint не используется');
        assert.equal(fallback.method, 'POST', 'device-aware fallback = POST JSON контракт');
        const body = JSON.parse(fallback.body);
        assert.equal(body.headers['x-hwid'], 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
        assert.equal(body.headers['x-device-model'], 'Saymer Link Generators Preview');
    } finally {
        globalThis.fetch = prevFetch;
        delete globalThis.window;
    }
});
