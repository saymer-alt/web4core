import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchSubscription } from '../../src/core/subscription.js';

const GOOD = 'vless://00000000-0000-0000-0000-000000000001@example.com:443?encryption=none&type=tcp#Synthetic';

async function withFetch(mock, fn, { browser = false } = {}) {
    const prevFetch = globalThis.fetch;
    const prevWindow = globalThis.window;
    globalThis.fetch = mock;
    if (browser) globalThis.window = { document: {} };
    try { return await fn(); }
    finally {
        globalThis.fetch = prevFetch;
        if (prevWindow === undefined) delete globalThis.window;
        else globalThis.window = prevWindow;
    }
}

function hangingFetch(callLog, { responseDelayMs = 0 } = {}) {
    // Никогда не отвечает сам: резолвер через ответ звонящего, чтобы гонки
    // теста не зависели от реального таймаута 15s.
    return (url, init) => new Promise((resolve) => {
        callLog.push(url);
        if (init && init.signal) {
            init.signal.addEventListener('abort', () => resolve(new Response('', { status: 599 })), { once: true });
        }
    });
}

test('fetchSubscription without signal keeps legacy behavior', async () => {
    let calls = 0;
    await withFetch(async () => {
        calls += 1;
        return new Response(GOOD, { status: 200 });
    }, async () => {
        assert.equal(await fetchSubscription('https://example.test/sub'), GOOD);
    });
    assert.equal(calls, 1);
});

test('caller abort before the chain starts makes zero network calls', async () => {
    let calls = 0;
    const callsLog = [];
    const controller = new AbortController();
    controller.abort();
    await withFetch(hangingFetch(callsLog), async () => {
        await assert.rejects(
            fetchSubscription('https://example.test/sub', { headers: { 'x-hwid': 'a'.repeat(32) }, signal: controller.signal }),
            (e) => e.name === 'AbortError'
        );
    });
    assert.equal(callsLog.length, 0, 'no fetch attempt after pre-aborted signal');
});

test('abort during in-flight attempt stops the fallback chain', async () => {
    const callsLog = [];
    let attempts = 0;
    const controller = new AbortController();
    await withFetch((url, init) => new Promise((resolve) => {
        attempts += 1;
        callsLog.push(url);
        // Первый запрос висит; отмена приходит снаружи, после его старта.
        if (init && init.signal) {
            init.signal.addEventListener('abort', () => resolve(new Response('', { status: 599 })), { once: true });
        }
        if (attempts === 1) setTimeout(() => controller.abort(), 5);
    }), async () => {
        await assert.rejects(
            fetchSubscription('https://example.test/sub', { headers: { 'x-hwid': 'a'.repeat(32) }, signal: controller.signal }),
            (e) => e.name === 'AbortError'
        );
    }, { browser: true });
    // Одна начатая попытка (+ возможно прерванный in-flight) — но никакой
    // следующей стадии (POST/GET fallback × retries) быть не должно.
    assert.ok(callsLog.length <= 2, 'at most the already-started attempt, got ' + callsLog.length);
});

test('abort immediately after first attempt returns no further attempts', async () => {
    const callsLog = [];
    const controller = new AbortController();
    await withFetch(async (url) => {
        callsLog.push(url);
        controller.abort(); // прямой fetch завершился ошибкой → abort до fallback
        throw new TypeError('Failed to fetch');
    }, async () => {
        await assert.rejects(
            fetchSubscription('https://example.test/sub', { headers: { 'x-hwid': 'a'.repeat(32) }, signal: controller.signal }),
            (e) => e.name === 'AbortError'
        );
    }, { browser: true });
    assert.equal(callsLog.length, 1, 'fallback POST/GET must not run after caller abort');
});
