// sub.web2core.workers.dev worker contract: GET legacy + POST JSON device
// headers (allowlist), scheme guard, no-store, CORS preflight.
import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../../workers/subscription/index.js';

const UPSTREAM = 'https://sub.example.test/real-sub';

async function callWorker(request, upstreamMock) {
    const prevFetch = globalThis.fetch;
    globalThis.fetch = upstreamMock;
    try {
        return await worker.fetch(request);
    } finally {
        globalThis.fetch = prevFetch;
    }
}

function jsonRequest(body) {
    return new Request('https://sub.web2core.workers.dev/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

test('GET ?url= keeps the legacy fixed-headers contract', async () => {
    const req = new Request('https://sub.web2core.workers.dev/?url=' + encodeURIComponent(UPSTREAM));
    const resp = await callWorker(req, async (target, init) => {
        assert.equal(target, UPSTREAM);
        const h = new Headers(init.headers);
        assert.equal(h.get('x-hwid'), null, 'GET contract never forwards client device headers');
        assert.equal(init.method, 'GET');
        return new Response('legacy-body', { status: 200 });
    });
    assert.equal(resp.status, 200);
    assert.equal(await resp.text(), 'legacy-body');
    assert.equal(resp.headers.get('Cache-Control'), 'no-store');
    assert.equal(resp.headers.get('Access-Control-Allow-Origin'), '*');
});

test('POST JSON forwards only allowlisted device headers to the upstream', async () => {
    const req = jsonRequest({ url: UPSTREAM, headers: {
        'x-hwid': '0123456789abcdef0123456789abcdef',
        'X-Device-Model': 'Saymer Link Generators Preview',
        'Authorization': 'Bearer must-not-forward',
        'Cookie': 'session=must-not-forward',
        'x-custom': 'must-not-forward'
    }});
    const resp = await callWorker(req, async (target, init) => {
        const h = new Headers(init.headers);
        assert.equal(h.get('x-hwid'), '0123456789abcdef0123456789abcdef');
        assert.equal(h.get('x-device-model'), 'Saymer Link Generators Preview');
        assert.equal(h.get('authorization'), null);
        assert.equal(h.get('cookie'), null);
        assert.equal(h.get('x-custom'), null);
        return new Response('device-body', { status: 200 });
    });
    assert.equal(resp.status, 200);
    assert.equal(await resp.text(), 'device-body');
});

test('POST rejects non-http(s) targets and invalid JSON', async () => {
    const bad = await callWorker(jsonRequest({ url: 'file:///etc/passwd', headers: {} }), async () => new Response('x'));
    assert.equal(bad.status, 400);
    const missing = new Request('https://sub.web2core.workers.dev/', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{ not json'
    });
    const badJson = await callWorker(missing, async () => new Response('x'));
    assert.equal(badJson.status, 400);
    const empty = await callWorker(jsonRequest({ headers: {} }), async () => new Response('x'));
    assert.equal(empty.status, 400);
});

test('worker caps redirects and surfaces upstream failure without URL echo', async () => {
    let hops = 0;
    const req = jsonRequest({ url: UPSTREAM, headers: { 'x-hwid': 'aaaa' } });
    const resp = await callWorker(req, async (_target, _init) => {
        hops++;
        return new Response(null, { status: 302, headers: { Location: UPSTREAM + '?hop=' + hops } });
    });
    assert.equal(resp.status, 508);
    assert.ok(hops <= 6, 'redirect loop bounded: ' + hops);
    const body = await resp.text();
    assert.ok(!body.includes('sub.example.test'), 'no URL echo in error body');
    const fail = await callWorker(jsonRequest({ url: UPSTREAM, headers: {} }), async () => { throw new TypeError('boom'); });
    assert.equal(fail.status, 502);
    assert.equal(await fail.text(), 'Upstream fetch failed');
});

test('OPTIONS preflight answered without touching the upstream', async () => {
    const req = new Request('https://sub.web2core.workers.dev/', { method: 'OPTIONS' });
    const resp = await callWorker(req, async () => { throw new Error('upstream must not be called'); });
    assert.equal(resp.status, 204);
    assert.equal(resp.headers.get('Access-Control-Allow-Origin'), '*');
});
