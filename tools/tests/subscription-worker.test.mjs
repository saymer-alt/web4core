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

test('redirect: upstream fetch uses manual mode so the limit governs the chain', async () => {
    const methods = [];
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    await callWorker(req, async (_target, init) => {
        methods.push(init && init.redirect);
        return new Response('final', { status: 200 });
    });
    assert.equal(methods[0], 'manual', 'upstream fetch в manual-режиме: лимит воркера управляет цепочкой');
});

test('redirect: one 302 hop then 200 succeeds', async () => {
    const calls = [];
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    const resp = await callWorker(req, async (target) => {
        calls.push(String(target));
        if (calls.length === 1) return new Response(null, { status: 302, headers: { Location: UPSTREAM + '?next' } });
        return new Response('after-hop', { status: 200 });
    });
    assert.equal(resp.status, 200);
    assert.equal(await resp.text(), 'after-hop');
    assert.equal(calls.length, 2);
    assert.equal(calls[1], UPSTREAM + '?next');
});

test('redirect: relative Location resolves against the current URL', async () => {
    const calls = [];
    const req = jsonRequest({ url: 'https://sub.example.test/dir/page', headers: {} });
    const resp = await callWorker(req, async (target) => {
        calls.push(String(target));
        if (calls.length === 1) return new Response(null, { status: 302, headers: { Location: '/next' } });
        return new Response('relative-ok', { status: 200 });
    });
    assert.equal(resp.status, 200);
    assert.equal(calls[1], 'https://sub.example.test/next');
});

test('redirect: exactly MAX_REDIRECTS hops still succeeds', async () => {
    const calls = [];
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    const resp = await callWorker(req, async (target) => {
        calls.push(String(target));
        if (calls.length <= 5) return new Response(null, { status: 302, headers: { Location: UPSTREAM + '?hop=' + calls.length } });
        return new Response('made-it', { status: 200 });
    });
    assert.equal(resp.status, 200);
    assert.equal(await resp.text(), 'made-it');
    assert.equal(calls.length, 6, 'initial fetch + 5 разрешённых redirect-хопов');
});

test('redirect: MAX_REDIRECTS + 1 → 508 Too many redirects', async () => {
    const calls = [];
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    const resp = await callWorker(req, async (target) => {
        calls.push(String(target));
        return new Response(null, { status: 302, headers: { Location: UPSTREAM + '?hop=' + calls.length } });
    });
    assert.equal(resp.status, 508);
    assert.equal(calls.length, 6, 'ровно MAX_REDIRECTS+1 fetch-ей, дальше не ходим');
    assert.equal(await resp.text(), 'Too many redirects');
});

test('redirect: non-http(s) Location rejected BEFORE fetching the forbidden scheme', async () => {
    const calls = [];
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    const resp = await callWorker(req, async (target) => {
        calls.push(String(target));
        if (calls.length === 1) return new Response(null, { status: 302, headers: { Location: 'file:///etc/passwd' } });
        return new Response('must-not-happen', { status: 200 });
    });
    assert.equal(resp.status, 502);
    assert.equal(await resp.text(), 'Redirect to a non-http(s) target rejected');
    assert.equal(calls.length, 1, 'запрещённая схема не fetch-ится');
    assert.ok(!calls.some(c => c.startsWith('file:')), 'нет fetch file://');
    const ftp = await callWorker(jsonRequest({ url: UPSTREAM, headers: {} }), async () => {
        return new Response(null, { status: 302, headers: { Location: 'ftp://sub.example.test/x' } });
    });
    assert.equal(ftp.status, 502);
    assert.ok(!(await ftp.text()).includes('sub.example.test'), 'нет URL-эха в ошибке');
});

test('redirect: self-referencing loop bounded with a finite fetch count', async () => {
    const req = jsonRequest({ url: UPSTREAM, headers: {} });
    let n = 0;
    const resp = await callWorker(req, async () => {
        n++;
        return new Response(null, { status: 302, headers: { Location: UPSTREAM } });
    });
    assert.equal(resp.status, 508);
    assert.ok(n <= 6, 'loop bounded: ' + n);
});

test('OPTIONS preflight answered without touching the upstream', async () => {
    const req = new Request('https://sub.web2core.workers.dev/', { method: 'OPTIONS' });
    const resp = await callWorker(req, async () => { throw new Error('upstream must not be called'); });
    assert.equal(resp.status, 204);
    assert.equal(resp.headers.get('Access-Control-Allow-Origin'), '*');
});
