// sub.web2core.workers.dev — CORS fallback for subscription preview fetch.
//
// Two request forms:
//  1. GET  /?url=<encoded-url>            — legacy contract, fixed fetch headers
//                                           (no client headers are forwarded).
//  2. POST /  { "url": "...", "headers": {...} }
//     Body JSON; only an allowlist of device-identity headers is forwarded to
//     the upstream (x-hwid, x-device-model). Anything else in `headers` is
//     dropped. Subscription URLs and forwarded values are never logged.
//
// Response: upstream body as text/plain with `Access-Control-Allow-Origin: *`
// and `Cache-Control: no-store`. Upstream fetch is bounded by timeout,
// response-size cap and http(s)-only scheme check.

const ALLOWED_HEADERS = new Set(["x-hwid", "x-device-model"]);
const MAX_REDIRECTS = 5;
const UPSTREAM_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400"
};

function textResponse(body, status) {
    return new Response(body, {
        status,
        headers: { "Content-Type": "text/plain; charset=utf-8", ...CORS_HEADERS, "Cache-Control": "no-store" }
    });
}

function collectForwardHeaders(rawHeaders) {
    const out = {};
    if (!rawHeaders || typeof rawHeaders !== "object" || Array.isArray(rawHeaders)) return out;
    for (const [rawName, rawValue] of Object.entries(rawHeaders)) {
        const name = String(rawName || "").trim().toLowerCase();
        const value = String(rawValue ?? "").trim();
        if (!ALLOWED_HEADERS.has(name) || !value) continue;
        // header value sanity: no CR/LF (header injection), bounded length
        if (/[\r\n]/.test(value) || value.length > 256) continue;
        out[name] = value;
    }
    return out;
}

async function fetchUpstream(target, forwardHeaders, deadline) {
    // redirect: "manual" — HTTP redirect chain ограничивается resolveUpstream
    // (MAX_REDIRECTS + повторная http(s)-валидация каждого хопа);
    // "follow" обошёл бы лимит внутри самого fetch.
    // deadline — общий AbortSignal на всю цепочку (не per-hop).
    const opts = {
        method: "GET",
        redirect: "manual",
        headers: forwardHeaders && Object.keys(forwardHeaders).length
            ? {
                "User-Agent": "curl/8.7.1",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                ...forwardHeaders
            }
            : {
                "User-Agent": "curl/8.7.1",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close"
            },
        signal: deadline
    };
    const response = await fetch(target, opts);
    // Bound the response size: read at most MAX_RESPONSE_BYTES, then stop.
    if (!response.ok || !response.body) {
        return new Response(null, { status: response.status, headers: response.headers });
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
            try { await reader.cancel(); } catch (_) {}
            return textResponse("Upstream response too large", 502);
        }
        chunks.push(value);
    }
    return new Response(concatChunks(chunks), { status: response.status, headers: response.headers });
}

function concatChunks(chunks) {
    const total = chunks.reduce((n, c) => n + c.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
    return out;
}

function isRedirect(status) {
    return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

async function resolveUpstream(target, forwardHeaders) {
    // Ручной redirect-chain: каждый хоп валидируется заново (http/https only,
    // относительный Location разрешается от текущего URL), лимит hops —
    // MAX_REDIRECTS, ошибки — generic, без эха полного target URL.
    // Один общий bounded deadline на всю цепочку (не per-hop): redirects
    // расходуют оставшийся бюджет, общий worst case = UPSTREAM_TIMEOUT_MS.
    const deadline = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
    let current = target;
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
        const response = await fetchUpstream(current, forwardHeaders, deadline);
        if (isRedirect(response.status)) {
            const location = response.headers.get("Location");
            if (!location) return textResponse("Upstream redirect without Location", 502);
            let next;
            try {
                next = new URL(location, current);
            } catch (_) {
                return textResponse("Invalid redirect target", 502);
            }
            if (next.protocol !== "http:" && next.protocol !== "https:") {
                // Перенаправление в запрещённую схему — не fetch-им её вообще.
                return textResponse("Redirect to a non-http(s) target rejected", 502);
            }
            current = next.toString();
            continue;
        }
        return response;
    }
    return textResponse("Too many redirects", 508);
}

export default {
    async fetch(request) {
        if (request.method === "OPTIONS") {
            return new Response(null, { status: 204, headers: CORS_HEADERS });
        }

        let target = "";
        let forwardHeaders = null;
        if (request.method === "POST") {
            let payload = null;
            try {
                payload = await request.json();
            } catch (_) {
                return textResponse("Invalid JSON body", 400);
            }
            if (!payload || typeof payload !== "object") return textResponse("Invalid JSON body", 400);
            target = String(payload.url || "").trim();
            forwardHeaders = collectForwardHeaders(payload.headers);
        } else if (request.method === "GET") {
            const url = new URL(request.url);
            target = (url.searchParams.get("url") || "").trim();
        } else {
            return textResponse("Method not allowed", 405);
        }

        if (!target) return textResponse("Add ?url=URL", 400);
        let parsed;
        try {
            parsed = new URL(target);
        } catch (_) {
            return textResponse("Invalid url", 400);
        }
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            return textResponse("Only http(s) urls are supported", 400);
        }

        let response;
        try {
            response = await resolveUpstream(parsed.toString(), forwardHeaders);
        } catch (_) {
            return textResponse("Upstream fetch failed", 502);
        }

        return new Response(response.body || null, {
            status: response.status,
            headers: {
                "Content-Type": "text/plain; charset=utf-8",
                ...CORS_HEADERS,
                "Cache-Control": "no-store"
            }
        });
    }
};
