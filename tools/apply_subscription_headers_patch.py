from pathlib import Path

path = Path('src/core/subscription.js')
text = path.read_bytes()
nl = b'\r\n' if b'\r\n' in text else b'\n'

def b(s):
    return s.replace('\n', nl.decode()).encode()

old = b("""async function fetchSubscription(url) {
    if (typeof fetch !== 'function') throw new Error('Fetch API not available');

    const allowedSchemes = new Set(SUPPORTED_SCHEMES.filter(s => s !== 'http' && s !== 'https'));
    const splitLines = (text) => (text || '').split(/\\n/).map(s => s.trim()).filter(Boolean);
    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    const isBrowser = (typeof window !== 'undefined') && (typeof window.document !== 'undefined');
""")
new = b("""async function fetchSubscription(url, options = {}) {
    if (typeof fetch !== 'function') throw new Error('Fetch API not available');

    const allowedSchemes = new Set(SUPPORTED_SCHEMES.filter(s => s !== 'http' && s !== 'https'));
    const splitLines = (text) => (text || '').split(/\\n/).map(s => s.trim()).filter(Boolean);
    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    const isBrowser = (typeof window !== 'undefined') && (typeof window.document !== 'undefined');
    const allowedRequestHeaders = new Set(['x-hwid', 'x-device-model', 'x-device-os', 'x-ver-os']);
    const requestHeaders = {};
    if (options && options.headers && typeof options.headers === 'object') {
        for (const [rawName, rawValue] of Object.entries(options.headers)) {
            const name = String(rawName || '').trim().toLowerCase();
            if (!allowedRequestHeaders.has(name) || rawValue === undefined || rawValue === null) continue;
            const value = String(rawValue).trim();
            if (value) requestHeaders[name] = value;
        }
    }
""")
if old not in text:
    raise SystemExit('fetchSubscription anchor not found')
text = text.replace(old, new, 1)

old = b("""            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            if (!isBrowser) {
""")
new = b("""            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            for (const [name, value] of Object.entries(requestHeaders)) headers.set(name, value);
            if (!isBrowser) {
""")
if old not in text:
    raise SystemExit('request headers anchor not found')
text = text.replace(old, new, 1)
path.write_bytes(text)
print('source EOL:', 'CRLF' if nl == b'\r\n' else 'LF')
