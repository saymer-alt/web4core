from pathlib import Path
import subprocess

base = subprocess.check_output(['git', 'show', 'origin/link-generators:src/core/subscription.js'])
nl = b'\r\n' if b'\r\n' in base else b'\n'

def block(s: str) -> bytes:
    return s.replace('\n', nl.decode()).encode()

text = base
old = block("""async function fetchSubscription(url) {
    if (typeof fetch !== 'function') throw new Error('Fetch API not available');

    const allowedSchemes = new Set(SUPPORTED_SCHEMES.filter(s => s !== 'http' && s !== 'https'));
    const splitLines = (text) => (text || '').split(/\\n/).map(s => s.trim()).filter(Boolean);
    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    const isBrowser = (typeof window !== 'undefined') && (typeof window.document !== 'undefined');
""")
new = block("""async function fetchSubscription(url, options = {}) {
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
    raise SystemExit('signature anchor missing from base source')
text = text.replace(old, new, 1)

old = block("""            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            if (!isBrowser) {
""")
new = block("""            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            for (const [name, value] of Object.entries(requestHeaders)) headers.set(name, value);
            if (!isBrowser) {
""")
if old not in text:
    raise SystemExit('request header anchor missing from base source')
text = text.replace(old, new, 1)

Path('src/core/subscription.js').write_bytes(text)
print('base EOL:', 'CRLF' if nl == b'\r\n' else 'LF', 'bytes:', len(text))
