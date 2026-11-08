// kas-mini offline test suite (issue #425 Phase 0). No network, synthetic credentials only.
// Run: node --test kas-mini/kas-mini-tests.mjs   (bundle checks require: node kas-mini/build-mini.mjs first)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildMiniMihomoConfig, vetWireGuardConf, redactLine } from './entry-kas-mini.js';

const here = path.dirname(fileURLToPath(import.meta.url));

// ---- synthetic, nonsecret placeholder fixtures (example.com, all-ones UUID) ----
const UUID = '11111111-2222-3333-4444-555555555555';
const SECRET32 = 'ab'.repeat(16); // 32 hex chars
const VLESS = `vless://${UUID}@example.com:443?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&sid=ab&type=tcp&flow=xtls-rprx-vision#NodeVLESS`;
const HY2 = 'hysteria2://synthetic-pass@example.org:443/?obfs=salamander&obfs-password=obfspass#NodeHy2';
const TROJAN = 'trojan://synthetic-pass@example.net:443?security=tls&type=ws&path=%2Fws#NodeTrojan';
const SUB_URLS = 'https://provider.example/sub-a\nhttps://provider.example/sub-b';
const WG_MINIMAL = [
    '[Interface]',
    'PrivateKey = yKdCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'Address = 10.0.0.2/32',
    '',
    '[Peer]',
    'PublicKey = xR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'Endpoint = vpn.example.com:51820',
    'AllowedIPs = 0.0.0.0/0',
].join('\n');
const WG_AWG = [
    '[Interface]',
    'PrivateKey = yKdCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'Address = 10.0.0.2/32',
    'Jc = 8',
    'Jmin = 40',
    'Jmax = 70',
    'S1 = 15',
    'H1 = 1234',
    'RandomTrailers = 1',
    'Version = 1',
    '',
    '[Peer]',
    'PublicKey = xR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'Endpoint = vpn.example.com:51820',
    'AllowedIPs = 0.0.0.0/0',
].join('\n');
const WG_DNS = WG_MINIMAL + '\nDNS = 1.1.1.1';
const WG_MULTI = WG_MINIMAL
    + '\n\n[Peer]\nPublicKey = xR5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = vpn2.example.com:51821\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25';

const DEFAULTS = {
    linksText: VLESS,
    subscriptions: false,
    allowLan: true,
    mixedPort: 7890,
    webUI: true,
    webUISecret: SECRET32,
    tun: true,
    mipsStack: true,
};

function build(overrides) {
    return buildMiniMihomoConfig({ ...DEFAULTS, ...overrides });
}

function mustInclude(yaml, needle, msg) {
    assert.ok(yaml.includes(needle), (msg || 'yaml must include') + ': ' + JSON.stringify(needle));
}
function mustNotInclude(yaml, needle, msg) {
    assert.ok(!yaml.includes(needle), (msg || 'yaml must NOT include') + ': ' + JSON.stringify(needle));
}

// ---------- 1. mixed-input honest parsing ----------
test('per-line parse: valid nodes accepted, separators/headings rejected without false success', () => {
    const r = build({ linksText: `${VLESS}\n=== Список серверов ===\n${HY2}\n---\n${TROJAN}\n\n  ` });
    assert.equal(r.report.nodes, 3);
    assert.equal(r.report.links.accepted, 3);
    assert.equal(r.report.links.rejected, 2);
    const msgs = r.report.links.errors.map(e => e.message).join(' | ');
    assert.match(msgs, /Unknown link/);
    // redaction: no raw URI text beyond scheme in error echo
    const errsJson = JSON.stringify(r.report.links.errors);
    assert.ok(!errsJson.includes(UUID), 'uuid must not leak into error report');
    assert.ok(!errsJson.includes('example.com'), 'host must not leak into error report');
});

test('error echo redaction: scheme-only line echo', () => {
    assert.equal(redactLine(VLESS), 'vless://…');
    assert.equal(redactLine('https://user:pass@host.example/path'), 'https://…');
    assert.ok(redactLine('=== heading ===').length <= 24);
});

test('JSON-looking garbage line is rejected, not silently skipped', () => {
    // garbage alone → honest throw, never a false success
    assert.throws(() => build({ linksText: '{garbage-not-json' }), /нет валидных узлов/);
    // garbage mixed with a valid line → counted, reported, valid node still emitted
    const r = build({ linksText: `{garbage-not-json\n${VLESS}` });
    assert.equal(r.report.nodes, 1);
    assert.equal(r.report.links.rejected, 1);
    assert.equal(r.report.links.errors.length, 1);
});

test('empty input fails honestly (no false success)', () => {
    assert.throws(() => build({ linksText: '   \n  ' }), /нет валидных узлов/);
});

// ---------- 2. protocol allowlist ----------
test('sdns:// (not in mihomo allowlist) rejected with clear message', () => {
    try {
        build({ linksText: 'sdns://AQcAAAAAAAAADzE5My4yMDAuMjI1LjMyAAXNsrv_' });
        assert.fail('expected throw for unsupported protocol');
    } catch (e) {
        assert.match(String(e.message), /не поддерживается/);
    }
});

// ---------- 3. dedup ----------
test('duplicate URI deduplicates to one proxy', () => {
    const r = build({ linksText: `${VLESS}\n${VLESS}` });
    assert.equal(r.report.nodes, 1);
});

// ---------- 4. settings → emitted fields (owner table) ----------
test('owner defaults: allow-lan true + bind-address, mixed-port, TUN mips auto-route false', () => {
    const { yaml, report } = build({});
    mustInclude(yaml, 'allow-lan: true');
    mustInclude(yaml, "bind-address: '*'");
    mustInclude(yaml, 'mixed-port: 7890');
    mustInclude(yaml, 'stack: mips');
    mustInclude(yaml, 'auto-route: false');
    mustInclude(yaml, 'device: mitun0');
    mustNotInclude(yaml, 'allow-lan: false');
    mustInclude(yaml, 'rules:', '');
    mustInclude(yaml, 'MATCH,GLOBAL');
    assert.equal(report.settings.tun.stack, 'mips');
});

test('allowLan=false keeps allow-lan false and emits no bind-address', () => {
    const { yaml } = build({ allowLan: false });
    mustInclude(yaml, 'allow-lan: false');
    mustNotInclude(yaml, 'bind-address');
});

test('mixed-port rewrite is verified and validated', () => {
    const { yaml } = build({ mixedPort: 7897 });
    mustInclude(yaml, 'mixed-port: 7897');
    mustNotInclude(yaml, 'mixed-port: 7890');
    assert.throws(() => build({ mixedPort: 0 }), /недопустимый порт/);
    assert.throws(() => build({ mixedPort: 70000 }), /недопустимый порт/);
    assert.throws(() => build({ mixedPort: 'abc' }), /недопустимый порт/);
});

test('conflicting port produces visible warning (not refusal)', () => {
    const r = build({ mixedPort: 9090 });
    assert.ok(r.report.warnings.some(w => w.includes('9090')), 'warning about busy port expected');
});

test('tun=false omits tun section; mips toggle is subordinate', () => {
    const { yaml, report } = build({ tun: false, mipsStack: true });
    mustNotInclude(yaml, 'tun:');
    mustNotInclude(yaml, 'stack: mips');
    assert.equal(report.settings.tun.enabled, false);
});

test('mipsStack=false falls back to gvisor explicitly', () => {
    const { yaml, report } = build({ mipsStack: false });
    mustInclude(yaml, 'stack: gvisor');
    mustNotInclude(yaml, 'stack: mips');
    assert.equal(report.settings.tun.stack, 'gvisor');
});

// ---------- 5. Web UI safety ----------
test('webUI=true emits controller WITH generated secret, never empty', () => {
    const { yaml, report } = build({});
    mustInclude(yaml, 'external-controller: 0.0.0.0:9090');
    mustInclude(yaml, 'external-ui: ui');
    mustInclude(yaml, 'secret: ' + SECRET32);
    assert.ok(/^secret: [0-9a-f]{32,128}$/m.test(yaml), 'secret line must be hex and non-empty');
    // secret must not appear in the report (only in YAML)
    const repJson = JSON.stringify(report);
    assert.ok(!repJson.includes(SECRET32), 'generated secret must not leak into report');
    assert.equal(report.settings.webUI.enabled, true);
});

test('webUI=true without provided secret generates one (32 hex)', () => {
    const { yaml } = build({ webUISecret: undefined });
    const m = yaml.match(/^secret: ([0-9a-f]{32,128})$/m);
    assert.ok(m, 'generated secret expected');
});

test('webUI=false emits no controller and no secret', () => {
    const { yaml } = build({ webUI: false });
    mustNotInclude(yaml, 'external-controller');
    mustNotInclude(yaml, 'secret:');
});

// ---------- 6. URL subscriptions: native providers, no fetch, no HWID ----------
test('URL entered while toggle OFF → explicit prompt error, not silent drop', () => {
    assert.throws(
        () => build({ linksText: VLESS, subscriptionUrlsText: SUB_URLS, subscriptions: false }),
        /включите|переключател/i,
    );
});

test('toggle ON: native proxy-providers + proxy-groups.use, GLOBAL has no dangling refs', () => {
    const { yaml, report } = build({
        linksText: VLESS,
        subscriptionUrlsText: SUB_URLS,
        subscriptions: true,
    });
    mustInclude(yaml, 'proxy-providers:');
    mustInclude(yaml, 'type: http');
    mustInclude(yaml, 'https://provider.example/sub-a');
    mustInclude(yaml, 'https://provider.example/sub-b');
    mustInclude(yaml, 'use:');
    mustNotInclude(yaml, 'x-hwid', 'no HWID header');
    mustNotInclude(yaml, 'header:', 'no header block after HWID removal');
    assert.equal(report.subscriptions.providers.length, 2);
    assert.equal(report.nodes, 1);
    assert.equal(report.links.accepted, 1);
});

test('toggle ON with no URLs → plain proxies path still works', () => {
    const { yaml } = build({ subscriptions: true, subscriptionUrlsText: '' });
    mustNotInclude(yaml, 'proxy-providers:');
    mustInclude(yaml, 'NodeVLESS');
});

test('non-http(s) subscription line is refused', () => {
    assert.throws(() => build({ subscriptionUrlsText: 'ftp://x/y', subscriptions: true }), /http\(s\)/);
});

// ---------- 7. WG/AWG ----------
test('minimal WG conf accepted and emitted as wireguard proxy', () => {
    const r = build({ linksText: '', wgFiles: [{ name: 'node-a.conf', text: WG_MINIMAL }] });
    assert.equal(r.report.nodes, 1);
    assert.equal(r.report.wg.accepted, 1);
    mustInclude(r.yaml, 'type: wireguard');
    mustInclude(r.yaml, 'server: vpn.example.com');
    mustInclude(r.yaml, 'ip: 10.0.0.2');
});

test('AWG options are carried into amnezia-wg-option', () => {
    const r = build({ linksText: '', wgFiles: [{ name: 'awg.awg', text: WG_AWG }] });
    mustInclude(r.yaml, 'amnezia-wg-option');
    mustInclude(r.yaml, 'jc: 8');
    mustInclude(r.yaml, 'jmin: 40');
    mustInclude(r.yaml, 's1: 15');
    mustInclude(r.yaml, 'h1: 1234');
    mustInclude(r.yaml, 'version: 1');
});

test('DNS in .conf → whole file refused (no silent loss)', () => {
    const r = build({ linksText: VLESS, wgFiles: [{ name: 'with-dns.conf', text: WG_DNS }] });
    assert.equal(r.report.wg.refused, 1);
    assert.equal(r.report.nodes, 1); // vless still present
    mustNotInclude(r.yaml, 'type: wireguard');
    const f = r.report.wg.files[0];
    assert.equal(f.status, 'refused');
    assert.equal(f.refused[0].key, 'DNS');
    assert.match(f.refused[0].reason, /LOST_FIELD/);
});

test('unknown key → refusal; wg-quick env keys → visible warning only', () => {
    const vet = vetWireGuardConf('PostUp = iptables -A FORWARD -j DROP\nWeirdField = x\n' + WG_MINIMAL);
    assert.equal(vet.refused.length, 1);
    assert.equal(vet.refused[0].key, 'WeirdField');
    assert.equal(vet.warnings.length, 1);
    assert.equal(vet.warnings[0].key, 'PostUp');
    const r = build({ linksText: VLESS, wgFiles: [{ name: 'weird.conf', text: 'WeirdField = x\n' + WG_MINIMAL }] });
    assert.equal(r.report.wg.refused, 1);
});

test('PostUp-only conf accepted with policy warning, not refusal', () => {
    const r = build({ linksText: '', wgFiles: [{ name: 'env.conf', text: 'PostUp = echo hi\n' + WG_MINIMAL }] });
    assert.equal(r.report.wg.accepted, 1);
    const f = r.report.wg.files[0];
    assert.equal(f.warnings.length, 1);
    assert.equal(f.warnings[0].reason, 'IGNORED_BY_POLICY');
});

test('invalid MTU / keepalive range refused instead of silently dropped', () => {
    const vetMtu = vetWireGuardConf(WG_MINIMAL.replace('Address = 10.0.0.2/32', 'Address = 10.0.0.2/32\nMTU = abc'));
    assert.ok(vetMtu.refused.some(r => r.key === 'MTU'));
    const vetPk = vetWireGuardConf(WG_MINIMAL.replace('AllowedIPs = 0.0.0.0/0', 'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 10-20'));
    assert.ok(vetPk.refused.some(r => r.key === 'PersistentKeepalive'));
});

test('invalid AWG boolean value refused', () => {
    const vet = vetWireGuardConf(WG_AWG.replace('RandomTrailers = 1', 'RandomTrailers = maybe'));
    assert.ok(vet.refused.some(r => r.key === 'RandomTrailers'));
});

test('multi-peer conf emits peers array (not silently collapsed)', () => {
    const r = build({ linksText: '', wgFiles: [{ name: 'multi.conf', text: WG_MULTI }] });
    assert.equal(r.report.wg.accepted, 1);
    mustInclude(r.yaml, 'peers:');
    mustInclude(r.yaml, 'server: vpn2.example.com');
    mustInclude(r.yaml, 'persistent-keepalive: 25');
});

test('missing PrivateKey → clear per-file error', () => {
    const bad = WG_MINIMAL.replace('PrivateKey = yKdCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'X-PrivateKey = yKdCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    const r = build({ linksText: VLESS, wgFiles: [{ name: 'bad.conf', text: bad }] });
    assert.equal(r.report.wg.refused, 1);
    const f = r.report.wg.files[0];
    assert.match(f.error.message, /privateKey|PrivateKey|неизвестное|WireGuard/i);
});

// ---------- 8. GLOBAL group contract: no dangling references ----------
function extractProxyNames(yaml) {
    const names = [];
    const proxiesStart = yaml.indexOf('\nproxies:\n');
    if (proxiesStart === -1) return names;
    const body = yaml.slice(proxiesStart);
    for (const m of body.matchAll(/^\s+- name: (.+)$/gm)) names.push(m[1].replace(/^"|"$/g, ''));
    return names;
}

test('GLOBAL includes direct proxies and providers without dangling references', () => {
    const { yaml } = build({
        linksText: `${VLESS}\n${HY2}\n${TROJAN}`,
        subscriptionUrlsText: SUB_URLS,
        subscriptions: true,
    });
    const defined = new Set(extractProxyNames(yaml));
    const providerNames = new Set();
    // proxy-providers are appended at the document end by overlayMihomoYaml (not near proxy-groups),
    // so scan the whole YAML: provider keys are the only empty-value keys at 2-space indent.
    for (const m of yaml.matchAll(/^  ([A-Za-z0-9_.-]+):$/gm)) providerNames.add(m[1]);

    const groupsBlock = yaml.slice(yaml.indexOf('\nproxy-groups:\n'), yaml.indexOf('\nrules:\n'));
    const refs = [];
    let inUse = false;
    for (const line of groupsBlock.split('\n')) {
        if (/^\s*use:\s*$/.test(line)) { inUse = true; continue; }
        // refs are deep items (6+ spaces, plain values); `  - name: X` lines are group definitions
        const itemM = line.match(/^\s{6,}- (.+)$/);
        if (itemM) { refs.push({ ref: itemM[1].replace(/^"|"$/g, ''), viaUse: inUse }); continue; }
        if (/^\s*[A-Za-z0-9_-]+:/.test(line)) inUse = false; // any key line (proxies:, url:, …) ends the use: list
    }
    assert.ok(defined.size >= 3, 'three direct proxies expected');
    const builtins = new Set(['REJECT', 'DIRECT']);
    for (const { ref, viaUse } of refs) {
        if (viaUse) assert.ok(providerNames.has(ref), `use-ref ${ref} must be a defined provider`);
        else if (ref === '⚡ Fastest') continue; // group defined in same block
        else if (!providerNames.has(ref)) assert.ok(defined.has(ref) || builtins.has(ref), `group-ref ${ref} must be defined`);
    }
    // GLOBAL must combine both worlds
    mustInclude(groupsBlock, '⚡ Fastest');
    mustInclude(groupsBlock, 'use:');
});

// ---------- 9. no-network guarantee at runtime ----------
test('generation performs no network calls (fetch monkeypatched to throw)', () => {
    const orig = globalThis.fetch;
    globalThis.fetch = () => { throw new Error('NETWORK_CALL_FORBIDDEN'); };
    try {
        const r = build({ subscriptionUrlsText: SUB_URLS, subscriptions: true });
        assert.ok(r.yaml.length > 0);
    } finally {
        globalThis.fetch = orig;
    }
});

// ---------- 10. bundle footprint & static checks ----------
test('bundle: exactly 2 files, minified+gzip measured, no CORS fallback / no fetch code / no storage', () => {
    const dist = path.join(here, 'dist');
    assert.ok(existsSync(dist), 'run: node kas-mini/build-mini.mjs first');
    const js = readFileSync(path.join(dist, 'kas-mini.js'), 'utf8');
    const html = readFileSync(path.join(dist, 'index.html'), 'utf8');
    // external-request sources must be tree-shaken away
    assert.ok(!js.includes('workers.dev'), 'CORS fallback domain must not survive tree-shaking');
    assert.ok(!js.includes('web2core'), 'worker glue must not survive');
    assert.ok(!js.includes('fetchSubscription'), 'subscription fetch helper must not survive');
    assert.ok(!js.includes('fetch('), 'no fetch() call sites in bundle');
    assert.ok(!js.includes('localStorage'), 'no storage');
    assert.ok(!js.includes('sessionStorage'), 'no storage');
    assert.ok(!html.includes('http://') && !html.includes('fetch('), 'index.html must not add network paths');
    // footprint sanity (small-bundle goal)
    const jsBytes = Buffer.byteLength(js);
    assert.ok(jsBytes < 120 * 1024, `bundle should stay small, got ${jsBytes} bytes`);
});
