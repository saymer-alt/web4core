// No-DIRECT egress invariant (link-generators #284, owner decision revised
// 2026-10-18): the generator must not create routes through which USER traffic
// silently egresses the host/VPS public IP; with no allowed egress left the
// build fails closed (REJECT / dial failure), never a host-IP fallback.
//
// User data plane (banned as DIRECT target/member):
//   - DPR category groups terminate in REJECT (never a DIRECT escape slot);
//   - an explicit DIRECT domain-policy target fails the build fail-closed
//     (both build layers).
// Service/control/transport plane (allowed, judged by purpose):
//   - subscription providers keep `proxy: DIRECT` as the download bootstrap —
//     mihomo routes provider fetches through the rule chain when the field is
//     absent (verified on v1.19.31: MATCH,GLOBAL over an empty provider-backed
//     group ⇒ immediate EOF, provider never loads);
//   - `dialer-proxy: DIRECT` (a WG handshake dialing directly) is emitted
//     verbatim — connection establishment, not user-traffic routing.
// The link-generators page layer enforces the policy at the UI (no DIRECT
// target options, legacy-card gate) — see the consumer suites.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoSubscriptionConfig, buildMihomoConfig, buildMihomoPriorityConfig } from '../../src/core/mihomo.js';
import { buildMihomoYaml } from '../../src/core/yaml.js';
import { buildFromRequest } from '../../src/build.js';
import { buildBeansFromInput } from '../../src/main.js';

const DIRECT_TOKEN = /\bDIRECT\b/;
const UUID = '00000000-0000-4000-8000-000000000001';

function directLines(yaml) {
    return String(yaml).split('\n')
        .map((line, i) => ({ no: i + 1, line: line.trim() }))
        .filter(x => DIRECT_TOKEN.test(x.line));
}

function assertNoDirectYaml(yaml, label) {
    const hits = directLines(yaml);
    assert.deepEqual(hits, [], label + ': DIRECT token found in emitted YAML: '
        + JSON.stringify(hits.slice(0, 3)));
}

const twoLinks = [
    'vless://' + UUID + '@192.0.2.1:443#A',
    'vless://' + UUID + '@192.0.2.2:443#B',
].join('\n');

function staticYaml(extraOpts, input) {
    const res = buildFromRequest({
        core: 'mihomo',
        input: input === undefined ? twoLinks : input,
        wgBeans: [],
        options: Object.assign({ addTun: false, addSocks: true, webUI: false }, extraOpts || {}),
    });
    assert.equal(res.kind, 'yaml');
    return res.data;
}

const policies = [
    { name: 'AI', domains: 'openai.com\nchatgpt.com' },
    { name: 'MEDIA', domains: ['youtube.com', 'googlevideo.com'] },
];

test('no-DIRECT: static build (two proxies) — lexical + structural', () => {
    const cfg = buildMihomoConfig(buildBeansFromInput(twoLinks), { addSocks: true });
    const globalGroup = cfg['proxy-groups'].find(g => g.name === 'GLOBAL');
    assert.equal(globalGroup.proxies[globalGroup.proxies.length - 1], 'REJECT', 'GLOBAL terminates in REJECT');
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, {}), 'static/2');
    assertNoDirectYaml(staticYaml(), 'static/2 via buildFromRequest');
});

test('no-DIRECT: static build (single proxy) — lexical + structural', () => {
    const cfg = buildMihomoConfig([], { addSocks: true });
    const globalGroup = cfg['proxy-groups'].find(g => g.name === 'GLOBAL');
    assert.equal(globalGroup.proxies[globalGroup.proxies.length - 1], 'REJECT', 'empty GLOBAL stays REJECT-only');
    assertNoDirectYaml(staticYaml({}, 'vless://' + UUID + '@192.0.2.1:443#A'), 'static/1');
});

test('no-DIRECT: per-proxy listeners — lexical', () => {
    const cfg = buildMihomoConfig(buildBeansFromInput(twoLinks), { perProxyListeners: true });
    for (const group of cfg['proxy-groups']) {
        // 🌐 static-health is a hidden checker (lazy:false) over static leaves,
        // not a routing group — it has no escape slot by design.
        if (group.name === '🌐 static-health') continue;
        if (Array.isArray(group.proxies)) {
            assert.ok(!group.proxies.includes('DIRECT'), 'group ' + group.name + ' has no DIRECT member');
            assert.equal(group.proxies[group.proxies.length - 1], 'REJECT', 'group ' + group.name + ' terminates in REJECT');
        }
    }
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, {}), 'per-proxy');
});

test('no-DIRECT: DPR SELECT cards — category selects end in REJECT, YAML lexical', () => {
    const cfg = buildMihomoConfig(buildBeansFromInput(twoLinks), { addSocks: true, domainPolicy: policies });
    for (const name of ['AI', 'MEDIA']) {
        const group = cfg['proxy-groups'].find(g => g.name === name);
        assert.equal(group.proxies[group.proxies.length - 1], 'REJECT', name + ' terminates in REJECT');
    }
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, { ruleProviders: cfg['rule-providers'] }), 'DPR SELECT');
});

test('no-DIRECT: DPR fixed GLOBAL/REJECT targets — lexical', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [
        { name: 'Glob', domains: 'glob.example.com', target: 'GLOBAL' },
        { name: 'Rej', domains: 'rej.example.com', target: 'REJECT' },
    ] });
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, { ruleProviders: cfg['rule-providers'] }), 'DPR fixed targets');
});

test('no-DIRECT: DPR DIRECT target fails closed at engine level', () => {
    assert.throws(
        () => buildMihomoConfig([], { domainPolicy: [{ name: 'Track', domains: 'tracker.example.com', target: 'DIRECT' }] }),
        /DIRECT is forbidden/,
    );
});

test('no-DIRECT: DPR DIRECT target fails closed via the public API', () => {
    assert.throws(
        () => buildFromRequest({
            core: 'mihomo',
            input: 'vless://' + UUID + '@192.0.2.1:443#A',
            wgBeans: [],
            options: { addTun: false, addSocks: true, mihomoDomainPolicy: [{ name: 'Track', domains: 'tracker.example.com', target: 'DIRECT' }] },
        }),
        /DIRECT is forbidden/,
    );
});

test('no-DIRECT: AUTO-WHITELIST priority config — flat fallback, lexical', () => {
    const cfg = buildMihomoPriorityConfig(
        { subUrls: [], beans: buildBeansFromInput('vless://' + UUID + '@192.0.2.1:443#P') },
        { subUrls: [], beans: buildBeansFromInput('vless://' + UUID + '@192.0.2.2:443#F') },
        {},
    );
    const globalGroup = cfg.groups[0];
    assert.equal(globalGroup.type, 'fallback');
    assert.equal(globalGroup['empty-fallback'], 'REJECT');
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg.groups, null, cfg.rules, [], {}), 'priority');
});

test('no-DIRECT: DPR priority-mode cards terminate in REJECT', () => {
    const cfg = buildMihomoPriorityConfig(
        { subUrls: [], beans: [] },
        { subUrls: [], beans: [] },
        { domainPolicy: policies },
    );
    for (const name of ['AI', 'MEDIA']) {
        const group = cfg.groups.find(g => g.name === name);
        assert.deepEqual(group.proxies, ['GLOBAL', 'REJECT'], name + ' = [GLOBAL, REJECT]');
    }
    assertNoDirectYaml(buildMihomoYaml(cfg.proxies, cfg.groups, null, cfg.rules, [], { ruleProviders: cfg.ruleProviders }), 'DPR priority');
});

test('no-DIRECT: dialer-proxy DIRECT (service plane) is emitted verbatim — baseline parity', () => {
    const wgBean = {
        name: 'WG-A',
        proto: 'wireguard',
        host: '192.0.2.73',
        port: 51820,
        wireguard: {
            privateKey: Buffer.alloc(32, 1).toString('base64'),
            publicKey: Buffer.alloc(32, 11).toString('base64'),
            ip: '10.66.1.2',
            allowedIPs: ['0.0.0.0/0'],
            dialerProxy: 'DIRECT',
        },
    };
    const res = buildFromRequest({
        core: 'mihomo',
        input: '',
        wgBeans: [wgBean],
        options: { addTun: false, addSocks: true, webUI: false },
    });
    assert.equal(res.kind, 'yaml');
    // Connection establishment is service plane: the handshake dials directly,
    // user traffic still flows through the tunnel (GLOBAL → REJECT-terminated).
    assert.ok(res.data.includes("dialer-proxy: 'DIRECT'") || res.data.includes('dialer-proxy: DIRECT'),
        'dialer-proxy DIRECT preserved (service plane)');
    assert.ok(!/^\s*-\s+DIRECT\s*$/m.test(res.data.split('rules:')[1] || ''), 'no DIRECT in routing rules');
});
