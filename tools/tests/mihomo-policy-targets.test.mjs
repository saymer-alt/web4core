// DPR v2: policy rule targets (SELECT/GLOBAL/DIRECT/REJECT) + DOMAIN-WILDCARD.
// Target contract: absent/empty/SELECT = legacy per-policy select group;
// GLOBAL/DIRECT/REJECT point the whole policy RULE-SET at the builtin target
// without creating a category proxy-group. Rule order preserved; MATCH,GLOBAL
// always last. Unknown targets are rejected at engine level (fail-closed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoConfig } from '../../src/core/mihomo.js';

test('DPR target absent -> legacy SELECT (category group + RULE-SET,name)', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'AI', domains: 'openai.com' }] });
    const ai = cfg['proxy-groups'].find(g => g.name === 'AI');
    assert.equal(ai.type, 'select');
    const rule = cfg.rules.find(r => r.startsWith('RULE-SET,'));
    assert.equal(rule, 'RULE-SET,policy-ai,AI');
});

test('DPR target SELECT explicit -> identical to legacy', () => {
    const a = buildMihomoConfig([], { domainPolicy: [{ name: 'AI', domains: 'openai.com' }] });
    const b = buildMihomoConfig([], { domainPolicy: [{ name: 'AI', domains: 'openai.com', target: 'SELECT' }] });
    assert.deepEqual(b.rules, a.rules);
    assert.deepEqual(b['proxy-groups'].map(g => g.name + ':' + g.type), a['proxy-groups'].map(g => g.name + ':' + g.type));
});

test('DPR target GLOBAL -> RULE-SET to GLOBAL, no category group', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'Ads', domains: 'ads.example.com', target: 'GLOBAL' }] });
    assert.ok(!cfg['proxy-groups'].some(g => g.name === 'Ads'), 'no category group for GLOBAL target');
    const rule = cfg.rules.find(r => r.startsWith('RULE-SET,'));
    assert.equal(rule, 'RULE-SET,policy-ads,GLOBAL');
});

test('DPR target DIRECT and REJECT -> direct rule targets, no groups', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [
        { name: 'Track', domains: 'tracker.example.com', target: 'DIRECT' },
        { name: 'Ads2', domains: 'ads2.example.com', target: 'REJECT' },
    ] });
    assert.deepEqual(cfg.rules.filter(r => r.startsWith('RULE-SET,')),
        ['RULE-SET,policy-track,DIRECT', 'RULE-SET,policy-ads2,REJECT']);
    assert.ok(!cfg['proxy-groups'].some(g => g.name === 'Track' || g.name === 'Ads2'), 'no category groups');
});

test('DPR mixed targets SELECT/GLOBAL/DIRECT/REJECT: order preserved, MATCH,GLOBAL last', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [
        { name: 'Sel', domains: 'sel.example.com' },
        { name: 'Glob', domains: 'glob.example.com', target: 'GLOBAL' },
        { name: 'Dir', domains: 'dir.example.com', target: 'DIRECT' },
        { name: 'Rej', domains: 'rej.example.com', target: 'REJECT' },
    ] });
    const ruleSetRules = cfg.rules.filter(r => r.startsWith('RULE-SET,'));
    assert.deepEqual(ruleSetRules.map(r => r.split(',')[2]), ['Sel', 'GLOBAL', 'DIRECT', 'REJECT']);
    assert.equal(cfg.rules[cfg.rules.length - 1], 'MATCH,GLOBAL');
});

test('DPR invalid target rejected at engine level', () => {
    assert.throws(
        () => buildMihomoConfig([], { domainPolicy: [{ name: 'X', domains: 'x.com', target: 'PROVIDER' }] }),
        /target must be SELECT, GLOBAL, DIRECT or REJECT/,
    );
});

test('DOMAIN-WILDCARD: explicit MT patterns accepted via type prefix', () => {
    const patterns = ['*.telegram.org', 'yt*.ggpht.com', 'yt*.googleusercontent.com', '*.rutracker.*'];
    for (const pattern of patterns) {
        const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'WC', domains: 'DOMAIN-WILDCARD,' + pattern }] });
        const payload = cfg['rule-providers']['policy-wc'].payload;
        assert.ok(payload.some(r => r === 'DOMAIN-WILDCARD,' + pattern.toLowerCase()), 'pattern accepted: ' + pattern);
    }
});

test('DOMAIN-WILDCARD: bare MT patterns map to DOMAIN-WILDCARD (not broken DOMAIN-SUFFIX)', () => {
    for (const pattern of ['yt*.ggpht.com', '*.rutracker.*']) {
        const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'WC', domains: pattern }] });
        const payload = cfg['rule-providers']['policy-wc'].payload;
        assert.ok(payload.some(r => r === 'DOMAIN-WILDCARD,' + pattern.toLowerCase()), 'bare wildcard -> DOMAIN-WILDCARD: ' + pattern);
    }
});

test('bare leading *. keeps legacy DOMAIN-SUFFIX semantics', () => {
    const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'S', domains: '*.telegram.org' }] });
    const payload = cfg['rule-providers']['policy-s'].payload;
    assert.ok(payload.some(r => r === 'DOMAIN-SUFFIX,telegram.org'), 'leading *. -> legacy DOMAIN-SUFFIX');
});

test('DOMAIN-WILDCARD: charset garbage -> policy skipped with warning, no provider', () => {
    for (const bad of ['***', 'a b c', 'foo..bar']) {
        const cfg = buildMihomoConfig([], { domainPolicy: [{ name: 'WC', domains: bad }] });
        assert.ok(!cfg['rule-providers'] || !cfg['rule-providers']['policy-wc'], 'no provider for garbage: ' + bad);
        assert.ok(Array.isArray(cfg.warnings) && cfg.warnings.length > 0, 'warning reported for: ' + bad);
    }
});
