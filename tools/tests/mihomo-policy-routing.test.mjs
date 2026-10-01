import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoSubscriptionConfig, buildMihomoConfig, buildMihomoPriorityConfig } from '../../src/core/mihomo.js';
import { buildMihomoYaml } from '../../src/core/yaml.js';
import { buildFromRequest } from '../../src/build.js';
import { buildBeansFromInput } from '../../src/main.js';

const subUrls = ['https://subs.example.invalid/token'];
const policies = [
    { name: 'AI', domains: 'openai.com\nchatgpt.com\noaistatic.com' },
    { name: 'MEDIA', domains: ['youtube.com', 'googlevideo.com', 'ytimg.com'] },
];

function dprSubscription() {
    return buildMihomoSubscriptionConfig(subUrls, [], { domainPolicy: policies });
}

test('DPR off: no rule-providers, no policy groups, rules keep legacy shape', () => {
    const cfg = buildMihomoSubscriptionConfig(subUrls, [], {});
    assert.equal(cfg.ruleProviders, undefined);
    assert.equal(cfg.warnings, undefined);
    assert.deepEqual(cfg.rules, ['MATCH,GLOBAL']);
    assert.ok(!cfg.groups.some(g => g.name === 'AI' || g.name === 'AI-AUTO'));
    const yaml = buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, cfg.listeners, {});
    assert.ok(!yaml.includes('rule-providers:'));
    assert.ok(!yaml.includes('RULE-SET'));
});

test('DPR off: buildFromRequest output stays byte-identical with and without the empty option', () => {
    const input = subUrls.join('\n');
    const opts = { mihomoSubscriptionMode: true };
    const without = buildFromRequest({ core: 'mihomo', input, options: { ...opts } });
    const withEmpty = buildFromRequest({ core: 'mihomo', input, options: { ...opts, mihomoDomainPolicy: [] } });
    const scrub = (s) => s.replace(/^\s+- [0-9a-f]{32}$/gm, 'HWID');
    assert.equal(scrub(without.data), scrub(withEmpty.data));
    assert.ok(!without.data.includes('rule-providers:'));
});

test('DPR basic: rule-providers, category groups over the shared provider, rules end with MATCH,GLOBAL', () => {
    const cfg = dprSubscription();
    const providerNames = Object.keys(cfg.providers);
    assert.equal(providerNames.length, 1);
    assert.deepEqual(cfg.rules, [
        'RULE-SET,policy-ai,AI',
        'RULE-SET,policy-media,MEDIA',
        'MATCH,GLOBAL',
    ]);
    const byName = Object.fromEntries(cfg.groups.map(g => [g.name, g]));
    for (const [policy, slug] of [['AI', 'policy-ai'], ['MEDIA', 'policy-media']]) {
        const auto = byName[`${policy}-AUTO`];
        assert.equal(auto.type, 'url-test');
        assert.deepEqual(auto.use, providerNames, 'AUTO group must reference the same provider');
        assert.equal(auto['empty-fallback'], 'REJECT');
        const select = byName[policy];
        assert.equal(select.type, 'select');
        assert.deepEqual(select.proxies, [`${policy}-AUTO`, '⚡ Fastest', 'GLOBAL', 'DIRECT']);
        const provider = cfg.ruleProviders[slug];
        assert.equal(provider.type, 'inline');
        assert.equal(provider.behavior, 'classical');
        assert.equal(provider.format, 'yaml');
        assert.ok(provider.payload.length >= 2);
        assert.ok(provider.payload.every(entry => /^(DOMAIN|GEOSITE|IP-CIDR)/.test(entry)));
    }
    const groupOrder = cfg.groups.map(g => g.name);
    assert.ok(groupOrder.indexOf('GLOBAL') > groupOrder.indexOf('MEDIA'), 'GLOBAL stays the last group');
});

test('DPR shared provider: several AUTO groups use one provider; provider contract keeps proxy: DIRECT', () => {
    const cfg = buildMihomoSubscriptionConfig(
        ['https://a.example.invalid/s1', 'https://b.example.org/s2'],
        [],
        { domainPolicy: policies }
    );
    const providerNames = Object.keys(cfg.providers);
    assert.equal(providerNames.length, 2);
    const autoGroups = cfg.groups.filter(g => g.name.endsWith('-AUTO'));
    assert.equal(autoGroups.length, 2);
    for (const group of autoGroups) assert.deepEqual(group.use, providerNames);
    // Provider contract (PoC-proven cold-start deadlock without it): every
    // subscription provider must keep proxy: DIRECT, DPR or not.
    for (const provider of Object.values(cfg.providers)) assert.equal(provider.proxy, 'DIRECT');
    const plain = buildMihomoSubscriptionConfig(subUrls, [], {});
    for (const provider of Object.values(plain.providers)) assert.equal(provider.proxy, 'DIRECT');
});

test('DPR YAML emission: inline rule-providers land after proxy-providers (legacy section order untouched)', () => {
    const cfg = dprSubscription();
    const yaml = buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, cfg.listeners, { ruleProviders: cfg.ruleProviders });
    // The legacy overlay keeps historical section order (proxy-groups, rules,
    // proxy-providers); the new section appends after proxy-providers, last.
    const idxProviders = yaml.indexOf('proxy-providers:');
    const idxRuleProviders = yaml.indexOf('rule-providers:');
    assert.ok(idxProviders !== -1 && idxRuleProviders > idxProviders);
    assert.ok(yaml.includes('  policy-ai:'));
    assert.ok(yaml.includes('    - "DOMAIN-SUFFIX,openai.com"'));
    assert.ok(yaml.includes('  - "RULE-SET,policy-ai,AI"'));
});

test('DPR parsing: bare domains, *., CIDR, explicit types, comments; invalid lines become warnings', () => {
    const cfg = buildMihomoSubscriptionConfig(subUrls, [], {
        domainPolicy: [{
            name: 'MIX',
            domains: [
                'example.com',            // bare → DOMAIN-SUFFIX
                '*.ker.example.com',      // *.-prefix → DOMAIN-SUFFIX without *.
                'DOMAIN,exact.example.com',
                'DOMAIN-KEYWORD,opensub',
                'DOMAIN-WILDCARD,*.svc.example.com',
                'GEOSITE,category-ai-!cn',
                '192.0.2.0/24',           // bare CIDR → IP-CIDR + no-resolve
                'IP-CIDR,198.51.100.7',   // explicit, default /32
                '# comment line',
                '',
                'not a domain!',          // invalid → warning
                'IP-CIDR,999.1.1.1/8',    // invalid octet → warning
            ],
        }],
    });
    const payload = cfg.ruleProviders['policy-mix'].payload;
    assert.deepEqual(payload, [
        'DOMAIN-SUFFIX,example.com',
        'DOMAIN-SUFFIX,ker.example.com',
        'DOMAIN,exact.example.com',
        'DOMAIN-KEYWORD,opensub',
        'DOMAIN-WILDCARD,*.svc.example.com',
        'GEOSITE,category-ai-!cn',
        'IP-CIDR,192.0.2.0/24,no-resolve',
        'IP-CIDR,198.51.100.7/32,no-resolve',
    ]);
    assert.equal(cfg.warnings.length, 2);
    assert.equal(cfg.groups.filter(g => g.name.startsWith('MIX')).length, 2);
});

test('DPR empty policy: skipped with a warning, other policies unaffected', () => {
    const cfg = buildMihomoSubscriptionConfig(subUrls, [], {
        domainPolicy: [
            { name: 'EMPTY', domains: '###\n\n' },
            { name: 'AI', domains: 'openai.com' },
        ],
    });
    assert.ok(cfg.warnings.some(w => w.includes('EMPTY')));
    assert.ok(!cfg.groups.some(g => g.name.startsWith('EMPTY')));
    assert.deepEqual(cfg.rules, ['RULE-SET,policy-ai,AI', 'MATCH,GLOBAL']);
    assert.deepEqual(Object.keys(cfg.ruleProviders), ['policy-ai']);
});

test('DPR structural errors: duplicate names, reserved names, per-proxy mode', () => {
    assert.throws(
        () => buildFromRequest({
            core: 'mihomo',
            input: subUrls.join('\n'),
            options: { mihomoSubscriptionMode: true, mihomoDomainPolicy: [{ name: 'AI', domains: 'a.com' }, { name: 'AI', domains: 'b.com' }] },
        }),
        /duplicate domain policy name/
    );
    for (const reserved of ['GLOBAL', 'DIRECT', '⚡ Fastest', 'REJECT']) {
        assert.throws(
            () => buildMihomoSubscriptionConfig(subUrls, [], { domainPolicy: [{ name: reserved, domains: 'a.com' }] }),
            /reserved/
        );
    }
    assert.throws(
        () => buildMihomoSubscriptionConfig(subUrls, [], { domainPolicy: policies, perProxyPort: true }),
        /per-proxy/
    );
    assert.throws(
        () => buildFromRequest({
            core: 'mihomo',
            input: subUrls.join('\n'),
            options: { mihomoSubscriptionMode: true, mihomoDomainPolicy: [{ name: 'x,y', domains: 'a.com' }] },
        }),
        /must not contain commas/
    );
    // the engine accepts any comma-free name (slugified for the provider key)
    assert.doesNotThrow(
        () => buildMihomoSubscriptionConfig(subUrls, [], { domainPolicy: [{ name: 'Мои серверы', domains: 'a.com' }] })
    );
});

test('DPR static mode: category selects over Fastest/GLOBAL, no AUTO groups', () => {
    const links = 'socks://user:pass@203.0.113.10:1080#S1\nsocks://user:pass@203.0.113.11:1080#S2';
    const beans = buildBeansFromInput(links);
    assert.ok(beans.length === 2);
    const cfg = buildMihomoConfig(beans, { addSocks: true, domainPolicy: policies });
    const groups = cfg['proxy-groups'];
    const byName = Object.fromEntries(groups.map(g => [g.name, g]));
    assert.equal(byName.AI.type, 'select');
    assert.deepEqual(byName.AI.proxies, ['⚡ Fastest', 'GLOBAL', 'DIRECT']);
    assert.ok(!groups.some(g => g.name.endsWith('-AUTO')));
    assert.deepEqual(cfg.rules, ['RULE-SET,policy-ai,AI', 'RULE-SET,policy-media,MEDIA', 'MATCH,GLOBAL']);
    assert.deepEqual(Object.keys(cfg['rule-providers']), ['policy-ai', 'policy-media']);
});

test('DPR static mode via public API: rule-providers section + policy rules in final YAML', () => {
    const result = buildFromRequest({
        core: 'mihomo',
        input: 'socks://user:pass@203.0.113.10:1080#S1',
        options: { mihomoDomainPolicy: [{ name: 'AI', domains: 'openai.com' }], webUI: false },
    });
    assert.equal(result.kind, 'yaml');
    assert.ok(result.data.includes('rule-providers:'));
    assert.ok(result.data.includes('  - "RULE-SET,policy-ai,AI"'));
    assert.ok(result.data.includes('- "MATCH,GLOBAL"'));
});

test('DPR × AUTO-WHITELIST: flat fallback untouched, policy selects point at GLOBAL', () => {
    const primary = 'socks://user:pass@203.0.113.10:1080#P1';
    const cfg = buildMihomoPriorityConfig(
        { subUrls: [], beans: [] },
        { subUrls: [subUrls[0]], beans: [] },
        { domainPolicy: policies }
    );
    assert.equal(cfg.groups.length, 3);
    const globalGroup = cfg.groups[0];
    assert.equal(globalGroup.type, 'fallback');
    assert.ok(!(globalGroup.proxies || []).some(n => n === 'AI' || n === 'MEDIA' || n.endsWith('-AUTO')),
        'no policy/AUTO names inside the fallback (#2588 contract)');
    const byName = Object.fromEntries(cfg.groups.map(g => [g.name, g]));
    assert.deepEqual(byName.AI.proxies, ['GLOBAL', 'DIRECT']);
    assert.deepEqual(byName.MEDIA.proxies, ['GLOBAL', 'DIRECT']);
    assert.deepEqual(cfg.rules, ['RULE-SET,policy-ai,AI', 'RULE-SET,policy-media,MEDIA', 'MATCH,GLOBAL']);
    for (const provider of Object.values(cfg.providers)) assert.equal(provider.proxy, 'DIRECT');
});

test('DPR × AUTO-WHITELIST via public API: YAML keeps the flat fallback and adds policy groups', () => {
    const result = buildFromRequest({
        core: 'mihomo',
        input: 'socks://user:pass@203.0.113.10:1080#P1',
        fallbackInput: subUrls.join('\n'),
        options: {
            mihomoSubscriptionMode: true,
            mihomoDomainPolicy: [{ name: 'AI', domains: 'openai.com' }],
        },
    });
    assert.equal(result.kind, 'yaml');
    assert.ok(result.data.includes('type: fallback'));
    assert.ok(result.data.includes('  - "RULE-SET,policy-ai,AI"'));
    assert.ok(!result.data.includes('AI-AUTO'));
});
