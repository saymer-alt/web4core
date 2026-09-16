import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { buildMihomoYaml } from '../../src/core/yaml.js';

const links = 'socks://user:pass@192.0.2.1:1080#A\nsocks://user:pass@192.0.2.2:1080#B';
for (const subscription of [false, true]) for (const perProxy of [false, true]) {
    test(`TUN stack contract (subscription: ${subscription}, per-proxy: ${perProxy})`, () => {
        const input = subscription ? `https://example.invalid/sub\n${links}` : links;
        const options = { addTun: true, mihomoSubscriptionMode: subscription, mihomoPerProxyTun: perProxy };
        const build = (extra = {}) => buildFromRequest({ core: 'mihomo', input, options: { ...options, ...extra } }).data;
        // Subscription IDs are random; normalize only that unrelated field in comparisons.
        const stable = yaml => yaml.replace(/(x-hwid:\n\s+- )[^\n]+/g, '$1TEST');
        const defaults = stable(build());
        const count = perProxy ? (subscription ? 3 : 2) : 1;
        assert.equal((defaults.match(/stack: gvisor/g) || []).length, count);
        for (const value of [undefined, null, '', 'gvisor']) {
            assert.equal(stable(build({ mihomoTunStack: value })), defaults);
        }
        // Upstream resolver semantics: the full stack set is accepted, case/space normalized.
        for (const value of ['mips', 'MIPS', ' mips ']) {
            const yaml = stable(build({ mihomoTunStack: value }));
            assert.equal((yaml.match(/stack: mips/g) || []).length, count);
            assert.equal(yaml.replace(/stack: mips/g, 'stack: gvisor'), defaults);
        }
        if (perProxy) assert.equal((stable(build({ mihomoTunStack: 'mips' })).match(/type: tun/g) || []).length, count);
        for (const stack of ['system', 'mixed']) {
            const yaml = stable(build({ mihomoTunStack: stack }));
            assert.equal((yaml.match(new RegExp(`stack: ${stack}`, 'g')) || []).length, count);
        }
        // Unknown values fail loudly instead of silently falling back to gvisor.
        for (const value of ['foobar', 'gVisor!', 1, {}, true, 'mips\nallow-lan: true', 'system;']) {
            assert.throws(() => build({ mihomoTunStack: value }), /invalid TUN stack/);
        }
    });
}

test('direct YAML API validates stack and no-TUN requests omit it', () => {
    for (const stack of [undefined, null, '']) {
        const yaml = buildMihomoYaml([], [], null, [], [], { tun: { stack } });
        assert.match(yaml, /stack: gvisor/);
    }
    for (const stack of ['gvisor', 'system', 'mixed', 'mips']) {
        const yaml = buildMihomoYaml([], [], null, [], [], { tun: { stack } });
        assert.match(yaml, new RegExp(`stack: ${stack}`));
    }
    for (const stack of ['foobar', {}, 1]) {
        assert.throws(() => buildMihomoYaml([], [], null, [], [], { tun: { stack } }), /invalid TUN stack/);
    }
    const result = buildFromRequest({ core: 'mihomo', input: links, options: { addSocks: true, addTun: false, mihomoTunStack: 'mips' } });
    assert.doesNotMatch(result.data, /stack:/);
});
