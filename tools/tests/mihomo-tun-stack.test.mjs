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
        for (const value of [undefined, 'gvisor', 'foobar', '', null, 1, {}, 'MIPS', 'mips\nallow-lan: true']) {
            assert.equal(stable(build({ mihomoTunStack: value })), defaults);
        }
        const mips = stable(build({ mihomoTunStack: 'mips' }));
        assert.equal((mips.match(/stack: mips/g) || []).length, count);
        assert.equal(mips.replace(/stack: mips/g, 'stack: gvisor'), defaults);
        if (perProxy) assert.equal((mips.match(/type: tun/g) || []).length, count);
    });
}

test('direct YAML API normalizes stack and no-TUN requests omit it', () => {
    for (const stack of [undefined, 'foobar', 'mips']) {
        const yaml = buildMihomoYaml([], [], null, [], [], { tun: { stack } });
        assert.match(yaml, new RegExp(`stack: ${stack === 'mips' ? 'mips' : 'gvisor'}`));
    }
    const result = buildFromRequest({ core: 'mihomo', input: links, options: { addSocks: true, addTun: false, mihomoTunStack: 'mips' } });
    assert.doesNotMatch(result.data, /stack:/);
});
