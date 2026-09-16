import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

const statics = 'socks://user:pass@192.0.2.1:1080#fi\nsocks://user:pass@192.0.2.2:1080#se';
const build = options => buildFromRequest({
    core: 'mihomo',
    input: 'https://example.invalid/sub\n' + statics,
    options: { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: true, ...options },
}).data;
const unquote = s => { try { return JSON.parse(s); } catch { return s; } };
const groupsOf = yaml => {
    const lines = yaml.split('\n');
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(/^  - name: (.+)$/);
        if (m) out.push({ name: unquote(m[1]), block: [] });
        else if (out.length && /^\s{4}/.test(lines[i])) out[out.length - 1].block.push(lines[i].trim());
    }
    return out;
};

test('per-proxy mode adds a hidden url-test checker over static leaves only', () => {
    const yaml = build({ perProxyPort: true });
    const groups = groupsOf(yaml);
    const checker = groups.find(g => g.name === '🌐 static-health');
    assert.ok(checker, 'checker group exists');
    assert.equal(checker.block.find(l => l.startsWith('type:')), 'type: url-test');
    assert.ok(checker.block.includes('hidden: true'));
    const members = checker.block.filter(l => l.startsWith('- ') && !l.startsWith('- force')).map(l => l.slice(2));
    assert.deepEqual(members, ['fi', 'se']);
    assert.ok(checker.block.some(l => l.startsWith('url: ')));
    // checker is not a GLOBAL target and listeners keep targeting wrappers
    const global = groups.find(g => g.name === 'GLOBAL');
    assert.ok(global.block.join('\n').includes('🔒 fi'));
    assert.ok(!global.block.join('\n').includes('static-health'));
    // provider keeps its own SUB group and its own health-check
    assert.ok(groups.some(g => g.name === 'SUB-example.invalid'));
});

test('per-proxy pure subscription mode has no static checker', () => {
    const yaml = buildFromRequest({
        core: 'mihomo',
        input: 'https://example.invalid/sub',
        options: { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: true, perProxyPort: true },
    }).data;
    assert.doesNotMatch(yaml, /static-health/);
});

test('generic mode never emits the checker (byte parity with legacy output)', () => {
    const yaml = build({ perProxyPort: false });
    assert.doesNotMatch(yaml, /static-health/);
    assert.match(yaml, /name: "⚡ Fastest"/);
});
