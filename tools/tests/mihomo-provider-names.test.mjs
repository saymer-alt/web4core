import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';
import { buildMihomoSubscriptionConfig } from '../../src/core/mihomo.js';

const one = 'https://one.example.invalid/sub';
const two = 'https://two.example.invalid/sub';
const generate = (input, extra = {}) => buildFromRequest({
  core: 'mihomo', input, options: { mihomoSubscriptionMode: true, deviceHwid: '1234567890abcdef1234567890abcdef', ...extra }
}).data;

test('default names retain legacy host-based behavior (no metadata fetch)', () => {
  const cfg = buildMihomoSubscriptionConfig([one, two], [], {});
  assert.deepEqual(Object.keys(cfg.providers), ['one.example.invalid', 'two.example.invalid']);
  assert.deepEqual(cfg.groups[0].use, ['one.example.invalid', 'two.example.invalid']);
});

test('two adjacent # provider-name directives generate readable provider IDs and matching group use', () => {
  const yaml = generate('# provider-name: Geodema\n' + one + '\n# provider-name: WL\n' + two);
  assert.match(yaml, /Geodema:/);
  assert.match(yaml, /\bWL:/);
  assert.doesNotMatch(yaml, /one\.example\.invalid:/);
  assert.match(yaml, /- Geodema/);
  assert.match(yaml, /- WL/);
});

test('custom name does not change provider URL or device identity', () => {
  const before = buildMihomoSubscriptionConfig([one], [], { deviceHwid: '1234567890abcdef1234567890abcdef' });
  const after = buildMihomoSubscriptionConfig([one], [], {
    deviceHwid: '1234567890abcdef1234567890abcdef',
    providerNames: ['Geodema']
  });
  const oldProvider = Object.values(before.providers)[0];
  const newProvider = Object.values(after.providers)[0];
  assert.equal(newProvider.url, oldProvider.url);
  assert.deepEqual(newProvider.header, oldProvider.header);
  assert.deepEqual(after.groups[0].use, ['Geodema']);
});

test('Unicode names and per-provider groups preserve provider references', () => {
  const cfg = buildMihomoSubscriptionConfig([one, two], [], {
    providerNames: ['Геодема 1', 'WL-2'],
    perProxyPort: true
  });
  assert.deepEqual(Object.keys(cfg.providers), ['Геодема 1', 'WL-2']);
  assert(cfg.groups.some(x => x.name === 'SUB-Геодема 1' && x.use.includes('Геодема 1')));
});

test('name directives are scoped to their adjacent URL and support comments', () => {
  const yaml = generate('# ordinary comment\n# provider-name: Geodema\n# another note\n' + one + '\n' + two);
  assert.match(yaml, /Geodema:/);
  assert.match(yaml, /two\.example\.invalid:/);
});

test('invalid or misplaced directives fail closed', () => {
  for (const input of [
    '# provider-name: \n' + one,
    '# provider-name: A\n# provider-name: B\n' + one,
    '# provider-name: A\nsocks://user:pass@proxy.example.invalid:1080',
    '# provider-name: A\nvless://x@y',
    '# provider-name: A\nhttps://user:secret@one.example.invalid/sub'
  ]) {
    assert.throws(() => generate(input), /provider-name/);
  }
});

test('reject duplicate explicit names and unsafe YAML keys', () => {
  assert.throws(() => generate('# provider-name: WL\n' + one + '\n# provider-name: WL\n' + two), /Duplicate provider-name/);
  for (const name of ['__proto__', 'constructor', 'bad:name', 'bad\nname', '<script>', 'A'.repeat(49)]) {
    assert.throws(() => buildMihomoSubscriptionConfig([one], [], { providerNames: [name] }), /Invalid provider-name/);
  }
});

test('primary/fallback subscription providers preserve two independent names', () => {
  const result = buildFromRequest({
    core: 'mihomo',
    input: '# provider-name: Primary\n' + one,
    fallbackInput: '# provider-name: Reserve\n' + two,
    options: { mihomoSubscriptionMode: true, addSocks: true, deviceHwid: '1234567890abcdef1234567890abcdef' }
  });
  assert.match(result.data, /primary-Primary:/);
  assert.match(result.data, /fallback-Reserve:/);
});
