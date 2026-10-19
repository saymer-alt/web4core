// #280 — synthetic-only per-provider HWID contract for the Mihomo core.
// Never use actual subscription URLs, customer HWIDs, credentials, or keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoSubscriptionConfig } from '../../src/core/mihomo.js';
import { buildFromRequest } from '../../src/build.js';

const URLS = [
  'https://sub-a.example.invalid/feed',
  'https://sub-b.example.invalid/feed',
  'https://sub-c.example.invalid/feed',
];
const H1 = '11111111111111111111111111111111';
const H2 = '22222222222222222222222222222222';
const getHwids = cfg => Object.values(cfg.providers).map(p => p.header['x-hwid'][0]);
const map = (hwids, urls = URLS) => hwids.map((hwid, i) => hwid === null ? null : { sourceUrl: urls[i], hwid });
const build = (urls = URLS, opts = {}) => buildMihomoSubscriptionConfig(urls, [], opts);

test('legacy single identity remains the default for every provider', () => {
  const result = build(URLS, { deviceHwid: H1 });
  assert.deepEqual(getHwids(result), [H1, H1, H1]);
  assert.equal(Object.keys(result.providers).length, 3);
});

test('explicit per-provider override preserves A != B == C', () => {
  const overrides = map([H1, H2, H2]);
  assert.deepEqual(getHwids(build(URLS, { deviceHwid: H1, providerOverrides: overrides })), [H1, H2, H2]);
  assert.deepEqual(getHwids(build(URLS, { deviceHwid: H1, providerOverrides: overrides })), [H1, H2, H2]);
});

test('null entries inherit global identity; explicit values never rotate', () => {
  const overrides = map([null, H2, null]);
  assert.deepEqual(getHwids(build(URLS, { deviceHwid: H1, providerOverrides: overrides })), [H1, H2, H1]);
});

test('mismatched order and counts are rejected before output', () => {
  assert.throws(() => build(URLS, { deviceHwid: H1, providerOverrides: map([H1, H2]) }), /providerOverrides/);
  const swapped = [URLS[1], URLS[0], URLS[2]];
  assert.throws(() => build(swapped, { deviceHwid: H1, providerOverrides: map([H1, H2, H2]) }), /providerOverrides/);
});

test('invalid HWIDs, mappings, and missing inherited identity fail closed', () => {
  const bad = [
    map([H1, 'bad', H2]),
    map([H1, '', H2]),
    [{ sourceUrl: URLS[0], hwid: H1, extra: true }, ...map([H2, H2]).map((x, i) => ({sourceUrl: URLS[i + 1], hwid: x.hwid}))],
  ];
  for (const entries of bad) {
    let failure = '';
    try { build(URLS, { deviceHwid: H1, providerOverrides: entries }); } catch (error) { failure = error.message; }
    assert.match(failure, /providerOverrides/);
    assert.ok(!failure.includes(URLS[0]) && !failure.includes(H1) && !failure.includes(H2), 'no source URL or HWID in error');
  }
  assert.throws(() => build(URLS, { providerOverrides: map([null, H2, H2]) }), /inherited HWID is missing/);
});

test('duplicate source URLs with explicit overrides must be disambiguated', () => {
  const urls = [URLS[0], URLS[0]];
  assert.throws(() => build(urls, { deviceHwid: H1, providerOverrides: map([H1, H2], urls) }), /duplicate subscription URLs/);
});

test('buildFromRequest forwards overrides to generated Mihomo YAML', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: URLS.join('\n'),
    options: {
      addSocks: true,
      mihomoSubscriptionMode: true,
      deviceHwid: H1,
      providerOverrides: map([H1, H2, H2]),
    },
  }).data;
  assert.equal(typeof yaml, 'string');
  assert.ok(yaml.includes(H1) && yaml.includes(H2));
  assert.equal((yaml.match(new RegExp(H1, 'g')) || []).length, 1);
  assert.equal((yaml.match(new RegExp(H2, 'g')) || []).length, 2);
});

test('non-subscription and primary/fallback requests reject unsupported override routing', () => {
  const options = {
    addSocks: true,
    mihomoSubscriptionMode: true,
    deviceHwid: H1,
    providerOverrides: map([H1, H2, H2]),
  };
  assert.throws(() => buildFromRequest({
    core: 'mihomo', input: URLS.join('\\n'), fallbackInput: URLS[2],
    options,
  }), /providerOverrides/);
  assert.throws(() => buildFromRequest({
    core: 'mihomo', input: 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443#synthetic',
    options: { ...options, mihomoSubscriptionMode: false },
  }), /providerOverrides/);
});
