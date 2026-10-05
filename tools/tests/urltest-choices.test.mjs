// URLTEST_CHOICES contract: Mihomo-recommended presets, default order, groups.
// Source-of-truth: src/main.js URLTEST_CHOICES (экспортируется через entry-web4core).
import test from 'node:test';
import assert from 'node:assert/strict';
import { URLTEST_CHOICES, URLTEST } from '../../src/main.js';

test('default health-check URL is the Mihomo-documented Google gstatic endpoint', () => {
  assert.equal(URLTEST, 'https://www.gstatic.com/generate_204');
  assert.equal(URLTEST_CHOICES[0].id, 'google');
  assert.equal(URLTEST_CHOICES[0].url, 'https://www.gstatic.com/generate_204');
});

test('Cloudflare preset uses the official cp.cloudflare.com endpoint', () => {
  const cf = URLTEST_CHOICES.find(c => c.id === 'cloudflare');
  assert.equal(cf.url, 'https://cp.cloudflare.com');
  assert.equal(cf.expectedStatus, 204);
});

test('recommended/other grouping is explicit', () => {
  const recommended = URLTEST_CHOICES.filter(c => c.group === 'mihomo-recommended').map(c => c.id);
  const other = URLTEST_CHOICES.filter(c => c.group === 'other').map(c => c.id);
  assert.deepEqual(recommended, ['google', 'cloudflare']);
  assert.deepEqual(other, ['apple', 'microsoft', 'ubuntu', 'fedora']);
  assert.equal(URLTEST_CHOICES.filter(c => !c.group).length, 0, 'every preset carries a group');
});

test('all preset URLs are https and well-formed', () => {
  for (const c of URLTEST_CHOICES) {
    const u = new URL(c.url);
    assert.equal(u.protocol, 'https:', c.id);
    assert.ok(!c.url.includes('@'), c.id + ': no credentials in URL');
    assert.ok(c.expectedStatus >= 200 && c.expectedStatus < 400, c.id);
  }
});
