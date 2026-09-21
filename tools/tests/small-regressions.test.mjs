import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

const opts = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const build = input => buildFromRequest({ core: 'mihomo', input, options: opts }).data;

test('hysteria2 mport: valid range and lists are preserved', () => {
  const range = build('hy2://pass@192.0.2.6:443?mport=20000-30000#H');
  assert.match(range, /ports: 20000-30000/);
  const list = build('hy2://pass@192.0.2.6:443?mport=2000-3000,4000#H');
  assert.match(list, /ports: "2000-3000,4000"/);
});

test('hysteria2 mport: garbage, out-of-range and malformed values fail loudly', () => {
  for (const mport of ['abc', '100-200-300', '70000', '1-70000', '3000-2000']) {
    assert.throws(
      () => build('hy2://pass@192.0.2.6:443?mport=' + encodeURIComponent(mport) + '#H'),
      /invalid mport/,
      'mport=' + mport,
    );
  }
});

test('hysteria2 mport: absent/empty adds no ports field', () => {
  const plain = build('hy2://pass@192.0.2.6:443#H');
  assert.doesNotMatch(plain, /^\s*ports:/m);
  const empty = build('hy2://pass@192.0.2.6:443?mport=#H');
  assert.doesNotMatch(empty, /^\s*ports:/m);
});

test('comment lines in the link input are skipped, not parsed as links', () => {
  const yaml = build('# just a comment\nsocks://user:pass@192.0.2.1:1080#A\n# another\n');
  assert.match(yaml, /name: A/);
  const count = (yaml.match(/type: socks5/g) || []).length;
  assert.equal(count, 1);
});

test('comment lines are skipped in Sub Mode proxy text too', () => {
  const yaml = buildFromRequest({
    core: 'mihomo',
    input: 'https://sub.example/one\n# comment\nsocks://user:pass@192.0.2.1:1080#A',
    options: { ...opts, mihomoSubscriptionMode: true },
  }).data;
  assert.match(yaml, /name: A/);
  assert.doesNotMatch(yaml, /Unknown link/);
});

test('mihomo production default uses warning log level', () => {
  const yaml = build('socks://user:pass@192.0.2.1:1080#A');
  assert.match(yaml, /^log-level: warning$/m);
  assert.doesNotMatch(yaml, /^log-level: info$/m);
});

