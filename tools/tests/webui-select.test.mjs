import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

const input = 'socks://user:pass@192.0.2.1:1080#A';
const base = { addTun: true, addSocks: true, webUI: true, mihomoSubscriptionMode: false };
const build = options => buildFromRequest({ core: 'mihomo', input, options: { ...base, ...options } }).data;
const METACUBE = 'https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz';
const YACD = 'https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip';
const ZASH = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip';
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

test('absent/metacubexd dashboard keeps legacy output byte-for-byte', () => {
  const legacy = buildFromRequest({ core: 'mihomo', input, options: { addTun: true, addSocks: true, webUI: true, mihomoSubscriptionMode: false } }).data;
  assert.equal(build({}), legacy);
  assert.equal(build({ webUiDashboard: 'metacubexd' }), legacy);
  assert.match(legacy, new RegExp('external-ui-url: ' + esc(METACUBE)));
});

test('dashboard presets emit exact external-ui-url values', () => {
  assert.match(build({ webUiDashboard: 'yacd' }), new RegExp('external-ui-url: ' + esc(YACD)));
  assert.match(build({ webUiDashboard: 'zashboard' }), new RegExp('external-ui-url: ' + esc(ZASH)));
});

test('custom dashboard requires absolute http/https URL; value is generated, never fetched', () => {
  assert.match(build({ webUiDashboard: 'custom', webUiCustomUrl: 'https://ui.example.net/dash.zip' }),
    /external-ui-url: https:\/\/ui\.example\.net\/dash\.zip/);
  assert.match(build({ webUiDashboard: 'custom', webUiCustomUrl: 'http://192.0.2.9/ui.tgz' }),
    /external-ui-url: http:\/\/192\.0\.2\.9\/ui\.tgz/);
  assert.throws(() => build({ webUiDashboard: 'custom', webUiCustomUrl: 'ftp://x/y' }), /Invalid Web UI URL/);
  assert.throws(() => build({ webUiDashboard: 'custom', webUiCustomUrl: 'not a url' }), /Invalid Web UI URL/);
  assert.throws(() => build({ webUiDashboard: 'custom' }), /Invalid Web UI URL/);
});

test('unknown dashboard name fails loudly', () => {
  assert.throws(() => build({ webUiDashboard: 'metacubexd-classic' }), /Unknown Web UI dashboard/);
});

test('webUI off: dashboard choice changes nothing', () => {
  const offYacd = buildFromRequest({ core: 'mihomo', input, options: { addTun: true, addSocks: true, webUI: false, mihomoSubscriptionMode: false, webUiDashboard: 'yacd' } }).data;
  const offZash = buildFromRequest({ core: 'mihomo', input, options: { addTun: true, addSocks: true, webUI: false, mihomoSubscriptionMode: false, webUiDashboard: 'zashboard' } }).data;
  assert.equal(offYacd, offZash);
  assert.doesNotMatch(offYacd, /external-ui/);
});
