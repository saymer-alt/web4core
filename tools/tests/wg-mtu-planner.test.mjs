// NIGHT-05: MTU chain planner — deterministic diagnostics-only model tests.
// planWireGuardMtu НИКОГДА не меняет YAML: только расчёт потолков/причин.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { planWireGuardMtu } from '../../src/core/wireguard.js';

const wg = (name, mtu, dialer, awg = {}) => ({
    name, type: 'wireguard', mtu, 'dialer-proxy': dialer,
    'amnezia-wg-option': Object.keys(awg).length ? awg : undefined,
});
const vless = (name) => ({ name, type: 'vless' });

test('single WG with explicit MTU, outermost: effective = imported, never touched', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', 1420)] });
    const a = r.profiles[0];
    assert.equal(a.confidence, 'proven');
    assert.equal(a.importedMtu, 1420);
    assert.equal(a.effective, 1420);
    assert.equal(a.mtuSource, 'imported');
    assert.ok(a.reason.some(x => x.includes('outermost')));
});

test('single WG without MTU: engine default 1408 (source-pinned), nothing emitted by planner', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', undefined)] });
    const a = r.profiles[0];
    assert.equal(a.importedMtu, null);
    assert.equal(a.effective, 1408);
    assert.equal(a.mtuSource, 'engine-default');
    assert.equal(r.note, 'diagnostics-only: YAML/mtu не изменяются');
});

test('A -> B plain WG: ceiling = outer - 75 worst-case; min() with imported', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', 1420, 'B'), wg('B', 1408)] });
    const a = r.profiles.find(p => p.name === 'A');
    const b = r.profiles.find(p => p.name === 'B');
    assert.equal(b.effective, 1408);
    assert.equal(a.ceiling, 1333, '1408 - (32 + 15 align + 28 inner IP/UDP)');
    assert.equal(a.effective, 1333, 'min(1420, 1333)');
    assert.equal(a.overhead.min, 32);
    assert.equal(a.overhead.max, 47);
    assert.equal(a.overhead.deterministic, true);
    assert.ok(a.reason.some(x => x.includes('dialer-proxy: B')));
    assert.ok(a.reason.some(x => x.includes('outer effective MTU: 1408')));
});

test('explicit low MTU is never raised: imported 1200 inside chain stays 1200', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', 1200, 'B'), wg('B', 1408)] });
    const a = r.profiles.find(p => p.name === 'A');
    assert.equal(a.ceiling, 1333);
    assert.equal(a.effective, 1200, 'min(1200, 1333) = 1200');
    assert.ok(a.effective <= a.importedMtu);
});

test('missing MTU inside a chain: planner emits calculated ceiling value in the MODEL only', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', undefined, 'B'), wg('B', 1408)] });
    const a = r.profiles.find(p => p.name === 'A');
    assert.equal(a.importedMtu, null);
    assert.equal(a.effective, 1333);
    assert.equal(a.mtuSource, 'planned-ceiling');
});

test('A -> B -> C: monotonic ceilings, outermost -> inward', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', undefined, 'B'), wg('B', undefined, 'C'), wg('C', 1300)] });
    const a = r.profiles.find(p => p.name === 'A');
    const b = r.profiles.find(p => p.name === 'B');
    const c = r.profiles.find(p => p.name === 'C');
    assert.equal(c.effective, 1300);
    assert.equal(b.ceiling, 1225);
    assert.equal(b.effective, 1225);
    assert.equal(a.ceiling, 1150);
    assert.equal(a.effective, 1150);
    assert.ok(a.ceiling < b.ceiling < c.effective, 'monotonic inward decrease');
    assert.deepEqual(a.chain[0], 'A');
});

test('AWG S4 + ContentPaddingAddition: worst-case max(range) enters the ceiling', () => {
    const r = planWireGuardMtu({
        proxies: [
            wg('A', 1420, 'B', { s4: 20, 'content-padding-addition': '10-100', version: 3 }),
            wg('B', 1408),
        ],
    });
    const a = r.profiles.find(p => p.name === 'A');
    // 1408 - (32 + 20 + 100 + 15 + 28) = 1213
    assert.equal(a.ceiling, 1213);
    assert.equal(a.overhead.min, 32 + 20 + 10);
    assert.equal(a.overhead.max, 32 + 20 + 100 + 15, 'wire-overhead max включает align 15');
    assert.equal(a.overhead.deterministic, true);
});

test('RandomTrailers: no config-derived bound -> confidence unknown, imported preserved', () => {
    const r = planWireGuardMtu({
        proxies: [
            wg('A', 1300, 'B', { 'random-trailers': true, version: 3 }),
            wg('B', 1408),
        ],
    });
    const a = r.profiles.find(p => p.name === 'A');
    assert.equal(a.confidence, 'unknown');
    assert.equal(a.ceiling, null);
    assert.equal(a.effective, 1300, 'imported preserved');
    assert.equal(a.overhead.deterministic, false);
    assert.ok(a.reason.some(x => x.includes('RandomTrailers')));
});

test('non-WG/AWG dialer target: chain analysis stops, imported preserved', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', 1380, 'VPS-VLESS'), vless('VPS-VLESS')] });
    const a = r.profiles.find(p => p.name === 'A');
    assert.equal(a.confidence, 'stopped');
    assert.equal(a.effective, 1380);
    assert.ok(a.reason.some(x => x.includes('non-WG/AWG dialer target') && x.includes('VPS-VLESS')));
});

test('cycle in doc (defensive): planner marks cycle, does not recurse forever', () => {
    const r = planWireGuardMtu({ proxies: [wg('A', 1400, 'B'), wg('B', 1400, 'A')] });
    const a = r.profiles.find(p => p.name === 'A');
    assert.equal(a.confidence, 'cycle');
});

test('4-hop chain: ceilings decrease monotonically inward', () => {
    const r = planWireGuardMtu({
        proxies: [wg('A', undefined, 'B'), wg('B', undefined, 'C'), wg('C', undefined, 'D'), wg('D', 1300)],
    });
    const a = r.profiles.find(p => p.name === 'A');
    const b = r.profiles.find(p => p.name === 'B');
    const c = r.profiles.find(p => p.name === 'C');
    assert.equal(c.ceiling, 1225);
    assert.equal(b.ceiling, 1150);
    assert.equal(a.ceiling, 1075);
    assert.ok(a.ceiling < b.ceiling && b.ceiling < c.ceiling);
});

test('chain requiring below practical minimum 576: confidence error', () => {
    const hops = [wg('Z', 600)];
    let prev = 'Z';
    for (let i = 0; i < 4; i++) {
        const n = 'H' + i;
        hops.push(wg(n, undefined, prev));
        prev = n;
    }
    const r = planWireGuardMtu({ proxies: hops });
    const inner = r.profiles.find(p => p.name === 'H3');
    assert.equal(inner.confidence, 'error');
    assert.ok(inner.reason.some(x => x.includes('576')));
});

test('non-WG proxies are invisible to the planner', () => {
    const r = planWireGuardMtu({ proxies: [vless('v1'), wg('A', 1400)] });
    assert.deepEqual(r.profiles.map(p => p.name), ['A']);
});
