import test from 'node:test';
import assert from 'node:assert/strict';
import { detectWireGuardGeneration, parseWireGuardConf } from '../../src/core/wireguard.js';

// Детектор generation (#157): diagnostics-only; без значений секретов в evidence;
// ambiguous-конфиги никогда не получают false exact version.

test('plain WireGuard profile: family wg, exact', () => {
    const r = detectWireGuardGeneration({});
    assert.equal(r.family, 'wg');
    assert.equal(r.label, 'WireGuard');
    assert.equal(r.confidence, 'exact');
    assert.deepEqual(r.conflicts, []);
});

const classic = { 'amnezia-wg-option': { jc: 3, jmin: 40, jmax: 70, s1: 15, s2: 20, h1: 1, h2: 2, h3: 3, h4: 4 } };
const premium = { 'amnezia-wg-option': { jc: 5, h1: '100-200', h2: '300-400', h3: '500-600', h4: '700-800', s3: 10, s4: 20, i1: '<b 0x1234><t>', i2: '<r 10>' } };
const v3 = { 'amnezia-wg-option': { 'header-protection-key': 'aGVsbG8=', 'content-padding-addition': '10-20', 'rekey-after-time': '90-120', 'keepalive-timeout': '10-20' } };
const v31 = { 'amnezia-wg-option': { 'header-protection-key': 'aGVsbG8=', 'random-trailers': true, 'disable-cookies': false } };

test('classic-only signature: AWG 1.x (legacy), range confidence', () => {
    const r = detectWireGuardGeneration(classic);
    assert.equal(r.family, 'awg');
    assert.equal(r.generation, '1.x');
    assert.match(r.label, /1\.x/);
    assert.equal(r.confidence, 'range');
    assert.deepEqual(r.compatible, ['1.x']);
    assert.ok(r.evidence.includes('jc') && r.evidence.includes('h4'));
});

test('CPS/I-fields: AWG 1.5–2.x compatible range, никогда exact 1.5 или 2.x', () => {
    const r = detectWireGuardGeneration(premium);
    assert.equal(r.generation, '1.5–2.x');
    assert.equal(r.confidence, 'range');
    assert.deepEqual(r.compatible, ['1.5', '2.x']);
    assert.ok(r.evidence.includes('i1') && r.evidence.includes('s4'));
    assert.ok(!/^AmneziaWG (1\.5|2\.x)$/.test(r.label), 'no false exact version');
});

test('v3 fields without 3.1 flags: AWG 3.x (lower bound 3.0), range', () => {
    const r = detectWireGuardGeneration(v3);
    assert.equal(r.generation, '3.x');
    assert.equal(r.confidence, 'range');
    assert.deepEqual(r.compatible, ['3.0', '3.1']);
    assert.ok(r.evidence.includes('header-protection-key'));
    // target compatibility note: v3 требует mihomo >= 1.19.30
    assert.ok(r.notes.some(n => /1\.19\.30/.test(n.text)));
});

test('3.1 flags: exact 3.1', () => {
    const r = detectWireGuardGeneration(v31);
    assert.equal(r.generation, '3.1');
    assert.equal(r.label, 'AmneziaWG 3.1');
    assert.equal(r.confidence, 'exact');
});

test('3.1 flag + classic fields (no v3 extras): still exact 3.1 (3.x engine accepts classic set)', () => {
    const r = detectWireGuardGeneration({
        'amnezia-wg-option': { jc: 3, h1: 1, h2: 2, h3: 3, h4: 4, 'random-trailers': true }
    });
    assert.equal(r.generation, '3.1');
    assert.equal(r.confidence, 'exact');
});

test('non-discriminating markers only (j1/itime): family awg, generation unknown-ish range 1.x? нет — j1/itime не дают версию', () => {
    const r = detectWireGuardGeneration({ 'amnezia-wg-option': { itime: 30, j1: '<b 0x10>' } });
    assert.equal(r.family, 'awg');
    // j1/itime не входят ни в один доказанный набор поколений — детектор
    // не должен выдать точную версию; допустим range/unknown семейство
    assert.ok(['1.x', '1.5–2.x', null].includes(r.generation), 'generation: ' + r.generation);
    assert.ok(r.evidence.includes('itime') && r.evidence.includes('j1'));
});

test('version: 3 без v3-маркеров → CONFLICT, no invented version', () => {
    const r = detectWireGuardGeneration({ 'amnezia-wg-option': { version: 3, jc: 3 } });
    assert.equal(r.confidence, 'conflict');
    assert.equal(r.generation, null);
    assert.equal(r.label, 'AmneziaWG ?');
    assert.ok(r.conflicts.length >= 1);
});

test('unknown AWG field values never leak into evidence (only marker names)', () => {
    const r = detectWireGuardGeneration({
        'amnezia-wg-option': {
            jc: 3, h1: 111111, h2: 222222, h3: 333333, h4: 444444,
            i1: '<b 0xdeadbeef><rc 10><t>', 'header-protection-key': 'SECRETKEYMATERIAL'
        }
    });
    const flat = JSON.stringify(r.evidence) + JSON.stringify(r.notes) + JSON.stringify(r.conflicts) + r.label;
    assert.ok(!flat.includes('111111') && !flat.includes('222222') && !flat.includes('deadbeef') && !flat.includes('SECRETKEYMATERIAL'), 'no values in evidence: ' + flat);
});

test('deterministic: same input → same detection', () => {
    assert.deepEqual(detectWireGuardGeneration(premium), detectWireGuardGeneration(premium));
});

test('parser integration: parseWireGuardConf output feeds the detector end-to-end', () => {
    const conf = [
        '[Interface]', 'PrivateKey = PRIVATEKEYMATERIAL', 'Address = 10.8.1.2/32',
        'Jc = 4', 'Jmin = 40', 'Jmax = 70', 'S1 = 15', 'S2 = 94', 'H1 = 1234', 'H2 = 2345', 'H3 = 3456', 'H4 = 4567',
        '[Peer]', 'PublicKey = PUBLICKEYMATERIAL', 'AllowedIPs = 0.0.0.0/0', 'Endpoint = 192.0.2.1:51820'
    ].join('\n');
    const bean = parseWireGuardConf(conf, 'classic.conf');
    assert.ok(bean && bean.wireguard, 'parser returns a bean');
    const r = detectWireGuardGeneration(bean);
    assert.equal(r.family, 'awg');
    assert.equal(r.generation, '1.x');
    const flat = JSON.stringify(r);
    assert.ok(!flat.includes('PRIVATEKEYMATERIAL') && !flat.includes('PUBLICKEYMATERIAL'), 'no key material');
});
