import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

// Synthetic TEST-NET fixtures only; no real keys, hosts or subscription tokens.
const base = 'vless://00000000-0000-0000-0000-000000000000@192.0.2.10:443?encryption=none&security=reality&pbk=TESTPBK&sid=00ff&fp=chrome&spx=%2F';

const build = link => buildFromRequest({
    core: 'mihomo',
    input: link,
    options: { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false },
}).data;

test('REALITY support-x25519mlkem768 is a per-link opt-in flag (upstream passthrough)', () => {
    assert.match(build(`${base}&support-x25519mlkem768=true#ON`), /support-x25519mlkem768: true/);
    assert.match(build(`${base}&support-x25519mlkem768=1#ON-NUM`), /support-x25519mlkem768: true/);
    assert.match(build(`${base}&support-x25519mlkem768=false#OFF`), /support-x25519mlkem768: false/);
});

test('REALITY links without the flag emit no mlkem key; garbage values are ignored, not thrown', () => {
    const plain = build(`${base}#PLAIN`);
    assert.doesNotMatch(plain, /support-x25519mlkem768/);
    assert.doesNotMatch(build(`${base}&support-x25519mlkem768=banana#GARBAGE`), /support-x25519mlkem768/);
});

test('pqv stays Xray-only: mihomo output never emits it', () => {
    const yaml = build(`${base}&pqv=TESTPQVVALUE#PQV`);
    assert.match(yaml, /type: vless/);
    assert.doesNotMatch(yaml, /pqv/);
});

test('dedup keeps mlkem variants apart and still collapses identical links', () => {
    const two = build(`${base}&support-x25519mlkem768=true#A\n${base}&support-x25519mlkem768=false#B`);
    assert.equal((two.match(/support-x25519mlkem768: true/g) || []).length, 1);
    assert.equal((two.match(/support-x25519mlkem768: false/g) || []).length, 1);
    const same = build(`${base}#A\n${base}#B`);
    assert.equal((same.match(/type: vless/g) || []).length, 1);
});

test('trojan links accept the same flag', () => {
    const trojan = `trojan://pass@192.0.2.11:443?security=reality&pbk=TESTPBK&sid=00ff&spx=%2F&support-x25519mlkem768=true#T`;
    assert.match(build(trojan), /support-x25519mlkem768: true/);
});

test('pqv remains a Xray mldsa65Verify feature end to end', () => {
    const pqv = Buffer.alloc(1952, 7).toString('base64url');
    const opts = { addTun: false, addSocks: true, webUI: false };
    const xray = JSON.stringify(buildFromRequest({ core: 'xray', input: `${base}&pqv=${pqv}#XRAY`, options: opts }).data);
    assert.match(xray, /mldsa65Verify/);
    assert.ok(xray.includes(pqv), 'pqv value carried into xray config');
    assert.throws(() => buildFromRequest({
        core: 'xray',
        input: `${base}&pqv=tooshort#BAD`,
        options: opts,
    }), /pqv is invalid/);
});

