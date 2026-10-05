// NIGHT-06: WG/AWG value semantics — no-silent-drop контракт.
// Точные результаты парсинга по каждому полю + типы в итоговом YAML.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseWireGuardConf } from '../../src/core/wireguard.js';
import { buildMihomoProxy } from '../../src/core/mihomo.js';

const base = (extra, peerExtra) => [
    '[Interface]',
    'PrivateKey = CkGOZHbIxJvSSWWGFlHpNkGt0HhRIcKbmTIrmA9TcHk=',
    'Address = 10.0.0.2/32',
    ...extra,
    '[Peer]',
    'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
    'AllowedIPs = 0.0.0.0/0',
    'Endpoint = 198.51.100.10:51820',
    ...peerExtra,
].filter(Boolean).join('\n');

const reportOf = (bean, key) => (bean.awgFieldReport || []).find(r => r.key === key);

// --- PersistentKeepalive (PHASE 3–5) ---
test('PK = 25: SUPPORTED, emitted as number', () => {
    const bean = parseWireGuardConf(base([], ['PersistentKeepalive = 25']), 'a.conf');
    assert.equal(bean.wireguard.persistentKeepalive, 25);
    assert.equal(bean.awgFieldReport.find(r => r.key === 'persistent-keepalive').status, 'SUPPORTED');
    const p = buildMihomoProxy(bean, new Set());
    assert.equal(p['persistent-keepalive'], 25);
    assert.equal(typeof p['persistent-keepalive'], 'number', 'число, не строка');
});

test('PK = 0: SUPPORTED_NORMALIZED (0 = disabled), не эмитится — семантика Mihomo', () => {
    const bean = parseWireGuardConf(base([], ['PersistentKeepalive = 0']), 'a.conf');
    assert.equal(bean.wireguard.persistentKeepalive, 0);
    const rep = bean.awgFieldReport.find(r => r.key === 'persistent-keepalive');
    assert.equal(rep.status, 'SUPPORTED_NORMALIZED');
    assert.match(rep.note, /отключ/);
    const p = buildMihomoProxy(bean, new Set());
    assert.equal(p['persistent-keepalive'], undefined, '0 = disabled, Mihomo сам опускает поле');
});

test('PK отсутствует: missing, без диагностик по PK', () => {
    const bean = parseWireGuardConf(base([], []), 'a.conf');
    assert.equal(bean.wireguard.persistentKeepalive, undefined);
    assert.equal(bean.awgFieldReport.find(r => r.key === 'persistent-keepalive'), undefined);
    assert.equal(bean.wireguard.persistentKeepaliveRaw, undefined);
});

test('PK = 25-35: UNSUPPORTED, raw сохранён, поле НЕ эмитится (no auto-conversion)', () => {
    const bean = parseWireGuardConf(base([], ['PersistentKeepalive = 25-35']), 'a.conf');
    assert.equal(bean.wireguard.persistentKeepalive, undefined, 'значение не эмитится');
    assert.equal(bean.wireguard.persistentKeepaliveRaw, '25-35', 'raw-факт сохранён');
    const rep = bean.awgFieldReport.find(r => r.key === 'persistent-keepalive');
    assert.equal(rep.status, 'UNSUPPORTED');
    assert.equal(rep.rawValue, '25-35');
    const p = buildMihomoProxy(bean, new Set());
    assert.equal(p['persistent-keepalive'], undefined);
});

test('PK = foo: INVALID', () => {
    const bean = parseWireGuardConf(base([], ['PersistentKeepalive = foo']), 'a.conf');
    assert.equal(bean.wireguard.persistentKeepalive, undefined);
    assert.equal(bean.awgFieldReport.find(r => r.key === 'persistent-keepalive').status, 'INVALID');
});

// --- числовые AWG-поля (PHASE 7) ---
test('Jc = 400: SUPPORTED uint', () => {
    const bean = parseWireGuardConf(base(['Jc = 400'], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option'].jc, 400);
    assert.equal(bean.awgFieldReport.find(r => r.key === 'jc').status, 'SUPPORTED');
});

test('Jc = 123abc: strict parse, stored raw + INVALID (не 123)', () => {
    const bean = parseWireGuardConf(base(['Jc = 123abc'], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option'].jc, '123abc', 'raw сохранён');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'jc').status, 'INVALID');
    const p = buildMihomoProxy(bean, new Set());
    assert.equal((p['amnezia-wg-option'] || {}).jc, undefined, 'INVALID значение не эмитится');
});

test('Jc = -5 и переполнение uint32: INVALID', () => {
    for (const bad of ['-5', '4294967296']) {
        const bean = parseWireGuardConf(base(['Jc = ' + bad], []), 'a.conf');
        assert.equal(bean.awgFieldReport.find(r => r.key === 'jc').status, 'INVALID', 'Jc = ' + bad);
    }
});

test('H1 = диапазон/строка: lossless string pass-through', () => {
    const bean = parseWireGuardConf(base(['H1 = 5-10'], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option'].h1, '5-10');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'h1').status, 'SUPPORTED');
});

test('ITime = 86400: SUPPORTED (int64-допустимый диапазон не ограничен uint32)', () => {
    const bean = parseWireGuardConf(base(['ITime = 86400'], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option'].itime, 86400);
    assert.equal(bean.awgFieldReport.find(r => r.key === 'itime').status, 'SUPPORTED');
});

// --- булевы (PHASE 8) ---
test('RandomTrailers = 1/true/yes: SUPPORTED boolean', () => {
    for (const v of ['1', 'true', 'yes']) {
        const bean = parseWireGuardConf(base(['RandomTrailers = ' + v, 'Version = 3'], []), 'a.conf');
        assert.equal(bean.wireguard['amnezia-wg-option']['random-trailers'], true, v);
        const p = buildMihomoProxy(bean, new Set());
        assert.equal(p['amnezia-wg-option']['random-trailers'], true, 'boolean в YAML, не строка');
    }
});

test('RandomTrailers = on/off: raw parser НЕ знает on/off (consumer нормализует), значение не теряется как UNSUPPORTED', () => {
    const bean = parseWireGuardConf(base(['RandomTrailers = on', 'Version = 3'], []), 'a.conf');
    const rep = bean.awgFieldReport.find(r => r.key === 'random-trailers');
    assert.equal(rep.status, 'UNSUPPORTED');
    assert.equal(rep.rawValue, 'on');
});

test('RandomTrailers = maybe: UNSUPPORTED, raw сохранён, не эмитится', () => {
    const bean = parseWireGuardConf(base(['RandomTrailers = maybe', 'Version = 3'], []), 'a.conf');
    const rep = bean.awgFieldReport.find(r => r.key === 'random-trailers');
    assert.equal(rep.status, 'UNSUPPORTED');
    assert.equal(bean.wireguard['amnezia-wg-option']['random-trailers'], 'maybe', 'fidelity в бине');
    const p = buildMihomoProxy(bean, new Set());
    assert.equal(p['amnezia-wg-option']['random-trailers'], undefined, 'INVALID/UNSUPPORTED не эмитится');
});

// --- duration-поля (PHASE 6) ---
test('RekeyAfterTime = 100-120: SUPPORTED (uint range, секунды)', () => {
    const bean = parseWireGuardConf(base(['RekeyAfterTime = 100-120'], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option']['rekey-after-time'], '100-120');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'rekey-after-time').status, 'SUPPORTED');
});

test('RekeyAfterTime = 86400: SUPPORTED (одиночное значение)', () => {
    const bean = parseWireGuardConf(base(['RekeyAfterTime = 86400'], []), 'a.conf');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'rekey-after-time').status, 'SUPPORTED');
});

test('RekeyAfterTime = 15s: INVALID (Go-duration не входит в контракт v3 ranges)', () => {
    const bean = parseWireGuardConf(base(['RekeyAfterTime = 15s'], []), 'a.conf');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'rekey-after-time').status, 'INVALID');
});

// --- строковые/ключевые поля (PHASE 9) ---
test('HeaderProtectionKey: trim only, значение не логируется и не искажается', () => {
    const bean = parseWireGuardConf(base(['HeaderProtectionKey =   IM0hW5Q5a62YuAB2OydZPgu/7ai6tRqpaeT0K9O4+XY=  '], []), 'a.conf');
    assert.equal(bean.wireguard['amnezia-wg-option']['header-protection-key'], 'IM0hW5Q5a62YuAB2OydZPgu/7ai6tRqpaeT0K9O4+XY=');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'header-protection-key').status, 'SUPPORTED');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'header-protection-key').rawValue, '(present)', 'в отчёте значение НЕ логируется');
});

// --- ContentPaddingAddition (PHASE 10) ---
test('CPA = 10-100 и CPA = 5: SUPPORTED (строковый контракт v3)', () => {
    for (const v of ['10-100', '5']) {
        const bean = parseWireGuardConf(base(['ContentPaddingAddition = ' + v], []), 'a.conf');
        assert.equal(bean.wireguard['amnezia-wg-option']['content-padding-addition'], v);
        assert.equal(bean.awgFieldReport.find(r => r.key === 'content-padding-addition').status, 'SUPPORTED');
    }
});

test('CPA = abc: INVALID (не silent)', () => {
    const bean = parseWireGuardConf(base(['ContentPaddingAddition = abc'], []), 'a.conf');
    assert.equal(bean.awgFieldReport.find(r => r.key === 'content-padding-addition').status, 'INVALID');
});

// --- неизвестные поля (PHASE 11) ---
test('Unknown AWG-поле: UNKNOWN diagnostic, в YAML не попадает', () => {
    const bean = parseWireGuardConf(base(['SomeFutureOption = 42'], []), 'a.conf');
    const rep = bean.awgFieldReport.find(r => r.key.toLowerCase() === 'somefutureoption');
    assert.ok(rep, 'unknown поле задокументировано');
    assert.equal(rep.status, 'UNKNOWN');
});

test('Known non-AWG WireGuard-окружение (Table/PostUp): IGNORED_BY_POLICY', () => {
    const bean = parseWireGuardConf(base(['PostUp = echo hi', 'Table = off'], []), 'a.conf');
    assert.ok((bean.awgFieldReport || []).some(r => r.status === 'IGNORED_BY_POLICY' && r.key === 'PostUp'));
    assert.ok((bean.awgFieldReport || []).some(r => r.status === 'IGNORED_BY_POLICY' && r.key === 'Table'));
});

// --- сериализация (PHASE 20) ---
test('serialization: jc number, random-trailers boolean, rekey-after-time string', () => {
    const bean = parseWireGuardConf(base([
        'Jc = 4',
        'RandomTrailers = 1',
        'RekeyAfterTime = 100-120',
        'Version = 3',
    ], []), 'a.conf');
    const p = buildMihomoProxy(bean, new Set());
    const awg = p['amnezia-wg-option'];
    assert.equal(typeof awg.jc, 'number');
    assert.equal(typeof awg['random-trailers'], 'boolean');
    assert.equal(typeof awg['rekey-after-time'], 'string');
});
