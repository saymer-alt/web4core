import { parseAddrHostPort } from '../main.js';

function parseWireGuardConf(confText, nameHint) {
    const text = String(confText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');
    let section = '';
    const iface = {};
    const peers = [];
    let curPeer = null;

    const cleanLine = (ln) => {
        let s = (ln || '').trim();
        if (!s) return '';
        const hash = s.indexOf('#');
        const semi = s.indexOf(';');
        const cut = (hash === -1) ? semi : (semi === -1 ? hash : Math.min(hash, semi));
        if (cut !== -1) s = s.slice(0, cut).trim();
        return s;
    };
    const splitKV = (ln) => {
        const i = ln.indexOf('=');
        if (i === -1) return null;
        const k = ln.slice(0, i).trim();
        const v = ln.slice(i + 1).trim();
        if (!k) return null;
        return {k, v};
    };
    const parseCsv = (v) => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
    const parseAddrList = (v) => parseCsv(v).map(x => x.replace(/\s+/g, '')).filter(Boolean);

    const setAwgOpt = (target, key, value) => {
        const k = String(key || '').trim().toLowerCase();
        const map = {
            jc: 'jc',
            jmin: 'jmin',
            jmax: 'jmax',
            s1: 's1',
            s2: 's2',
            s3: 's3',
            s4: 's4',
            h1: 'h1',
            h2: 'h2',
            h3: 'h3',
            h4: 'h4',
            i1: 'i1',
            i2: 'i2',
            i3: 'i3',
            i4: 'i4',
            i5: 'i5',
            j1: 'j1',
            j2: 'j2',
            j3: 'j3',
            itime: 'itime',
            version: 'version',
            headerprotectionkey: 'header-protection-key',
            contentpaddingaddition: 'content-padding-addition',
            rekeyaftertime: 'rekey-after-time',
            rekeytimeout: 'rekey-timeout',
            rejectaftertime: 'reject-after-time',
            keepalivetimeout: 'keepalive-timeout',
            maxhandshakeattempts: 'max-handshake-attempts',
            randomtrailers: 'random-trailers',
            disablecookies: 'disable-cookies',
        };
        if (!map[k]) return false;
        if (!target['amnezia-wg-option']) target['amnezia-wg-option'] = {};
        const outKey = map[k];
        const raw = String(value || '').trim();
        const numericKeys = new Set(['version', 'jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'itime']);
        const booleanKeys = new Set(['random-trailers', 'disable-cookies']);
        if (numericKeys.has(outKey) && /^-?\d+$/.test(raw)) {
            target['amnezia-wg-option'][outKey] = parseInt(raw, 10);
        } else if (booleanKeys.has(outKey)) {
            const boolValue = raw.toLowerCase();
            if (!['1', 'true', 'yes', '0', 'false', 'no'].includes(boolValue)) return false;
            target['amnezia-wg-option'][outKey] = ['1', 'true', 'yes'].includes(boolValue);
        } else {
            target['amnezia-wg-option'][outKey] = raw;
        }
        return true;
    };

    const parseReserved = (v) => {
        const s = String(v || '').trim();
        if (!s) return undefined;
        if (s.includes(',')) {
            const parts = parseCsv(s);
            const nums = parts
                .map(x => (/^\d+$/.test(x) ? parseInt(x, 10) : NaN))
                .filter(n => Number.isInteger(n) && n >= 0 && n <= 255);
            return nums.length ? nums : undefined;
        }
        return s;
    };

    for (const rawLine of lines) {
        const ln = cleanLine(rawLine);
        if (!ln) continue;
        const secMatch = ln.match(/^\[([^\]]+)\]$/);
        if (secMatch) {
            section = (secMatch[1] || '').trim().toLowerCase();
            if (section === 'peer') {
                curPeer = {};
                peers.push(curPeer);
            } else {
                curPeer = null;
            }
            continue;
        }
        const kv = splitKV(ln);
        if (!kv) continue;
        const key = kv.k.trim();
        const value = kv.v;
        const keyLower = key.toLowerCase();

        if (setAwgOpt(iface, key, value)) continue;

        if (section === 'interface') {
            if (keyLower === 'privatekey') iface.privateKey = value;
            else if (keyLower === 'address') iface.addresses = parseAddrList(value);
            else if (keyLower === 'dns') iface.dns = parseCsv(value);
            else if (keyLower === 'mtu') iface.mtu = /^\d+$/.test(value) ? parseInt(value, 10) : undefined;
            else if (keyLower === 'name') iface.name = value;
            else if (keyLower === 'ipstack' || keyLower === 'ipstackmode') {
                if (!iface.ipStack) iface.ipStack = {};
                iface.ipStack.mode = value;
            } else if (keyLower === 'ipstackcongestioncontroller') {
                if (!iface.ipStack) iface.ipStack = {};
                iface.ipStack['congestion-controller'] = value;
            }
        } else if (section === 'peer' && curPeer) {
            if (keyLower === 'publickey') curPeer.publicKey = value;
            else if (keyLower === 'presharedkey') curPeer.preSharedKey = value;
            else if (keyLower === 'allowedips') curPeer.allowedIPs = parseAddrList(value);
            else if (keyLower === 'endpoint') curPeer.endpoint = value;
            else if (keyLower === 'persistentkeepalive') curPeer.persistentKeepalive = /^\d+$/.test(value) ? parseInt(value, 10) : undefined;
            else if (keyLower === 'reserved') {
                curPeer.reserved = parseReserved(value);
            } else {
                setAwgOpt(iface, key, value);
            }
        }
    }

    const chosenPeer = peers[0] || {};
    const {host, port} = parseAddrHostPort(chosenPeer.endpoint || '', 51820);
    const addrs = Array.isArray(iface.addresses) ? iface.addresses : [];
    const ipv4Raw = addrs.find(a => /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/.test(a));
    const ipv6Raw = addrs.find(a => /:/.test(a));
    const ipv4 = ipv4Raw ? ipv4Raw.split('/')[0] : '';
    const ipv6 = ipv6Raw ? ipv6Raw.split('/')[0] : '';

    const nameBase = (iface.name || nameHint || 'WireGuard').toString().trim();
    const name = nameBase ? nameBase.replace(/\.(conf|wg|awg)$/i, '') : 'WireGuard';

    const wgPeers = peers.map(p => {
        const ap = parseAddrHostPort(p.endpoint || '', 51820);
        return {
            server: ap.host,
            port: ap.port,
            publicKey: p.publicKey || '',
            preSharedKey: p.preSharedKey || '',
            allowedIPs: Array.isArray(p.allowedIPs) ? p.allowedIPs : [],
            reserved: p.reserved
        };
    }).filter(p => p.server && p.port);

    const keepalive = peers.map(p => p.persistentKeepalive).find(v => Number.isFinite(v));

    const hasIpv6 = !!ipv6;
    const peer0 = wgPeers[0] || {};
    const allowed0 = Array.isArray(peer0.allowedIPs) ? peer0.allowedIPs.slice() : [];
    const allowedFiltered0 = hasIpv6 ? allowed0 : allowed0.filter(x => !String(x || '').includes(':'));
    const peersFiltered = wgPeers.map(peer => {
        const a = Array.isArray(peer.allowedIPs) ? peer.allowedIPs : [];
        const allowedFiltered = hasIpv6 ? a : a.filter(x => !String(x || '').includes(':'));
        return Object.assign({}, peer, {allowedIPs: allowedFiltered});
    });

    const bean = {
        proto: 'wireguard',
        name,
        host: peer0.server || host,
        port: peer0.port || port,
        ipVersion: hasIpv6 ? '' : 'ipv4',
        wireguard: {
            ip: ipv4 || '',
            ipv6: ipv6 || '',
            addresses: Array.isArray(iface.addresses) ? iface.addresses.slice() : [],
            privateKey: iface.privateKey || '',
            publicKey: peer0.publicKey || (chosenPeer.publicKey || ''),
            preSharedKey: peer0.preSharedKey || (chosenPeer.preSharedKey || ''),
            allowedIPs: allowedFiltered0.length ? allowedFiltered0 : (chosenPeer.allowedIPs || []),
            reserved: peer0.reserved !== undefined ? peer0.reserved : chosenPeer.reserved,
            peers: peersFiltered.length >= 2 ? peersFiltered : undefined,
            dns: Array.isArray(iface.dns) && iface.dns.length ? iface.dns : [],
            remoteDnsResolve: Array.isArray(iface.dns) && iface.dns.length ? true : false,
            ipStack: (iface.ipStack && typeof iface.ipStack === 'object') ? iface.ipStack : undefined,
            mtu: iface.mtu,
            persistentKeepalive: keepalive
        }
    };
    if (iface['amnezia-wg-option']) {
        bean.wireguard['amnezia-wg-option'] = iface['amnezia-wg-option'];
    }
    return bean;
}

// IPv4-only contract (link-generators v1.8.0): нормализация выполняется на
// build-слое, парсер остаётся faithful к исходному файлу. Убирается только IPv6:
// interface-адрес ::, allowed-ips с ':' (включая ::/0), поле ipv6. IPv4 не трогается.
function isIpv6AddrEntry(entry) {
    return String(entry || '').includes(':');
}

function normalizeWireGuardIpv4Only(wg) {
    const src = wg && typeof wg === 'object' ? wg : {};
    const allowedIPs = Array.isArray(src.allowedIPs)
        ? src.allowedIPs.filter(x => !isIpv6AddrEntry(x))
        : src.allowedIPs;
    const peers = Array.isArray(src.peers)
        ? src.peers.map(peer => {
            if (!peer || typeof peer !== 'object') return peer;
            const filtered = Array.isArray(peer.allowedIPs) ? peer.allowedIPs.filter(x => !isIpv6AddrEntry(x)) : peer.allowedIPs;
            return Object.assign({}, peer, { allowedIPs: filtered });
        })
        : src.peers;
    const dns = Array.isArray(src.dns) ? src.dns.filter(x => !isIpv6AddrEntry(x)) : src.dns;
    const removed = {
        addresses: isIpv6AddrEntry(src.ipv6) ? 1 : 0,
        allowedIps: (Array.isArray(src.allowedIPs) ? src.allowedIPs.filter(x => isIpv6AddrEntry(x)).length : 0)
            + (Array.isArray(src.peers) ? src.peers.reduce((acc, peer) => acc + (Array.isArray(peer && peer.allowedIPs) ? peer.allowedIPs.filter(x => isIpv6AddrEntry(x)).length : 0), 0) : 0),
        dns: (Array.isArray(src.dns) ? src.dns.filter(x => isIpv6AddrEntry(x)).length : 0),
    };
    return {
        ip: src.ip || '',
        ipv6: '', // contract: IPv6 interface address never emitted
        allowedIPs,
        peers,
        dns,
        removed,
        ipv6Removed: removed.addresses + removed.allowedIps + removed.dns > 0,
        ipv6RemovedCount: removed.addresses + removed.allowedIps + removed.dns,
    };
}

// Жёсткая часть IPv4-only контракта: то, что не может быть «мягко отфильтровано».
// Возвращает { ok, reason } — emitter обязан reject-ить профиль при !ok.
function validateWireGuardIpv4Only(bean) {
    const wg = bean && bean.wireguard && typeof bean.wireguard === 'object' ? bean.wireguard : {};
    const norm = normalizeWireGuardIpv4Only(wg);
    if (!norm.ip) {
        return {
            ok: false,
            code: 'WG_IPV6_ONLY_ADDRESS',
            reason: 'wireguard: profile has only an IPv6 interface address; link-generators emits IPv4-only WireGuard and requires an IPv4 Address',
        };
    }
    const isV6 = (s) => String(s || '').includes(':');
    if (isV6(bean.host)) {
        return {
            ok: false,
            code: 'WG_IPV6_ENDPOINT',
            reason: 'wireguard: IPv6 literal endpoint "' + bean.host + '" is not allowed in IPv4-only output; use an IPv4 endpoint or a hostname',
        };
    }
    const peers = Array.isArray(norm.peers) ? norm.peers : [];
    const v6Peer = peers.findIndex(p => p && isV6(p.server));
    if (v6Peer !== -1) {
        return {
            ok: false,
            code: 'WG_IPV6_ENDPOINT',
            reason: 'wireguard: peer #' + (v6Peer + 1) + ' has an IPv6 literal endpoint; IPv4-only output requires IPv4 endpoints or hostnames',
        };
    }
    return { ok: true, code: null, reason: null };
}

// Размер (в байтах) I-tag последовательности AmneziaWG. Синтаксис тегов
// воспроизводит device_v1/awg (v1.5) и device/obf* (v3) amneziawg-go:
//   <b 0xHEX> — hex-байты; <r N>/<rc N>/<rd N> — N случайных байт/ASCII/цифр;
//   <t> — 8-байтовый timestamp; <c> — 8-байтовый счётчик;
//   <wt N>/<wr N> — wait-теги, байт не добавляют; <d>/<ds>/<dz N> — data-теги v3.
// Возвращает { size, unknown: [теги] } — точный размер, если все теги известны.
function computeAmneziaTagJunkSize(spec) {
    const input = String(spec || '');
    const tags = input.match(/<[^<>]*>/g) || [];
    let size = 0;
    const unknown = [];
    for (const raw of tags) {
        const m = raw.slice(1, -1).match(/^([a-zA-Z]+)(?:\s+(.*?))?$/);
        if (!m) { unknown.push(raw); continue; }
        const tag = m[1];
        const param = (m[2] || '').trim();
        const n = /^\d+$/.test(param) ? parseInt(param, 10) : null;
        if (tag === 'b') {
            const hex = param.replace(/^0x/i, '').replace(/\s+/g, '');
            size += /^[0-9a-fA-F]+$/.test(hex) ? Math.floor(hex.length / 2) : 0;
            if (!/^[0-9a-fA-F]+$/.test(hex)) unknown.push(raw);
        } else if ((tag === 'r' || tag === 'rc' || tag === 'rd') && n !== null) {
            size += n;
        } else if (tag === 't' || tag === 'c') {
            size += (n !== null && n > 0) ? n : 8;
        } else if (tag === 'wt' || tag === 'wr' || tag === 'd' || tag === 'ds') {
            // wait-теги и data-теги байт в пакет не добавляют
        } else if (tag === 'dz' && n !== null) {
            size += n;
        } else {
            unknown.push(raw);
        }
    }
    if (!tags.length) unknown.push(input);
    return { size, unknown };
}

// Диагностика профиля WG/AWG для UI: imported/effective MTU, следы IPv6-нормализации
// и классификация AWG-параметров. Только чтение; effectiveMtu в v1.8.0 НИКОГДА не
// больше importedMtu (auto-change не выполняется — см. ROADMAP про PoC-гейт).
// Default 1408 — source-pinned: MetaCubeX/mihomo adapter/outbound/wireguard.go
// (`if mtu == 0 { mtu = 1408 }`), теги v1.19.31 == v1.19.32.
function analyzeWireGuardProfile(bean) {
    const wg = bean && bean.wireguard && typeof bean.wireguard === 'object' ? bean.wireguard : {};
    const norm = normalizeWireGuardIpv4Only(wg);
    const importedMtu = Number.isFinite(wg.mtu) && wg.mtu > 0 ? wg.mtu : null;
    const notes = [];
    const awg = wg['amnezia-wg-option'] && typeof wg['amnezia-wg-option'] === 'object' ? wg['amnezia-wg-option'] : {};
    const num = v => (Number.isFinite(v) ? v : (/^\d+$/.test(String(v || '')) ? parseInt(v, 10) : null));

    if (norm.ipv6Removed) {
        notes.push({ level: 'info', text: 'IPv6 detected in imported WG/AWG profile. Removed by link-generators IPv4-only contract.' });
    }
    if (importedMtu === null) {
        notes.push({ level: 'info', text: 'MTU в конфиге не задан — Mihomo применит default 1408.' });
    }

    const s4 = num(awg.s4);
    if (s4 !== null && s4 > 0) {
        notes.push({ level: 'info', text: 'AWG S4 = ' + s4 + ': junk добавляется к каждому transport-пакету (пер-пакетный overhead).' });
    }
    const cpRaw = String(awg['content-padding-addition'] || '').trim();
    if (cpRaw) {
        const range = cpRaw.match(/^(\d+)-(\d+)$/);
        const maxPad = range ? parseInt(range[2], 10) : num(cpRaw);
        if (maxPad !== null && maxPad > 0) {
            notes.push({ level: 'info', text: 'AWG ContentPaddingAddition = ' + cpRaw + ': пер-пакетный padding, worst-case +' + maxPad + ' байт учтён в диагностике.' });
        } else {
            notes.push({ level: 'warn', text: 'AWG ContentPaddingAddition="' + cpRaw + '": формат не распознан, точный overhead не вычислить.' });
        }
    }
    if (awg['random-trailers'] === true) {
        notes.push({ level: 'warn', text: 'AWG RandomTrailers включён: случайные хвосты ограничены внутренним окном реализации (DefaultUdpWindow=500 в amneziawg-go), строгая верхняя граница из конфига не выводится.' });
    }
    const jmax = num(awg.jmax);
    const jc = num(awg.jc);
    if (jc !== null && jc > 0 && jmax !== null && jmax > 1408) {
        notes.push({ level: 'warn', text: 'AWG Jmax = ' + jmax + ' превышает default transport-бюджет 1408: junk-пакеты отдельные и могут фрагментироваться на path MTU.' });
    }
    const iSizes = [];
    for (const key of ['i1', 'i2', 'i3', 'i4', 'i5']) {
        const spec = awg[key];
        if (!spec) continue;
        const calc = computeAmneziaTagJunkSize(spec);
        iSizes.push({ key: key.toUpperCase(), size: calc.unknown.length ? null : calc.size, unknown: calc.unknown });
    }
    for (const i of iSizes) {
        if (i.size === null) {
            notes.push({ level: 'warn', text: 'AWG ' + i.key + ': не все теги распознаны, размер signature-пакета не вычислить точно.' });
        } else if (i.size > 1408) {
            notes.push({ level: 'warn', text: 'AWG ' + i.key + ' = ' + i.size + ' B превышает default transport-бюджет 1408: signature-пакет отдельный и может фрагментироваться.' });
        } else if (i.size > 0) {
            notes.push({ level: 'info', text: 'AWG ' + i.key + ': signature-пакет ' + i.size + ' B (отдельный, при handshake).' });
        }
    }
    const handshakeOnly = ['s1', 's2', 's3'].filter(k => num(awg[k]) > 0);
    if (handshakeOnly.length) {
        notes.push({ level: 'info', text: 'AWG ' + handshakeOnly.map(k => k.toUpperCase()).join('/') + ': junk только в handshake-пакетах, на transport MTU не влияет.' });
    }
    const headerTags = ['h1', 'h2', 'h3', 'h4'].filter(k => awg[k] !== undefined && awg[k] !== '');
    if (headerTags.length) {
        notes.push({ level: 'info', text: 'AWG ' + headerTags.map(k => k.toUpperCase()).join('/') + ': заменяют тип сообщения (байты), длину пакетов не меняют.' });
    }

    return {
        importedMtu,
        effectiveMtu: importedMtu, // v1.8.0: auto-correction не выполняется (PoC-гейт не пройден)
        mtuSource: importedMtu !== null ? 'imported' : 'engine-default',
        engineDefaultMtu: 1408,
        ipv6Removed: norm.ipv6Removed,
        ipv6RemovedCount: norm.ipv6RemovedCount,
        removed: norm.removed,
        ipv6OnlyAddress: !norm.ip,
        ipv6LiteralEndpoints: [
            ...(isIpv6AddrEntry(bean.host) ? ['primary'] : []),
            ...((Array.isArray(norm.peers) ? norm.peers : []).map((p, i) => (p && isIpv6AddrEntry(p.server) ? 'peer #' + (i + 1) : null)).filter(Boolean)),
        ],
        notes,
        awg: {
            version: awg.version !== undefined ? awg.version : null,
            s4: s4 !== null ? s4 : 0,
            contentPaddingAddition: cpRaw || null,
            randomTrailers: awg['random-trailers'] === true,
            junkPacketCount: jc !== null ? jc : 0,
            junkPacketMaxSize: jmax !== null ? jmax : 0,
            iSizes
        }
    };
}

// MTU chain planner — ТОЛЬКО диагностика (v1.8.0). НИКОГДА не меняет YAML/mtu:
// auto-MTU остаётся выключенным, пока mipstack runtime и live-crypto PoC не
// докажут модель на реальных стеках (NIGHT-02: PARTIALLY PROVEN, gVisor path).
// Модель (NIGHT-02/03, IPv4): каждый уровень вложения добавляет
// 32 (WG hdr+tag) + S4 + CPA-max|align(15) к inner-пакету, а транспорт
// через dialer добавляет inner IP+UDP = 28. Направление расчёта: outermost → inner.
// Стеки без строгой верхней границы overhead (RandomTrailers) и цепочки,
// упирающиеся в не-WG/AWG dialer, получают confidence unknown/stopped —
// потолок не выдаётся вовсе.
function planWireGuardMtu(doc) {
    const proxies = (doc && Array.isArray(doc.proxies))
        ? doc.proxies.filter(p => p && p.type === 'wireguard' && p.name)
        : [];
    const byName = new Map(proxies.map(p => [p.name, p]));
    const profiles = proxies.map(p => {
        const awg = p['amnezia-wg-option'] && typeof p['amnezia-wg-option'] === 'object' ? p['amnezia-wg-option'] : {};
        const num = v => (Number.isFinite(v) ? v : (/^\d+$/.test(String(v ?? '')) ? parseInt(v, 10) : null));
        const cpaRaw = String(awg['content-padding-addition'] || '').trim();
        const cpaRange = cpaRaw.match(/^(\d+)-(\d+)$/);
        return {
            name: p.name,
            dialer: typeof p['dialer-proxy'] === 'string' && p['dialer-proxy'].trim() ? p['dialer-proxy'].trim() : null,
            importedMtu: Number.isFinite(p.mtu) && p.mtu > 0 ? p.mtu : null,
            s4: num(awg.s4) || 0,
            cpaMin: cpaRange ? parseInt(cpaRange[1], 10) : (num(cpaRaw) !== null ? num(cpaRaw) : null),
            cpaMax: cpaRange ? parseInt(cpaRange[2], 10) : (num(cpaRaw) !== null ? num(cpaRaw) : null),
            cpaSet: !!cpaRaw,
            rt: awg['random-trailers'] === true,
        };
    });
    const byProfile = new Map(profiles.map(p => [p.name, p]));
    const PRACTICAL_MIN = 576; // практичный минимум inner IPv4 MTU (RFC 791 min 68; 576 — sanity-уровень)

    const memo = new Map();
    const visiting = new Set();
    function plan(name) {
        if (memo.has(name)) return memo.get(name);
        if (visiting.has(name)) {
            const r = { name, confidence: 'cycle', ceiling: null, effective: null, reason: ['цикл dialer-proxy — считается authoritative cycle detection при сборке'] };
            memo.set(name, r);
            return r;
        }
        visiting.add(name);
        const pr = byProfile.get(name);
        const r = { name, chain: [name], confidence: 'proven', ceiling: null, effective: null, overhead: null, reason: [] };
        if (!pr) {
            r.confidence = 'unknown';
            r.reason.push('профиль не найден в конфиге');
            memo.set(name, r);
            return r;
        }
        r.importedMtu = pr.importedMtu;
        const cpaMinB = pr.cpaSet ? (pr.cpaMin ?? 0) : 0;
        // per-hop worst-case = 32 (WG hdr+tag) + 15 (align) + 28 (inner IP/UDP) = 75,
        // плюс S4/CPA-max как пер-пакетные байты. Align считается РОВНО ОДИН РАЗ.
        let ovhMax;
        if (pr.cpaSet) {
            ovhMax = pr.s4 + (pr.cpaMax ?? 0);
        } else if (pr.rt) {
            ovhMax = null; // RandomTrailers: граница не выводится из конфига
        } else {
            ovhMax = pr.s4;
        }
        r.overhead = {
            min: 32 + pr.s4 + cpaMinB,
            max: 32 + (ovhMax !== null ? ovhMax + 15 : null),
            deterministic: pr.cpaSet || !pr.rt,
        };
        const dialer = pr.dialer;
        if (!dialer) {
            r.reason.push('outermost: транспорт — физический интерфейс');
            r.effective = pr.importedMtu !== null ? pr.importedMtu : 1408; // 1408 — Mihomo default (source-pinned)
            r.mtuSource = pr.importedMtu !== null ? 'imported' : 'engine-default';
        } else if (!byProfile.has(dialer)) {
            r.confidence = 'stopped';
            r.reason.push('MTU chain analysis stops at non-WG/AWG dialer target «' + dialer + '»');
            r.effective = pr.importedMtu;
        } else {
            const outer = plan(dialer);
            r.chain = [name].concat(outer.chain || []);
            if (outer.confidence !== 'proven' || outer.effective === null || ovhMax === null) {
                r.confidence = outer.confidence !== 'proven' ? outer.confidence : 'unknown';
                r.effective = pr.importedMtu;
                if (ovhMax === null) r.reason.push('AWG RandomTrailers: строгая верхняя граница overhead не выводится из конфига — расчёт остановлен, исходный MTU сохранён');
                if (outer.confidence !== 'proven') {
                    r.reason.push('внешний hop «' + dialer + '» не имеет доказанного бюджета');
                    (outer.reason || []).forEach(rs => r.reason.push('↳ ' + rs)); // проброс причин (в т.ч. ниже-минимум)
                }
            } else {
                // worst-case IPv4: inner_A + align(15) + 32 + S4 + CPA-max + 28 (inner IP+UDP) ≤ MTU_B
                r.ceiling = outer.effective - (32 + (ovhMax !== null ? ovhMax : 15) + 15 + 28);
                if (r.ceiling < PRACTICAL_MIN) {
                    r.confidence = 'error';
                    r.effective = pr.importedMtu;
                    r.reason.push('цепочка требует MTU ' + r.ceiling + ' — ниже практичного минимума ' + PRACTICAL_MIN);
                } else {
                    r.effective = pr.importedMtu !== null ? Math.min(pr.importedMtu, r.ceiling) : r.ceiling;
                    r.mtuSource = 'planned-ceiling';
                    r.reason.push('dialer-proxy: ' + dialer, 'outer effective MTU: ' + outer.effective, 'IPv4 worst-case per hop: 60 (32 + align 15 + inner IP/UDP 28)');
                }
            }
        }
        visiting.delete(name);
        memo.set(name, r);
        return r;
    }
    const out = profiles.map(p => plan(p.name));
    return { profiles: out, note: 'diagnostics-only: YAML/mtu не изменяются' };
}

export {
    parseWireGuardConf,
    normalizeWireGuardIpv4Only,
    validateWireGuardIpv4Only,
    computeAmneziaTagJunkSize,
    analyzeWireGuardProfile,
    planWireGuardMtu,
};
