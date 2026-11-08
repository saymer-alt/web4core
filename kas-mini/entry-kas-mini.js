// kas-mini: KAS Mini Mihomo Generator — experiment-only entry (issue saymer-alt/keenetic-auto-setup#425, Phase 0).
//
// Glue layer over unchanged web4core main modules:
//   - src/main.js               (URI parsing, validateBean, protocol allowlist)
//   - src/core/mihomo.js        (buildMihomoConfig / buildMihomoSubscriptionConfig)
//   - src/core/yaml.js          (buildMihomoYaml)
//   - src/core/wireguard.js     (parseWireGuardConf)
//
// This file adds ONLY:
//   1. per-line honest URI parsing (no false success on separators/headings),
//   2. native provider mode without fetching and without HWID header,
//   3. WG/AWG .conf refusal layer for fields that web4core would silently drop,
//   4. safe KAS defaults the shared template does not parameterize
//      (allow-lan/bind-address, mixed-port, secret-protected external-controller, TUN mips).
// No network calls, no storage, no UI framework. Browser-only at runtime.

import { buildBeansFromInput, validateBean, getAllowedCoreProtocols } from '../src/main.js';
import { buildMihomoConfig, buildMihomoSubscriptionConfig } from '../src/core/mihomo.js';
import { buildMihomoYaml } from '../src/core/yaml.js';
import { parseWireGuardConf } from '../src/core/wireguard.js';

const MAX_REPORTED_ERRORS = 10;
const WARN_PORTS = new Set([22, 53, 80, 443, 9090]);

// AWG option keys accepted by src/core/wireguard.js (setAwgOpt map, case-insensitive).
const AWG_KEYS = new Set([
    'jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4',
    'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5', 'j1', 'j2', 'j3',
    'itime', 'version', 'headerprotectionkey', 'contentpaddingaddition',
    'rekeyaftertime', 'rekeytimeout', 'rejectaftertime', 'keepalivetimeout',
    'maxhandshakeattempts', 'randomtrailers', 'disablecookies',
]);
// Keys whose value must be boolean-like, otherwise the shared parser drops them silently.
const AWG_BOOLEAN_KEYS = new Set(['randomtrailers', 'disablecookies']);

// wg-quick environment fields: not part of the tunnel data plane, classified as in the
// mature link-generators branch (IGNORED_BY_POLICY) — accepted with a visible warning.
const WG_POLICY_IGNORED = new Set(['listenport', 'table', 'saveconfig', 'preup', 'postup', 'predown', 'postdown', 'fwmark']);

// Fields web4core main parses but does not emit into the Mihomo wireguard proxy
// (verified for both main and link-generators branch): refusing instead of silent loss.
const WG_REFUSED = new Set(['dns']);

// Everything else outside these whitelists is refused as unknown.
const WG_IFACE_KEYS = new Set(['privatekey', 'address', 'mtu', 'name', 'ipstack', 'ipstackmode', 'ipstackcongestioncontroller']);
const WG_PEER_KEYS = new Set(['publickey', 'presharedkey', 'allowedips', 'endpoint', 'persistentkeepalive', 'reserved']);

const MINI_NOTES = [
    'bind-address "*" означает все интерфейсы; доступ извне ограничивается firewall роутера (firewall не меняется автоматически)',
    'external-controller: 0.0.0.0:9090 защищён secret — без него API недоступен; доступ из LAN возможен только с secret, WAN ограничивается firewall роутера',
    'tun.stack: mips требует Mihomo >= 1.19.31; gvisor используется только при явном отключении MIPS-переключателя',
    'URL-подписки становятся нативными proxy-providers и загружаются самим Mihomo после импорта; генератор не обращается к сети',
    'WireGuard/AWG .conf: DNS не переносится в Mihomo proxy — файл с DNS отклоняется целиком (параметр не теряется молча)',
    'результат — ПОЛНАЯ замена config.yaml: существующий импортёр KAS Web (с проверкой/backup/rollback) заменяет текущий конфиг',
];

function redactLine(line) {
    const s = String(line || '').trim();
    const i = s.indexOf('://');
    if (i === -1) return s.length > 24 ? s.slice(0, 21) + '…' : s;
    const scheme = s.slice(0, i);
    return scheme + '://…';
}

function sanitizeMessage(message, line) {
    let out = String(message || '');
    if (line) out = out.split(String(line).trim()).join(redactLine(line));
    return out;
}

function generateSecretHex32() {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function stripConfLine(ln) {
    let s = String(ln || '').trim();
    if (!s) return '';
    const hash = s.indexOf('#');
    const semi = s.indexOf(';');
    const cut = (hash === -1) ? semi : (semi === -1 ? hash : Math.min(hash, semi));
    if (cut !== -1) s = s.slice(0, cut).trim();
    return s;
}

// Pre-scan a WireGuard/AWG .conf and refuse every key that would be silently
// dropped or semantically lost by the shared parser/builder pipeline.
function vetWireGuardConf(confText) {
    const warnings = [];
    const refused = [];
    let section = '';
    for (const rawLine of String(confText || '').split(/\r?\n/)) {
        const ln = stripConfLine(rawLine);
        if (!ln) continue;
        const secMatch = ln.match(/^\[([^\]]+)\]$/);
        if (secMatch) {
            section = (secMatch[1] || '').trim().toLowerCase();
            continue;
        }
        const i = ln.indexOf('=');
        if (i === -1) continue;
        const key = ln.slice(0, i).trim().toLowerCase();
        const value = ln.slice(i + 1).trim();
        if (!key) continue;
        if (WG_POLICY_IGNORED.has(key)) {
            warnings.push({ key: ln.slice(0, i).trim(), reason: 'IGNORED_BY_POLICY', detail: 'поле WireGuard-окружения, не применимое к Mihomo proxy — в YAML не попадает' });
            continue;
        }
        if (WG_REFUSED.has(key)) {
            refused.push({ key: ln.slice(0, i).trim(), reason: 'REFUSED_LOST_FIELD', detail: 'поле разбирается web4core, но не переносится в Mihomo proxy — файл отклонён, чтобы не терять параметр молча' });
            continue;
        }
        if (AWG_BOOLEAN_KEYS.has(key) && !/^(1|true|yes|0|false|no)$/i.test(value)) {
            refused.push({ key: ln.slice(0, i).trim(), reason: 'REFUSED_INVALID_VALUE', detail: 'ожидалось 1/true/yes/0/false/no — иначе значение было бы потеряно' });
            continue;
        }
        if (key === 'mtu' && !/^\d+$/.test(value)) {
            refused.push({ key: ln.slice(0, i).trim(), reason: 'REFUSED_INVALID_VALUE', detail: 'MTU должен быть целым числом — иначе значение было бы потеряно' });
            continue;
        }
        if (key === 'persistentkeepalive' && !/^\d+$/.test(value)) {
            refused.push({ key: ln.slice(0, i).trim(), reason: 'REFUSED_INVALID_VALUE', detail: 'PersistentKeepalive должен быть целым числом (диапазоны AWG не поддерживаются без тестов) — иначе значение было бы потеряно' });
            continue;
        }
        if (AWG_KEYS.has(key)) continue;
        if (section === 'interface' && WG_IFACE_KEYS.has(key)) continue;
        if (section === 'peer' && WG_PEER_KEYS.has(key)) continue;
        refused.push({ key: ln.slice(0, i).trim(), reason: 'REFUSED_UNKNOWN_KEY', detail: 'неизвестное поле — в YAML не попадает' });
    }
    return { warnings, refused };
}

function parseLinksLineByLine(linksText) {
    const beans = [];
    const errors = [];
    let accepted = 0;
    let rejected = 0;
    const lines = String(linksText || '').split(/\r?\n/);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        try {
            const fromLine = buildBeansFromInput(line);
            if (!fromLine.length) {
                // e.g. a JSON-looking line that is not supported in mini mode — no false success.
                rejected++;
                errors.push({ line: redactLine(line), message: 'строка не распознана как ссылка' });
                continue;
            }
            fromLine.forEach(b => validateBean(b));
            const allowed = new Set(getAllowedCoreProtocols('mihomo'));
            for (const b of fromLine) {
                if (!allowed.has(b.proto)) {
                    rejected++;
                    errors.push({ line: redactLine(line), message: `протокол ${b.proto} не поддерживается Mihomo-ядром web4core` });
                    continue;
                }
                beans.push(b);
                accepted++;
            }
        } catch (e) {
            rejected++;
            errors.push({ line: redactLine(line), message: sanitizeMessage(e && e.message, line) });
        }
    }
    return { beans, accepted, rejected, errors };
}

function parseSubscriptionUrls(subText, subEnabled) {
    const urls = [];
    const errors = [];
    const lines = String(subText || '').split(/\r?\n/);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        if (!/^https?:\/\//i.test(line)) {
            errors.push({ line: redactLine(line), message: 'подписка должна быть http(s) URL' });
            continue;
        }
        urls.push(line);
    }
    return { urls, errors, promptNeeded: !subEnabled && urls.length > 0 };
}

function vetWireGuardFiles(files) {
    const acceptedBeans = [];
    const fileReports = [];
    for (const f of (Array.isArray(files) ? files : [])) {
        const name = String((f && f.name) || 'wg.conf');
        const rep = { name, status: 'accepted', warnings: [], refused: [] };
        try {
            const vet = vetWireGuardConf(f && f.text);
            if (vet.refused.length) {
                rep.status = 'refused';
                rep.refused = vet.refused;
                rep.error = { message: `файл отклонён: ${vet.refused.map(r => r.key).join(', ')}` };
                fileReports.push(rep);
                continue;
            }
            rep.warnings = vet.warnings;
            const bean = parseWireGuardConf(f && f.text, name);
            validateBean(bean);
            acceptedBeans.push(bean);
        } catch (e) {
            rep.status = 'error';
            rep.error = { message: sanitizeMessage(e && e.message, null) };
        }
        fileReports.push(rep);
    }
    return { beans: acceptedBeans, fileReports };
}

function validatePort(port) {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
        throw new Error(`недопустимый порт: ${String(port)} — ожидается целое 1–65535`);
    }
    return n;
}

function applyMiniSettings(yaml, settings, warnings) {
    const mixedPort = settings.mixedPort;
    let out = yaml;

    const mixedAnchor = /^mixed-port: 7890$/m;
    if (!mixedAnchor.test(out)) throw new Error('internal: template anchor mixed-port:7890 not found');
    out = out.replace(mixedAnchor, `mixed-port: ${mixedPort}`);
    if (!new RegExp(`^mixed-port: ${mixedPort}$`, 'm').test(out)) {
        throw new Error('internal: mixed-port replacement failed');
    }
    if (WARN_PORTS.has(mixedPort)) {
        warnings.push(`порт ${mixedPort} часто занят другими сервисами роутера (проверьте, что он свободен)`);
    }

    if (settings.allowLan === true) {
        const lanAnchor = /^allow-lan: false$/m;
        if (!lanAnchor.test(out)) throw new Error('internal: template anchor allow-lan:false not found');
        out = out.replace(lanAnchor, 'allow-lan: true\nbind-address: \'*\'');
        if (!/^bind-address: '\*'$/m.test(out)) throw new Error('internal: bind-address injection failed');
    }

    if (settings.webUI === true) {
        const secret = settings.webUISecret;
        if (!/^[0-9a-f]{32,128}$/.test(String(secret || ''))) {
            throw new Error('internal: web UI requires a generated hex secret');
        }
        const anchor = /^ipv6: false$/m;
        if (!anchor.test(out)) throw new Error('internal: template anchor ipv6:false not found');
        const block = [
            'external-controller: 0.0.0.0:9090',
            'external-ui: ui',
            'external-ui-url: https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz',
            `secret: ${secret}`,
        ].join('\n');
        out = out.replace(anchor, `ipv6: false\n${block}`);
        if (!/^external-controller: 0\.0\.0\.0:9090$/m.test(out)) throw new Error('internal: external-controller injection failed');
        if (!/^secret: [0-9a-f]{32,128}$/m.test(out)) throw new Error('internal: secret injection failed');
    }
    return out;
}

function buildMiniMihomoConfig(settings) {
    const s = settings && typeof settings === 'object' ? settings : {};
    const warnings = [];

    const mixedPort = validatePort(s.mixedPort === undefined ? 7890 : s.mixedPort);
    const allowLan = s.allowLan === true;
    const webUI = s.webUI === true;
    let webUISecret = '';
    if (webUI) {
        webUISecret = /^[0-9a-f]{32,128}$/.test(String(s.webUISecret || '')) ? String(s.webUISecret) : generateSecretHex32();
    }
    const tun = s.tun === true;
    const mipsStack = tun && s.mipsStack === true; // subordinate to TUN, per owner table
    const tunStack = !tun ? null : (mipsStack ? 'mips' : 'gvisor');
    const subEnabled = s.subscriptions === true;

    const sub = parseSubscriptionUrls(s.subscriptionUrlsText || '', subEnabled);
    if (sub.promptNeeded) {
        throw new Error('введены URL-подписки, но переключатель «Использовать URL-подписки» выключен — включите его, чтобы URL стали нативными proxy-providers');
    }
    if (sub.errors.length) {
        throw new Error('некорректные URL-подписки: ' + sub.errors[0].message);
    }

    const links = parseLinksLineByLine(s.linksText || '');
    const wg = vetWireGuardFiles(s.wgFiles);
    for (const f of wg.fileReports) {
        if (f.status === 'refused' && f.refused && f.refused.length) {
            warnings.push(`${f.name}: ${f.refused[0].detail}`);
        }
    }

    const allBeans = [...links.beans, ...wg.beans];
    if (!allBeans.length && !sub.urls.length) {
        const detail = [];
        if (links.rejected) detail.push(`ссылок отклонено ${links.rejected}: ${links.errors[0] ? links.errors[0].message : 'без деталей'}`);
        const wgBad = wg.fileReports.filter(f => f.status !== 'accepted');
        if (wgBad.length) detail.push(`WG/AWG файлов отклонено ${wgBad.length}: ${wgBad[0].error ? wgBad[0].error.message : 'без деталей'}`);
        throw new Error('нет валидных узлов' + (detail.length ? ' — ' + detail.join('; ') : ': ни одной распознанной ссылки, WG/AWG-профиля или включённой URL-подписки'));
    }

    let proxies;
    let groups;
    let providers = null;
    let rules;
    let listeners = [];
    if (sub.urls.length) {
        const cfg = buildMihomoSubscriptionConfig(sub.urls, allBeans, {
            addSocks: false,
            perProxyPort: false,
            perProxyListeners: false,
        });
        providers = cfg.providers;
        // No-HWID mode (owner: HWID management deliberately absent in mini).
        for (const name of Object.keys(providers)) delete providers[name].header;
        proxies = cfg.proxies;
        groups = cfg.groups;
        rules = cfg.rules;
        listeners = Array.isArray(cfg.listeners) ? cfg.listeners : [];
    } else {
        const cfg = buildMihomoConfig(allBeans, { addSocks: true });
        proxies = cfg.proxies;
        groups = cfg['proxy-groups'];
        rules = cfg.rules;
        listeners = Array.isArray(cfg.listeners) ? cfg.listeners : [];
    }

    const yaml = buildMihomoYaml(proxies, groups, providers, rules, listeners, {
        addSocks: true,
        webUI: false, // safe block is injected by applyMiniSettings, never the shared empty-secret preset
        tun: tun ? { mode: 'tun', stack: tunStack } : null,
    });
    const finalYaml = applyMiniSettings(yaml, {
        mixedPort,
        allowLan,
        webUI,
        webUISecret,
    }, warnings);

    const linkErrors = links.errors.slice(0, MAX_REPORTED_ERRORS).map(e => ({
        line: e.line,
        message: e.message,
    }));

    return {
        yaml: finalYaml,
        report: {
            nodes: proxies.length,
            links: {
                accepted: links.accepted,
                rejected: links.rejected,
                errors: linkErrors,
                errorsTotal: links.errors.length,
            },
            subscriptions: {
                enabled: subEnabled,
                urls: sub.urls.length,
                providers: providers ? Object.keys(providers) : [],
            },
            wg: {
                accepted: wg.fileReports.filter(f => f.status === 'accepted').length,
                refused: wg.fileReports.filter(f => f.status !== 'accepted').length,
                files: wg.fileReports,
            },
            settings: {
                allowLan,
                mixedPort,
                webUI: { enabled: webUI, generatedSecret: webUI },
                tun: { enabled: tun, stack: tunStack },
            },
            notes: MINI_NOTES,
            warnings,
        },
    };
}

export {
    buildMiniMihomoConfig,
    applyMiniSettings,
    vetWireGuardConf,
    redactLine,
    MINI_NOTES,
    AWG_KEYS,
    WG_REFUSED,
    WG_POLICY_IGNORED,
};
