import { computeTag, validateBean, PROXY_FETCH_INTERVAL, SUB_REFRESH_INTERVAL, resolveUrlTest, resolveUrlTestExpectedStatus, generateSecretHex32 } from '../main.js';
import { normalizeWireGuardIpv4Only, validateWireGuardIpv4Only } from './wireguard.js';

const FASTEST_GROUP_NAME = '⚡ Fastest';
const GLOBAL_GROUP_NAME = 'GLOBAL';
const PER_PROXY_GROUP_PREFIX = '🔒 ';
// Per-proxy listeners remove the ⚡ Fastest url-test group, which was the only
// actor health-checking static proxies (providers self-check). This hidden
// checker restores alive/history for static leaves without appearing in GLOBAL
// or the dashboard; listeners keep targeting the 🔒 wrapper groups.
const STATIC_HEALTH_GROUP_NAME = '🌐 static-health';
// Dial-failure detection for the unattended primary/fallback GLOBAL: mihomo
// only triggers the forced health check after max-failed-times dial failures
// within `timeout` ms ("connection refused" triggers immediately). With the
// 5000ms default the counter resets between sparse user dials, so a blackhole
// primary stays "alive" until the next scheduled provider check. 2 failures
// within 60s were verified to switch over on mihomo v1.19.31.
const FALLBACK_DIAL_FAILURE_WINDOW_MS = 60000;
const FALLBACK_MAX_DIAL_FAILURES = 2;

function getPerProxyGroupName(proxyName) {
    return `${PER_PROXY_GROUP_PREFIX}${proxyName}`;
}

function uniqueTargets(...parts) {
    const out = [];
    const seen = new Set();
    parts.flat().forEach((item) => {
        const name = String(item || '').trim();
        if (!name || seen.has(name)) return;
        seen.add(name);
        out.push(name);
    });
    return out;
}

function getUrlTest(opts) {
    return resolveUrlTest(opts?.urlTest);
}

function getUrlTestExpectedStatus(opts) {
    return resolveUrlTestExpectedStatus(opts?.urlTest);
}

function sanitizeProviderName(name) {
    const raw = String(name || '').trim().toLowerCase();
    if (!raw) return '';
    const cleaned = raw
        .replace(/^www\./, '')
        .replace(/[^a-z0-9._-]+/g, '-')
        .replace(/[._-]{2,}/g, '-')
        .replace(/^[._-]+|[._-]+$/g, '');
    return cleaned.slice(0, 48);
}

function computeProviderName(url, index, total, used) {
    let base = '';
    try {
        const u = new URL(String(url || '').trim());
        base = sanitizeProviderName(u.hostname || '');
    } catch {
    }
    if (!base) {
        base = total === 1 ? 'my_subscription' : `subscription_${index + 1}`;
    }
    let name = base;
    let i = 2;
    while (used.has(name)) {
        name = `${base}-${i++}`;
    }
    used.add(name);
    return name;
}

function isPerProxyListenerMode(opts) {
    return !!(opts && (opts.perProxyPort || opts.perProxyListeners));
}

function attachPerProxySelectGroup(groups, proxy) {
    const groupName = getPerProxyGroupName(proxy.name);
    groups.push({
        name: groupName,
        type: 'select',
        proxies: [proxy.name, 'REJECT']
    });
    return groupName;
}

function assignSafeProxyNames(proxies, reservedNames = []) {
    const reserved = new Set(reservedNames.map(name => String(name || '').trim()).filter(Boolean));
    const used = new Set();
    for (const proxy of proxies) {
        const base = String(proxy?.name || 'proxy').trim() || 'proxy';
        let name = base;
        let i = 2;
        while (used.has(name) || reserved.has(name)) {
            name = base + '-' + i++;
        }
        proxy.name = name;
        used.add(name);
    }
    return proxies;
}

// === Domain Policy Routing (DPR, Variant B) ===
// User policies [{name, domains}] become inline classical rule-providers +
// category proxy-groups + RULE-SET rules. Rules reference stable policy GROUPS;
// groups reach the subscription nodes via use: on the provider — so the paid
// provider may add/rename/remove servers freely and the rules never need
// regeneration (contract live-verified on mihomo v1.19.31/v1.19.32, PoC 2026-10-01).
// Nesting contract (issue #2588): url-test AUTO groups are only ever referenced
// from select groups, never placed inside fallback.
const DOMAIN_POLICY_RESERVED_NAMES = new Set([
    GLOBAL_GROUP_NAME,
    FASTEST_GROUP_NAME,
    STATIC_HEALTH_GROUP_NAME,
    'DIRECT',
    'REJECT',
    'REJECT-DROP',
    'PASS',
    'COMPATIBLE',
]);
const DOMAIN_POLICY_RULE_TYPES = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX', 'GEOSITE', 'IP-CIDR', 'IP-CIDR6']);
const DOMAIN_POLICY_HOSTNAME_RE = /^(\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i;
const DOMAIN_IPV4_CIDR_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function normalizeDomainPolicyCidr(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const slash = raw.indexOf('/');
    const addr = (slash === -1 ? raw : raw.slice(0, slash)).trim().toLowerCase();
    const prefixRaw = slash === -1 ? '' : raw.slice(slash + 1).trim();
    const prefix = prefixRaw === '' ? undefined : Number(prefixRaw);
    if (prefix !== undefined && (!Number.isInteger(prefix) || prefix < 0)) return '';
    if (DOMAIN_IPV4_CIDR_RE.test(addr)) {
        const octets = addr.split('.').map(Number);
        if (octets.some(o => o > 255)) return '';
        if (prefix !== undefined && prefix > 32) return '';
        return `${addr}/${prefix === undefined ? 32 : prefix}`;
    }
    if (addr.includes(':') && /^[0-9a-f:]+$/i.test(addr) && (addr.match(/::/g) || []).length <= 1) {
        if (prefix !== undefined && prefix > 128) return '';
        return `${addr}/${prefix === undefined ? 128 : prefix}`;
    }
    return '';
}

function parseDomainPolicyLine(raw) {
    const line = String(raw || '').trim();
    if (!line || line.startsWith('#')) return { skip: true };
    const comma = line.indexOf(',');
    if (comma !== -1) {
        const type = line.slice(0, comma).trim().toUpperCase();
        const value = line.slice(comma + 1).trim();
        if (DOMAIN_POLICY_RULE_TYPES.has(type)) {
            if (type === 'IP-CIDR' || type === 'IP-CIDR6') {
                // A trailing ,no-resolve is legal in pasted mihomo rules
                // (MagiTrickle import emits it) and the engine re-adds it
                // unconditionally; other options (src) change semantics and
                // are not stripped.
                const cidr = normalizeDomainPolicyCidr(value.replace(/,\s*no-resolve\s*$/i, ''));
                if (!cidr) return { invalid: line };
                return { rule: `IP-CIDR,${cidr},no-resolve` };
            }
            if (type === 'GEOSITE') {
                if (!/^[a-z0-9!@._-]+$/i.test(value)) return { invalid: line };
                return { rule: `GEOSITE,${value}` };
            }
            if (type === 'DOMAIN-KEYWORD' || type === 'DOMAIN-REGEX') {
                // keywords/regex are not hostnames: accept any sane charset
                if (!value || !/^[a-z0-9._*?+|^$()\[\]{}\\-]+$/i.test(value)) return { invalid: line };
                return { rule: `${type},${value}` };
            }
            if (type === 'DOMAIN-WILDCARD') {
                // Mihomo DOMAIN-WILDCARD: * and ? are wildcards anywhere in
                // the pattern. Real MagiTrickle exports use patterns like
                // yt*.ggpht.com / *.rutracker.* that are not hostnames, so
                // wildcard values get charset validation instead of the
                // hostname regex below.
                if (!value || !/^[a-z0-9_*?][a-z0-9_*?.-]*$/i.test(value) || !/[a-z0-9]/i.test(value) || value.includes('..')) return { invalid: line };
                return { rule: `DOMAIN-WILDCARD,${value.toLowerCase()}` };
            }
            if (!value || !DOMAIN_POLICY_HOSTNAME_RE.test(value)) return { invalid: line };
            return { rule: `${type},${value.toLowerCase()}` };
        }
        return { invalid: line };
    }
    const cidr = normalizeDomainPolicyCidr(line);
    if (cidr) return { rule: `IP-CIDR,${cidr},no-resolve` };
        // Bare wildcard patterns: a leading '*.' is legacy DOMAIN-SUFFIX,
        // but any other * / ? placement (MT-style 'yt*.ggpht.com',
        // '*.rutracker.*') is DOMAIN-WILDCARD, not a broken DOMAIN-SUFFIX.
        if (/[*?]/.test(line.slice(2))) {
            if (/^[a-z0-9_*?][a-z0-9_*?.-]*$/i.test(line) && /[a-z0-9]/i.test(line) && !line.includes('..')) {
                return { rule: `DOMAIN-WILDCARD,${line.toLowerCase()}` };
            }
            return { invalid: line };
        }
    if (!DOMAIN_POLICY_HOSTNAME_RE.test(line)) return { invalid: line };
    return { rule: `DOMAIN-SUFFIX,${line.toLowerCase().replace(/^\*\./, '')}` };
}

function domainPolicySlug(name, index, used) {
    let base = String(name).trim().toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 32);
    if (!base) base = `n${index + 1}`;
    let slug = `policy-${base}`;
    let i = 2;
    while (used.has(slug)) slug = `policy-${base}-${i++}`;
    used.add(slug);
    return slug;
}

function buildDomainPolicyArtifacts(policies, ctx) {
    const warnings = [];
    const ruleProviders = {};
    const groups = [];
    const rules = [];
    const usedSlugs = new Set();
    const existingGroups = new Set(ctx.existingGroupNames || []);
    policies.forEach((policy, index) => {
        const name = String(policy?.name || '').trim();
        if (DOMAIN_POLICY_RESERVED_NAMES.has(name)) {
            throw new Error(`Mihomo: domain policy name "${name}" is reserved`);
        }
        if (existingGroups.has(name)) {
            throw new Error(`Mihomo: domain policy name "${name}" conflicts with an existing group`);
        }
        const lines = Array.isArray(policy.domains) ? policy.domains : String(policy.domains || '').split(/\r?\n/);
        const seen = new Set();
        const payload = [];
        lines.forEach((raw) => {
            const parsed = parseDomainPolicyLine(raw);
            if (parsed.skip) return;
            if (parsed.invalid) {
                warnings.push(`Политика «${name}»: строка «${parsed.invalid}» не распознана и пропущена`);
                return;
            }
            if (!seen.has(parsed.rule)) {
                seen.add(parsed.rule);
                payload.push(parsed.rule);
            }
        });
        if (!payload.length) {
            warnings.push(`Политика «${name}»: нет ни одного корректного домена — политика пропущена`);
            return;
        }
        const slug = domainPolicySlug(name, index, usedSlugs);
        ruleProviders[slug] = { type: 'inline', behavior: 'classical', format: 'yaml', payload };
        // Policy rule target (DPR v2): SELECT keeps the legacy per-policy
        // category group; GLOBAL/DIRECT/REJECT point the whole policy rule
        // at the builtin target without creating any group.
        const rawTarget = String(policy?.target || '').trim().toUpperCase();
        // Engine-level strictness: direct callers (tests/tools) bypass the
        // upstream normalization, so an unknown target must not silently
        // degrade to legacy SELECT semantics.
        if (rawTarget !== '' && rawTarget !== 'SELECT' && rawTarget !== 'GLOBAL' && rawTarget !== 'DIRECT' && rawTarget !== 'REJECT') {
            throw new Error(`Mihomo: domain policy target must be SELECT, GLOBAL, DIRECT or REJECT: "${rawTarget}"`);
        }
        const ruleTarget = rawTarget === 'GLOBAL' || rawTarget === 'DIRECT' || rawTarget === 'REJECT' ? rawTarget : 'SELECT';
        if (ruleTarget === 'SELECT') {
            rules.push(`RULE-SET,${slug},${name}`);
        } else {
            rules.push(`RULE-SET,${slug},${ruleTarget}`);
        }
        if (ruleTarget === 'SELECT') {
        if (ctx.mode === 'subscription') {
            groups.push({
                name: `${name}-AUTO`,
                type: 'url-test',
                use: ctx.providerNames.slice(),
                url: ctx.urlTest,
                interval: PROXY_FETCH_INTERVAL,
                tolerance: 50,
                'expected-status': ctx.urlTestExpectedStatus,
                'empty-fallback': 'REJECT'
            });
            groups.push({
                name,
                type: 'select',
                // ⚡ Fastest is referenced only when it is actually emitted
                // (a single-static config emits no Fastest group; referencing
                // it would produce a dangling group target).
                proxies: [`${name}-AUTO`, ...(existingGroups.has(FASTEST_GROUP_NAME) ? [FASTEST_GROUP_NAME] : []), GLOBAL_GROUP_NAME, 'DIRECT']
            });
            existingGroups.add(`${name}-AUTO`);
        } else if (ctx.mode === 'static') {
            groups.push({
                name,
                type: 'select',
                // ⚡ Fastest is referenced only when it is actually emitted (see above).
                proxies: [...(existingGroups.has(FASTEST_GROUP_NAME) ? [FASTEST_GROUP_NAME] : []), GLOBAL_GROUP_NAME, 'DIRECT']
            });
        } else {
            // AUTO-WHITELIST priority mode: the allowed chain is
            // RULE-SET → policy select → GLOBAL → existing flat fallback.
            groups.push({
                name,
                type: 'select',
                proxies: [GLOBAL_GROUP_NAME, 'DIRECT']
            });
        }
        existingGroups.add(name);
        } // end ruleTarget === 'SELECT' (non-SELECT targets emit no category group)
    });
    return { ruleProviders, groups, rules, warnings };
}

function getDomainPolicyPolicies(opts) {
    const policies = (opts && Array.isArray(opts.domainPolicy)) ? opts.domainPolicy : [];
    if (policies.length && isPerProxyListenerMode(opts)) {
        throw new Error('Mihomo: domain policy routing does not support per-proxy listeners');
    }
    return policies;
}

function buildMihomoProxy(bean) {
    const s = bean.stream || {};
    const base = { name: bean.name || computeTag(bean, new Set()), type: '', server: bean.host, port: bean.port };
    const applyCommon = (obj) => {
        if (bean.udp === true) obj.udp = true;
        if (bean.udpOverTcp === true) obj['udp-over-tcp'] = true;
        if (bean.ipVersion) obj['ip-version'] = bean.ipVersion;
    };
    const applyTls = (obj) => {
        if (s.security === 'tls') {
            obj.tls = true;
            if (s.sni) {
                obj.servername = s.sni;
                if (bean.proto === 'http' || bean.proto === 'tuic' || bean.proto === 'hy2' || bean.proto === 'trojan') {
                    obj.sni = s.sni;
                }
            }
            if (s.alpn && s.alpn.length) obj.alpn = s.alpn;
            if (s.allowInsecure) obj['skip-cert-verify'] = true;
            if (s.fp) obj['client-fingerprint'] = s.fp;
            if (s.reality && s.reality.pbk) {
                const ro = { 'public-key': s.reality.pbk };
                if (s.reality.sid) ro['short-id'] = s.reality.sid;
                if (s.reality.spx) ro['spider-x'] = s.reality.spx;
                if (typeof s.reality.supportX25519MLKEM768 === 'boolean') {
                    ro['support-x25519mlkem768'] = s.reality.supportX25519MLKEM768;
                }
                obj['reality-opts'] = ro;
            }
        }
    };
    const applyPacketEncoding = (obj) => {
        const packetEncoding = String(s.packet_encoding || '').trim().toLowerCase();
        if (packetEncoding === 'none') return;
        if (packetEncoding === 'packet') obj['packet-addr'] = true;
        else obj.xudp = true;
    };
    const applyNetwork = (obj) => {
        if (s.network === 'ws') {
            obj.network = 'ws';
            obj['ws-opts'] = {};
            if (s.path) obj['ws-opts'].path = s.path;
            if (s.host) obj['ws-opts'].headers = { Host: s.host };
            if (s.wsEarlyData && s.wsEarlyData.max_early_data) {
                obj['ws-opts']['max-early-data'] = s.wsEarlyData.max_early_data;
                if (s.wsEarlyData.early_data_header_name) obj['ws-opts']['early-data-header-name'] = s.wsEarlyData.early_data_header_name;
            }
        } else if (s.network === 'http') {
            obj.network = 'http';
            obj['http-opts'] = {};
            if (s.path) obj['http-opts'].path = [s.path];
            if (s.host) obj['http-opts'].host = s.host.split(',').map(x => x.trim()).filter(Boolean);
        } else if (s.network === 'h2') {
            obj.network = 'h2';
            obj['h2-opts'] = {};
            if (s.path) obj['h2-opts'].path = s.path;
            if (s.host) obj['h2-opts'].host = s.host.split(',').map(x => x.trim()).filter(Boolean);
        } else if (s.network === 'grpc') {
            obj.network = 'grpc';
            obj['grpc-opts'] = {};
            if (s.path) obj['grpc-opts']['grpc-service-name'] = s.path;
            if (s.grpcUserAgent) obj['grpc-opts']['grpc-user-agent'] = s.grpcUserAgent;
            if (Number.isFinite(s.grpcPingInterval) && s.grpcPingInterval > 0) {
                obj['grpc-opts']['ping-interval'] = s.grpcPingInterval;
            }
            if (Number.isFinite(s.grpcMaxConnections) && s.grpcMaxConnections > 0) {
                obj['grpc-opts']['max-connections'] = s.grpcMaxConnections;
            }
            if (Number.isFinite(s.grpcMinStreams) && s.grpcMinStreams >= 0) {
                obj['grpc-opts']['min-streams'] = s.grpcMinStreams;
            }
            if (Number.isFinite(s.grpcMaxStreams) && s.grpcMaxStreams >= 0) {
                obj['grpc-opts']['max-streams'] = s.grpcMaxStreams;
            }
        } else if (s.network === 'xhttp') {
            obj.network = 'xhttp';
            obj['xhttp-opts'] = {};
            if (s.path) obj['xhttp-opts'].path = s.path;
            if (s.host) obj['xhttp-opts'].host = s.host;
            if (s.xhttpMode) obj['xhttp-opts'].mode = s.xhttpMode;
            else obj['xhttp-opts'].mode = 'auto';
            obj['xhttp-opts']['x-padding-bytes'] = s.xhttpXPaddingBytes || '100-1000';

            if (s.xhttpNoGrpcHeader === true) obj['xhttp-opts']['no-grpc-header'] = true;
            if (s.xhttpNoSseHeader === true) obj['xhttp-opts']['no-sse-header'] = true;
            if (typeof s.xhttpXPaddingObfsMode === 'boolean') obj['xhttp-opts']['x-padding-obfs-mode'] = s.xhttpXPaddingObfsMode;
            if (s.xhttpXPaddingKey) obj['xhttp-opts']['x-padding-key'] = s.xhttpXPaddingKey;
            if (s.xhttpXPaddingHeader) obj['xhttp-opts']['x-padding-header'] = s.xhttpXPaddingHeader;
            if (s.xhttpXPaddingPlacement) obj['xhttp-opts']['x-padding-placement'] = s.xhttpXPaddingPlacement;
            if (s.xhttpXPaddingMethod) obj['xhttp-opts']['x-padding-method'] = s.xhttpXPaddingMethod;
            if (s.xhttpUplinkHttpMethod) obj['xhttp-opts']['uplink-http-method'] = s.xhttpUplinkHttpMethod;
            if (s.xhttpSessionPlacement) obj['xhttp-opts']['session-placement'] = s.xhttpSessionPlacement;
            if (s.xhttpSessionKey) obj['xhttp-opts']['session-key'] = s.xhttpSessionKey;
            if (s.xhttpSessionTable) obj['xhttp-opts']['session-table'] = s.xhttpSessionTable;
            if (Number.isFinite(s.xhttpSessionLength) && s.xhttpSessionLength > 0) {
                obj['xhttp-opts']['session-length'] = s.xhttpSessionLength;
            }
            if (s.xhttpSeqPlacement) obj['xhttp-opts']['seq-placement'] = s.xhttpSeqPlacement;
            if (s.xhttpSeqKey) obj['xhttp-opts']['seq-key'] = s.xhttpSeqKey;
            if (s.xhttpUplinkDataPlacement) obj['xhttp-opts']['uplink-data-placement'] = s.xhttpUplinkDataPlacement;
            if (s.xhttpUplinkDataKey) obj['xhttp-opts']['uplink-data-key'] = s.xhttpUplinkDataKey;
            if (Number.isFinite(s.xhttpUplinkChunkSize) && s.xhttpUplinkChunkSize > 0) {
                obj['xhttp-opts']['uplink-chunk-size'] = s.xhttpUplinkChunkSize;
            }

            if (s.xhttpScMaxEachPostBytes !== '' && s.xhttpScMaxEachPostBytes !== undefined) {
                obj['xhttp-opts']['sc-max-each-post-bytes'] = s.xhttpScMaxEachPostBytes;
            }
            if (Number.isFinite(s.xhttpScMaxBufferedPosts) && s.xhttpScMaxBufferedPosts > 0) {
                obj['xhttp-opts']['sc-max-buffered-posts'] = s.xhttpScMaxBufferedPosts;
            }
            if (s.xhttpScMinPostsIntervalMs !== '' && s.xhttpScMinPostsIntervalMs !== undefined) {
                obj['xhttp-opts']['sc-min-posts-interval-ms'] = s.xhttpScMinPostsIntervalMs;
            }
            if (s.xhttpScStreamUpServerSecs !== '' && s.xhttpScStreamUpServerSecs !== undefined) {
                obj['xhttp-opts']['sc-stream-up-server-secs'] = s.xhttpScStreamUpServerSecs;
            }
            if (Number.isFinite(s.xhttpServerMaxHeaderBytes) && s.xhttpServerMaxHeaderBytes > 0) {
                obj['xhttp-opts']['server-max-header-bytes'] = s.xhttpServerMaxHeaderBytes;
            }

            const xmux = s.xhttpXmux || {};
            const reuseSettings = {};
            if (xmux.max_connections) reuseSettings['max-connections'] = xmux.max_connections;
            if (xmux.max_concurrency) reuseSettings['max-concurrency'] = xmux.max_concurrency;
            if (xmux.c_max_reuse_times) reuseSettings['c-max-reuse-times'] = xmux.c_max_reuse_times;
            if (xmux.h_max_request_times) reuseSettings['h-max-request-times'] = xmux.h_max_request_times;
            if (xmux.h_max_reusable_secs) reuseSettings['h-max-reusable-secs'] = xmux.h_max_reusable_secs;
            if (xmux.h_keep_alive_period) reuseSettings['h-keep-alive-period'] = xmux.h_keep_alive_period;
            if (Object.keys(reuseSettings).length) {
                obj['xhttp-opts']['reuse-settings'] = reuseSettings;
            }

            const download = s.xhttpDownload || {};
            const hasDownload = [
                download.mode,
                download.host,
                download.path,
                download.x_padding_bytes,
                download.sc_max_each_post_bytes,
                download.sc_min_posts_interval_ms,
                download.sc_stream_up_server_secs,
                download.sc_max_buffered_posts,
                download.server_max_header_bytes,
                download.no_sse_header,
                download.server,
                download.server_port,
                download.security,
                download.servername,
                download.client_fingerprint,
                download.alpn,
                download.skip_cert_verify,
                download.detour,
                download.headers
            ].some((v) => {
                if (!v) return false;
                if (typeof v === 'object') return Object.keys(v).length > 0;
                return true;
            }) || Object.values(download.xmux || {}).some(v => v !== '' && v !== 0) ||
                (download.reality && typeof download.reality === 'object' &&
                    Object.values(download.reality).some((v) => String(v || '').trim() !== ''));
            if (hasDownload) {
                obj['xhttp-opts']['download-settings'] = {};
                if (download.mode) obj['xhttp-opts']['download-settings'].mode = download.mode;
                if (download.host) obj['xhttp-opts']['download-settings'].host = download.host;
                if (download.path) obj['xhttp-opts']['download-settings'].path = download.path;
                if (download.headers && typeof download.headers === 'object' && Object.keys(download.headers).length) {
                    obj['xhttp-opts']['download-settings'].headers = download.headers;
                }
                if (download.x_padding_bytes) obj['xhttp-opts']['download-settings']['x-padding-bytes'] = download.x_padding_bytes;
                if (download.no_sse_header === true || download.no_sse_header === 'true' || download.no_sse_header === '1') {
                    obj['xhttp-opts']['download-settings']['no-sse-header'] = true;
                }
                if (download.sc_max_each_post_bytes) {
                    obj['xhttp-opts']['download-settings']['sc-max-each-post-bytes'] = download.sc_max_each_post_bytes;
                }
                if (download.sc_min_posts_interval_ms) {
                    obj['xhttp-opts']['download-settings']['sc-min-posts-interval-ms'] = download.sc_min_posts_interval_ms;
                }
                if (download.sc_stream_up_server_secs) {
                    obj['xhttp-opts']['download-settings']['sc-stream-up-server-secs'] = download.sc_stream_up_server_secs;
                }
                if (download.sc_max_buffered_posts) {
                    obj['xhttp-opts']['download-settings']['sc-max-buffered-posts'] = download.sc_max_buffered_posts;
                }
                if (download.server_max_header_bytes) {
                    obj['xhttp-opts']['download-settings']['server-max-header-bytes'] = download.server_max_header_bytes;
                }
                if (download.server) obj['xhttp-opts']['download-settings'].server = download.server;
                if (download.server_port) obj['xhttp-opts']['download-settings'].port = download.server_port;

                const downloadSecurity = String(download.security || '').toLowerCase();
                if (downloadSecurity === 'tls' || downloadSecurity === 'reality') {
                    obj['xhttp-opts']['download-settings'].tls = true;
                    if (download.servername) obj['xhttp-opts']['download-settings'].servername = download.servername;
                    if (download.client_fingerprint) obj['xhttp-opts']['download-settings']['client-fingerprint'] = download.client_fingerprint;
                    if (Array.isArray(download.alpn) && download.alpn.length) obj['xhttp-opts']['download-settings'].alpn = download.alpn;
                    if (download.skip_cert_verify === true) obj['xhttp-opts']['download-settings']['skip-cert-verify'] = true;
                    if (downloadSecurity === 'reality') {
                        const realitySource = download.reality || {};
                        const publicKey = realitySource.pbk || realitySource.public_key || '';
                        const shortID = realitySource.sid || realitySource.short_id || '';
                        const realityOpts = {};
                        if (publicKey) realityOpts['public-key'] = publicKey;
                        if (shortID) realityOpts['short-id'] = shortID;
                        if (Object.keys(realityOpts).length) obj['xhttp-opts']['download-settings']['reality-opts'] = realityOpts;
                    }
                }

                const dx = download.xmux || {};
                const downloadReuseSettings = {};
                if (dx.max_connections) downloadReuseSettings['max-connections'] = dx.max_connections;
                if (dx.max_concurrency) downloadReuseSettings['max-concurrency'] = dx.max_concurrency;
                if (dx.c_max_reuse_times) downloadReuseSettings['c-max-reuse-times'] = dx.c_max_reuse_times;
                if (dx.h_max_request_times) downloadReuseSettings['h-max-request-times'] = dx.h_max_request_times;
                if (dx.h_max_reusable_secs) downloadReuseSettings['h-max-reusable-secs'] = dx.h_max_reusable_secs;
                if (dx.h_keep_alive_period) downloadReuseSettings['h-keep-alive-period'] = dx.h_keep_alive_period;
                if (Object.keys(downloadReuseSettings).length) {
                    obj['xhttp-opts']['download-settings']['reuse-settings'] = downloadReuseSettings;
                }
            }
        } else if (s.network === 'httpupgrade') {
            obj.network = 'httpupgrade';
            obj['ws-opts'] = {};
            if (s.path) obj['ws-opts'].path = s.path;
            if (s.host) obj['ws-opts'].headers = { Host: s.host };
            if (s.wsEarlyData && s.wsEarlyData.max_early_data) {
                obj['ws-opts']['v2ray-http-upgrade-fast-open'] = true;
                if (s.wsEarlyData.early_data_header_name) obj['ws-opts']['early-data-header-name'] = s.wsEarlyData.early_data_header_name;
            }
        } else if (s.network === 'tcp' && s.headerType === 'http') {
            obj.network = 'tcp';
            const httpOpts = {};
            if (s.path) {
                httpOpts.path = [s.path].filter(Boolean);
            }
            if (s.host) {
                httpOpts.headers = {
                    Host: Array.isArray(s.host) ? s.host : [s.host]
                };
            }
            obj['http-opts'] = httpOpts;
        } else {
            obj.network = 'tcp';
        }
    };
    if (bean.proto === 'vmess') {
        const p = { ...base, type: 'vmess', uuid: bean.auth.uuid, cipher: bean.auth.security || 'auto', alterId: 0 };
        applyTls(p);
        applyNetwork(p);
        applyPacketEncoding(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'vless') {
        const p = { ...base, type: 'vless', uuid: bean.auth.uuid, encryption: 'none' };
        if (bean.auth.flow) p.flow = bean.auth.flow;
        if (bean.auth.flow && bean.auth.flow.includes('vision')) {
            p.udp = true;
        }
        applyTls(p);
        applyNetwork(p);
        applyPacketEncoding(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'trojan') {
        const p = { ...base, type: 'trojan', password: bean.auth.password };
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'ss') {
        const p = { ...base, type: 'ss', cipher: bean.ss.method, password: bean.ss.password };
        if (bean.ss.plugin) {
            p.plugin = bean.ss.plugin;
            if (bean.ss.pluginOpts && typeof bean.ss.pluginOpts === 'object') {
                p['plugin-opts'] = bean.ss.pluginOpts;
            }
        }
        if (bean.ss.smux && bean.ss.smux.enabled) {
            p.smux = bean.ss.smux;
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'http') {
        const p = { ...base, type: 'http' };
        if (bean.socks?.username) p.username = bean.socks.username;
        if (bean.socks?.password) p.password = bean.socks.password;
        applyTls(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'socks') {
        if (bean.socks?.type === 'socks4') {
            throw new Error('Mihomo does not support: socks4');
        }
        const p = { ...base, type: 'socks5' };
        if (bean.socks?.username) p.username = bean.socks.username;
        if (bean.socks?.password) p.password = bean.socks.password;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'hy2') {
        const p = { ...base, type: 'hysteria2', password: bean.auth.password };
        if (bean.hysteria2?.alpn) p.alpn = bean.hysteria2.alpn.split(',').filter(Boolean);
        if (bean.hysteria2?.sni) p.sni = bean.hysteria2.sni;
        if (bean.hysteria2?.allowInsecure) p['skip-cert-verify'] = true;
        if (bean.hysteria2?.obfs) p.obfs = bean.hysteria2.obfs;
        if (bean.hysteria2?.obfsPassword) {
            if (!p.obfs) p.obfs = 'salamander';
            p['obfs-password'] = bean.hysteria2.obfsPassword;
        }
        if (Number.isFinite(bean.hysteria2?.obfsMinPacketSize) && bean.hysteria2.obfsMinPacketSize > 0) {
            p['obfs-min-packet-size'] = bean.hysteria2.obfsMinPacketSize;
        }
        if (Number.isFinite(bean.hysteria2?.obfsMaxPacketSize) && bean.hysteria2.obfsMaxPacketSize > 0) {
            p['obfs-max-packet-size'] = bean.hysteria2.obfsMaxPacketSize;
        }
        if (bean.hysteria2?.hopPort) p.ports = String(bean.hysteria2.hopPort).trim();
        if (bean.hysteria2?.hopInterval) {
            const hi = String(bean.hysteria2.hopInterval).trim();
            const range = hi.match(/^(\d+)\s*-\s*(\d+)$/);
            if (range && range[1] && range[2]) {
                p['hop-interval'] = `${range[1]}-${range[2]}`;
            } else {
                const m = hi.match(/^(\d+)/);
                if (m && m[1]) {
                    p['hop-interval'] = parseInt(m[1], 10);
                }
            }
        }
        if (bean.hysteria2?.bbrProfile) p['bbr-profile'] = bean.hysteria2.bbrProfile;
        if (Number.isFinite(bean.hysteria2?.udpMtu) && bean.hysteria2.udpMtu > 0) p['udp-mtu'] = bean.hysteria2.udpMtu;
        if (Number.isFinite(bean.hysteria2?.handshakeTimeout) && bean.hysteria2.handshakeTimeout > 0) {
            p['handshake-timeout'] = bean.hysteria2.handshakeTimeout;
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'tuic') {
        const p = { ...base, type: 'tuic' };
        if (bean.tuic?.token) {
            p.token = bean.tuic.token;
        } else {
            if (bean.auth?.uuid) p.uuid = bean.auth.uuid;
            if (bean.auth?.password) p.password = bean.auth.password;
        }
        if (bean.tuic?.alpn) p.alpn = bean.tuic.alpn.split(',').filter(Boolean);
        if (bean.tuic?.sni) p.sni = bean.tuic.sni;
        if (bean.tuic?.allowInsecure) p['skip-cert-verify'] = true;
        if (bean.tuic?.congestion_control) p['congestion-controller'] = bean.tuic.congestion_control;
        if (bean.tuic?.bbr_profile) p['bbr-profile'] = bean.tuic.bbr_profile;
        if (bean.tuic?.udp_relay_mode) p['udp-relay-mode'] = bean.tuic.udp_relay_mode;
        if (bean.tuic?.disableSni) p['disable-sni'] = true;
        if (bean.tuic?.heartbeat) {
            const hb = String(bean.tuic.heartbeat).trim();
            p['heartbeat-interval'] = /^\d+$/.test(hb) ? parseInt(hb, 10) : hb;
        }
        if (bean.tuic?.requestTimeout) {
            const rt = String(bean.tuic.requestTimeout).trim();
            p['request-timeout'] = /^\d+$/.test(rt) ? parseInt(rt, 10) : rt;
        }
        if (bean.tuic?.reduceRtt) p['reduce-rtt'] = true;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'wireguard') {
        const wg = bean.wireguard || {};
        // IPv4-only contract (link-generators v1.8.0): нормализация на build-слое,
        // парсер остаётся faithful. Жёсткая часть — reject вместо молчаливой порчи:
        // IPv6-only interface address и IPv6 literal endpoint несовместимы с контрактом.
        const validation = validateWireGuardIpv4Only(bean);
        if (!validation.ok) throw new Error(validation.reason);
        const ipv4 = normalizeWireGuardIpv4Only(wg);
        const peers = Array.isArray(ipv4.peers) ? ipv4.peers : [];
        const hasPeers = peers.length > 0;
        const mapPeer = (peer) => {
            if (!peer || typeof peer !== 'object') return null;
            const out = { server: peer.server, port: peer.port };
            if (peer.publicKey) out['public-key'] = peer.publicKey;
            if (peer.preSharedKey) out['pre-shared-key'] = peer.preSharedKey;
            if (Array.isArray(peer.allowedIPs) && peer.allowedIPs.length) out['allowed-ips'] = peer.allowedIPs;
            if (peer.reserved !== undefined) out.reserved = peer.reserved;
            return out;
        };
        const p = {
            name: bean.name || computeTag(bean, new Set()),
            type: 'wireguard',
            server: bean.host,
            port: bean.port,
            'private-key': wg.privateKey,
            udp: true,
        };
        if (ipv4.ip) p.ip = ipv4.ip;
        if (wg.publicKey) p['public-key'] = wg.publicKey;
        if (wg.preSharedKey) p['pre-shared-key'] = wg.preSharedKey;
        if (Array.isArray(ipv4.allowedIPs) && ipv4.allowedIPs.length) p['allowed-ips'] = ipv4.allowedIPs;
        if (Number.isFinite(wg.mtu)) p.mtu = wg.mtu;
        if (Number.isFinite(wg.persistentKeepalive) && wg.persistentKeepalive > 0) p['persistent-keepalive'] = wg.persistentKeepalive;
        if (wg.reserved !== undefined) p.reserved = wg.reserved;
        // Контракт: endpoint-транспорт WG/AWG всегда резолвится в IPv4
        // (hostname не должен молча уйти в AAAA; applyCommon ниже не перезапишет —
        // bean.ipVersion у dual-stack пуст после нормализации интерфейса).
        p['ip-version'] = 'ipv4';
                // Per-profile dialer assignment (consumer sets it from the profile's
                // connection mode). Global wgDialerProxy stamping never overwrites it.
                if (typeof wg.dialerProxy === 'string' && wg.dialerProxy.trim()) p['dialer-proxy'] = wg.dialerProxy.trim();
        if (hasPeers) p.peers = peers.map(mapPeer).filter(Boolean);
        if (wg.ipStack && typeof wg.ipStack === 'object' && Object.keys(wg.ipStack).length) p['ip-stack'] = wg.ipStack;
        if (wg['amnezia-wg-option'] && typeof wg['amnezia-wg-option'] === 'object') {
            // no-silent-drop (NIGHT-06): INVALID/UNSUPPORTED значения НЕ эмитятся
            // (mihomo отверг бы весь конфиг) — raw-факт остаётся в bean.awgFieldReport
            // и показывается диагностикой на карточке профиля.
            const badKeys = new Set((bean.awgFieldReport || [])
                .filter(r => r.status === 'INVALID' || r.status === 'UNSUPPORTED')
                .map(r => String(r.key).toLowerCase()));
            const cleanOpt = {};
            for (const [k, v] of Object.entries(wg['amnezia-wg-option'])) {
                if (badKeys.has(String(k).toLowerCase())) continue;
                cleanOpt[k] = v;
            }
            if (Object.keys(cleanOpt).length) p['amnezia-wg-option'] = cleanOpt;
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'masque') {
        const mq = bean.masque || {};
        const p = {
            ...base,
            type: 'masque'
        };
        if (mq.privateKey) p['private-key'] = mq.privateKey;
        if (mq.publicKey) p['public-key'] = mq.publicKey;
        if (mq.ip) p.ip = mq.ip;
        if (mq.ipv6) p.ipv6 = mq.ipv6;
        if (mq.uri) p.uri = mq.uri;
        if (mq.sni) p.sni = mq.sni;
        if (mq.network) p.network = mq.network;
        if (Number.isFinite(mq.mtu) && mq.mtu > 0) p.mtu = mq.mtu;
        if (mq.udp === true) p.udp = true;
        if (mq.congestionController) p['congestion-controller'] = mq.congestionController;
        if (mq.bbrProfile) p['bbr-profile'] = mq.bbrProfile;
        if (Number.isFinite(mq.cwnd) && mq.cwnd > 0) p.cwnd = mq.cwnd;
        if (Number.isFinite(mq.handshakeTimeout) && mq.handshakeTimeout > 0) p['handshake-timeout'] = mq.handshakeTimeout;
        if (mq.allowInsecure) p['skip-cert-verify'] = true;
        if (mq.nameCertVerify) p['name-cert-verify'] = mq.nameCertVerify;
        if (mq.ipStack && typeof mq.ipStack === 'object' && Object.keys(mq.ipStack).length) p['ip-stack'] = mq.ipStack;
        if (mq.remoteDnsResolve) p['remote-dns-resolve'] = true;
        if (Array.isArray(mq.dns) && mq.dns.length) p.dns = mq.dns;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'anytls') {
        const anytls = bean.anytls || {};
        const p = { ...base, type: 'anytls', password: bean.auth.password };
        if (s.sni) p.sni = s.sni;
        if (s.alpn && s.alpn.length) p.alpn = s.alpn;
        if (s.allowInsecure) p['skip-cert-verify'] = true;
        if (s.fp) p['client-fingerprint'] = s.fp;
        if (anytls.clientMetadata) p['client-metadata'] = anytls.clientMetadata;
        if (Number.isFinite(anytls.idleSessionCheckInterval) && anytls.idleSessionCheckInterval > 0) {
            p['idle-session-check-interval'] = anytls.idleSessionCheckInterval;
        }
        if (Number.isFinite(anytls.idleSessionTimeout) && anytls.idleSessionTimeout > 0) {
            p['idle-session-timeout'] = anytls.idleSessionTimeout;
        }
        if (Number.isFinite(anytls.minIdleSession) && anytls.minIdleSession > 0) p['min-idle-session'] = anytls.minIdleSession;
        if (anytls.disableReuse) p['disable-reuse'] = true;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'mieru') {
        const mieru = bean.mieru || {};
        const p = {
            name: bean.name || computeTag(bean, new Set()),
            type: 'mieru',
            server: bean.host,
            transport: mieru.transport || 'TCP',
            username: mieru.username,
            password: mieru.password,
        };
        if (mieru.server_ports) p['port-range'] = mieru.server_ports;
        else p.port = bean.port;
        if (mieru.multiplexing) p.multiplexing = mieru.multiplexing;
        if (mieru.handshake_mode) p['handshake-mode'] = mieru.handshake_mode;
        if (mieru.traffic_pattern) p['traffic-pattern'] = mieru.traffic_pattern;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'trusttunnel') {
        const tt = bean.trusttunnel || {};
        const p = {
            ...base,
            type: 'trusttunnel',
            username: tt.username,
            password: tt.password,
        };
        if (s.sni) p.sni = s.sni;
        if (s.alpn && s.alpn.length) p.alpn = s.alpn;
        if (s.allowInsecure) p['skip-cert-verify'] = true;
        if (s.fp) p['client-fingerprint'] = s.fp;
        if (tt.fingerprint) p.fingerprint = tt.fingerprint;
        if (tt.certificate) p.certificate = tt.certificate;
        if (tt.privateKey) p['private-key'] = tt.privateKey;
        const echConfig = (s.ech?.config || s.ech?.configList || '').trim();
        const echQueryServerName = (s.ech?.queryServerName || '').trim();
        if (echConfig || echQueryServerName) {
            p['ech-opts'] = { enable: true };
            if (echConfig) p['ech-opts'].config = echConfig;
            if (echQueryServerName) p['ech-opts']['query-server-name'] = echQueryServerName;
        }
        if (tt.healthCheck) p['health-check'] = true;
        if (tt.quic) p.quic = true;
        if (tt.congestionController) p['congestion-controller'] = tt.congestionController;
        if (tt.bbrProfile) p['bbr-profile'] = tt.bbrProfile;
        if (Number.isFinite(tt.cwnd) && tt.cwnd > 0) p.cwnd = tt.cwnd;
        if (Number.isFinite(tt.maxConnections) && tt.maxConnections > 0) p['max-connections'] = tt.maxConnections;
        if (Number.isFinite(tt.minStreams) && tt.minStreams >= 0) p['min-streams'] = tt.minStreams;
        if (Number.isFinite(tt.maxStreams) && tt.maxStreams >= 0) p['max-streams'] = tt.maxStreams;
        applyCommon(p);
        return p;
    }
    throw new Error('Not supported by Mihomo: ' + bean.proto);
}

function deduplicateProxies(beans) {
    const stableKey = (value) => {
        if (value === null) return 'null';
        if (Array.isArray(value)) return '[' + value.map(stableKey).join(',') + ']';
        if (value && typeof value === 'object') {
            return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stableKey(value[k])).join(',') + '}';
        }
        return JSON.stringify(value);
    };

    const seen = new Set();
    return beans.filter(bean => {
        // Deduplicate by the actual Mihomo semantics we emit, not by a partial
        // hand-maintained subset of bean fields. Different labels may still
        // represent the same proxy, so name is intentionally excluded.
        const proxy = buildMihomoProxy(bean);
        const identity = { ...proxy };
        delete identity.name;
        const key = stableKey(identity);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function buildMihomoConfig(beans, opts) {
    const urlTest = getUrlTest(opts);
    const urlTestExpectedStatus = getUrlTestExpectedStatus(opts);
    const policies = getDomainPolicyPolicies(opts);
    const dedupedBeans = deduplicateProxies(beans);
    const proxies = dedupedBeans.map(b => buildMihomoProxy(b));
    const usePerProxyListeners = isPerProxyListenerMode(opts);
    const reservedProxyNames = [
        GLOBAL_GROUP_NAME,
        FASTEST_GROUP_NAME,
        STATIC_HEALTH_GROUP_NAME,
        'DIRECT',
        'REJECT'
    ];
    if (usePerProxyListeners) {
        const rawNames = proxies.map(p => String(p?.name || 'proxy').trim() || 'proxy');
        rawNames.forEach(name => reservedProxyNames.push(getPerProxyGroupName(name)));
    }
    assignSafeProxyNames(proxies, reservedProxyNames);
    const names = proxies.map(p => p.name);
    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const addSocks = !opts || opts.addSocks !== false;
    const groups = [];

    if (usePerProxyListeners) {
        proxies.forEach(p => {
            attachPerProxySelectGroup(groups, p);
        });
        if (proxies.length > 0) {
            groups.push({
                name: STATIC_HEALTH_GROUP_NAME,
                type: 'url-test',
                hidden: true,
                lazy: false,
                proxies: proxies.map(p => p.name),
                url: urlTest,
                interval: PROXY_FETCH_INTERVAL,
                'expected-status': urlTestExpectedStatus
            });
        }
        const groupNames = proxies.map(p => getPerProxyGroupName(p.name));
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: groupNames.length > 0 ? [...groupNames, 'REJECT'] : ['REJECT']
        });
    } else {
        if (names.length > 1) {
            groups.push({
                name: FASTEST_GROUP_NAME,
                type: 'url-test',
                proxies: names,
                url: urlTest,
                interval: PROXY_FETCH_INTERVAL,
                'expected-status': urlTestExpectedStatus
            });
            groups.push({
                name: GLOBAL_GROUP_NAME,
                type: 'select',
                proxies: uniqueTargets(FASTEST_GROUP_NAME, names, 'REJECT')
            });
        } else {
            const only = names[0] || 'REJECT';
            groups.push({
                name: GLOBAL_GROUP_NAME,
                type: 'select',
                proxies: [only, 'REJECT']
            });
        }
    }

    // DPR static mode: category groups are plain selects over the existing
    // Fastest/GLOBAL chain — no provider-backed AUTO groups without providers.
    const policyArtifacts = policies.length ? buildDomainPolicyArtifacts(policies, {
        mode: 'static',
        existingGroupNames: groups.map(g => g.name),
        urlTest,
        urlTestExpectedStatus
    }) : null;
    if (policyArtifacts) groups.push(...policyArtifacts.groups);

    const basePort = (opts && opts.basePort) || 7890;
    const listeners = [];
    if (addSocks && usePerProxyPort && proxies.length > 0) {
        for (let i = 0; i < proxies.length; i++) {
            const port = basePort + i;
            const targetGroup = usePerProxyListeners ? getPerProxyGroupName(proxies[i].name) : proxies[i].name;
            listeners.push({
                name: `socks-${proxies[i].name}`,
                type: 'socks',
                port: port,
                proxy: targetGroup
            });
        }
    }
    const config = {
        'allow-lan': false,
        mode: 'rule',
        'log-level': 'warning',
        proxies,
        'proxy-groups': groups,
        rules: [...(policyArtifacts ? policyArtifacts.rules : []), `MATCH,${GLOBAL_GROUP_NAME}`]
    };
    if (policyArtifacts) {
        config['rule-providers'] = policyArtifacts.ruleProviders;
        config.warnings = policyArtifacts.warnings;
    }
    if (addSocks && !usePerProxyPort) {
        config['mixed-port'] = basePort;
    } else if (listeners.length > 0) {
        config.listeners = listeners;
    }
    return config;
}

function buildMihomoSubscriptionConfig(subscriptionUrls, extraBeans, opts) {
    const urlTest = getUrlTest(opts);
    const urlTestExpectedStatus = getUrlTestExpectedStatus(opts);
    const policies = getDomainPolicyPolicies(opts);
    if (!Array.isArray(subscriptionUrls) || subscriptionUrls.length === 0) {
        throw new Error('At least one subscription URL is required');
    }

    const providers = {};
    const providerNames = [];
    const usedProviderNames = new Set();
    subscriptionUrls.forEach((url, index) => {
        const providerName = computeProviderName(url, index, subscriptionUrls.length, usedProviderNames);
        const deviceModel = typeof opts?.deviceModel === 'string' ? opts.deviceModel.trim() : '';
        providers[providerName] = {
            type: 'http',
            proxy: 'DIRECT',
            header: {
                'x-hwid': [generateSecretHex32()],
                ...(deviceModel ? { 'x-device-model': [deviceModel] } : {})
            },
            url: url,
            interval: SUB_REFRESH_INTERVAL,
            __comments: {
                interval: 'Subscription refresh interval'
            },
            'health-check': {
                enable: true,
                interval: PROXY_FETCH_INTERVAL,
                url: urlTest,
                'expected-status': urlTestExpectedStatus,
                __comments: {
                    interval: 'Health-check interval'
                }
            }
        };
        const excludeFilter = typeof opts?.excludeFilter === 'string' ? opts.excludeFilter.trim() : '';
        if (excludeFilter) providers[providerName]['exclude-filter'] = excludeFilter;
        providerNames.push(providerName);
    });

    // Selective modern REALITY: per-host(/port) override expressions applied by
    // mihomo to every loaded provider node. has("reality-opts") keeps plain
    // VLESS/TLS nodes untouched; a second expression sets chrome fingerprint
    // only where the provider did not define one.
    if (Array.isArray(opts?.modernHosts) && opts.modernHosts.length) {
        const exprs = [];
        for (const e of opts.modernHosts) {
            let sel = `select(.server == ${JSON.stringify(e.host)})`;
            if (e.port !== undefined) sel += ` | select(.port == ${e.port})`;
            exprs.push(`(${sel} | select(has("reality-opts")) | ."reality-opts"."support-x25519mlkem768") = true`);
            exprs.push(`(${sel} | select(has("reality-opts")) | select(.client-fingerprint == null) | .client-fingerprint) = "chrome"`);
        }
        for (const providerName of providerNames) {
            const override = providers[providerName].override = Object.assign({}, providers[providerName].override);
            override['override-expr'] = [...(override['override-expr'] || []), ...exprs];
        }
    }

    const usePerProxyListeners = isPerProxyListenerMode(opts);
    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const groups = [];
    if (!usePerProxyListeners) {
        groups.push({
            name: FASTEST_GROUP_NAME,
            type: 'url-test',
            use: providerNames,
            url: urlTest,
            interval: PROXY_FETCH_INTERVAL,
            'expected-status': urlTestExpectedStatus,
            tolerance: 50,
            'empty-fallback': 'REJECT',
            __comments: {
                interval: 'Latency probe interval (seconds)',
                tolerance: 'Switch threshold (ms)'
            }
        });
    }

    if (usePerProxyListeners || usePerProxyPort) {
        providerNames.forEach((providerName) => {
            groups.push({
                name: `SUB-${providerName}`,
                type: 'select',
                use: [providerName],
                'empty-fallback': 'REJECT'
            });
        });
    }

    const addSocks = !opts || opts.addSocks !== false;
    const fastestGroup = !usePerProxyListeners
        ? groups.find(g => g && g.name === FASTEST_GROUP_NAME && g.type === 'url-test')
        : null;
    const extraProxies = [];
    if (Array.isArray(extraBeans) && extraBeans.length > 0) {
        extraBeans.forEach(bean => {
            validateBean(bean);
            extraProxies.push(buildMihomoProxy(bean));
        });

        const reservedProxyNames = [
            GLOBAL_GROUP_NAME,
            FASTEST_GROUP_NAME,
            STATIC_HEALTH_GROUP_NAME,
            'DIRECT',
            'REJECT',
            ...providerNames.map(providerName => `SUB-${providerName}`)
        ];
        if (usePerProxyListeners) {
            const rawNames = extraProxies.map(p => String(p?.name || 'proxy').trim() || 'proxy');
            rawNames.forEach(name => reservedProxyNames.push(getPerProxyGroupName(name)));
        }
        assignSafeProxyNames(extraProxies, reservedProxyNames);

        extraProxies.forEach(p => {
            if (usePerProxyListeners) {
                attachPerProxySelectGroup(groups, p);
            } else {
                if (fastestGroup) {
                    if (!Array.isArray(fastestGroup.proxies)) fastestGroup.proxies = [];
                    if (!fastestGroup.proxies.includes(p.name)) fastestGroup.proxies.push(p.name);
                }
            }
        });
    }

    let subscriptionPolicyArtifacts = null;
    if (usePerProxyListeners) {
        if (extraProxies.length > 0) {
            groups.push({
                name: STATIC_HEALTH_GROUP_NAME,
                type: 'url-test',
                hidden: true,
                lazy: false,
                proxies: extraProxies.map(p => p.name),
                url: urlTest,
                interval: PROXY_FETCH_INTERVAL,
                'expected-status': urlTestExpectedStatus
            });
        }
        const globalTargets = providerNames.map(providerName => `SUB-${providerName}`);
        extraProxies.forEach((p) => {
            const targetGroup = getPerProxyGroupName(p.name);
            if (targetGroup) globalTargets.push(targetGroup);
        });
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: globalTargets.length > 0 ? [...globalTargets, 'REJECT'] : ['REJECT']
        });
    } else {
        const fastestTargets = fastestGroup && Array.isArray(fastestGroup.proxies)
            ? [...fastestGroup.proxies]
            : [];
        // DPR subscription mode: AUTO url-test groups share the SAME providers
        // as Fastest (use: is a reference, not a move — PoC-verified); category
        // selects sit above them, GLOBAL stays the last DEFAULT target.
        const policyArtifacts = policies.length ? buildDomainPolicyArtifacts(policies, {
            mode: 'subscription',
            providerNames,
            urlTest,
            urlTestExpectedStatus,
            existingGroupNames: groups.map(g => g.name)
        }) : null;
        if (policyArtifacts) {
            groups.push(...policyArtifacts.groups);
            subscriptionPolicyArtifacts = policyArtifacts;
        }
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: uniqueTargets(FASTEST_GROUP_NAME, fastestTargets, 'REJECT'),
            use: providerNames
        });
    }

    const basePort = (opts && opts.basePort) || 7890;
    const listeners = [];
    if (addSocks && usePerProxyPort) {
        const buildSocksListener = (name, proxy, port) => ({
            name: `socks-${name}`,
            type: 'socks',
            port,
            proxy
        });
        let portIdx = 0;
        providerNames.forEach(providerName => {
            listeners.push(buildSocksListener(`SUB-${providerName}`, `SUB-${providerName}`, basePort + portIdx++));
        });
        extraProxies.forEach(p => {
            const targetGroup = getPerProxyGroupName(p.name);
            listeners.push(buildSocksListener(p.name, targetGroup, basePort + portIdx++));
        });
    }

    const rules = [
        ...(subscriptionPolicyArtifacts ? subscriptionPolicyArtifacts.rules : []),
        `MATCH,${GLOBAL_GROUP_NAME}`
    ];
    return {
        providers,
        groups,
        rules,
        proxies: extraProxies,
        listeners,
        ...(subscriptionPolicyArtifacts ? { ruleProviders: subscriptionPolicyArtifacts.ruleProviders, warnings: subscriptionPolicyArtifacts.warnings } : {})
    };
}

// Two independent priority tiers. Reuse proxy/provider builders; no domain-specific policy.
function buildMihomoPriorityConfig(primary, fallback, opts) {
    const proxies = [];
    const providers = {};
    const targets = [];
    const providerTargets = [];
    // Priority mode answers a routing question: can this proxy establish an HTTP
    // path to the probe URL? Do not require one exact response code here.
    // MetaCubeXD's manual /delay probe has the same any-HTTP-response semantics;
    // strict expected-status checks remain on HTTP providers themselves.
    const probe = { url: getUrlTest(opts), interval: PROXY_FETCH_INTERVAL, lazy: false };
    for (const [name, side] of [['PRIMARY', primary], ['FALLBACK', fallback]]) {
        const built = side.subUrls.length
            ? buildMihomoSubscriptionConfig(side.subUrls, side.beans, { urlTest: opts?.urlTest, excludeFilter: opts?.excludeFilter, modernHosts: opts?.modernHosts, deviceModel: opts?.deviceModel })
            : buildMihomoConfig(side.beans, { urlTest: opts?.urlTest });
        const names = [];
        const renameMap = new Map();
        const sideProxies = [];
        built.proxies.forEach((proxy, index) => {
            // Index prevents duplicate user names, including reserved group/builtin names.
            const oldName = proxy.name;
            proxy.name = name + '-' + (index + 1) + ': ' + proxy.name;
            renameMap.set(oldName, proxy.name);
            names.push(proxy.name);
            sideProxies.push(proxy);
            proxies.push(proxy);
        });
        // Per-profile dialer targets are proxy names: rewrite them after the whole
        // side is renamed (a target may sit later in the list than the dialed proxy).
        sideProxies.forEach((proxy) => {
            if (typeof proxy['dialer-proxy'] === 'string') {
                const mapped = renameMap.get(proxy['dialer-proxy']);
                if (mapped) proxy['dialer-proxy'] = mapped;
            }
        });
        const use = [];
        Object.entries(built.providers || {}).forEach(([key, provider]) => {
            const providerName = name.toLowerCase() + '-' + key;
            provider['health-check'].lazy = false;
            // Merge, not replace: buildMihomoSubscriptionConfig may already have
            // attached override-expr (selective modern REALITY) to this provider.
            provider.override = Object.assign({}, provider.override, { 'additional-prefix': providerName + ': ' });
            providers[providerName] = provider;
            use.push(providerName);
        });
        targets.push(...names);
        providerTargets.push(...use);
    }
    // Mihomo GetProxies reorders ALL providers (including static proxies) by these
    // backtick-separated filters. Without this, fallback statics precede primary use.
    // Never nest groups here: their cached health state can mask live children (#2588).
    const groups = [{ name: GLOBAL_GROUP_NAME, type: 'fallback',
        ...(targets.length ? { proxies: targets } : {}),
        ...(providerTargets.length ? { use: providerTargets } : {}),
        filter: '^(PRIMARY-|primary-)`^(FALLBACK-|fallback-)',
        ...probe, 'empty-fallback': 'REJECT',
        timeout: FALLBACK_DIAL_FAILURE_WINDOW_MS,
        'max-failed-times': FALLBACK_MAX_DIAL_FAILURES }];
    // DPR in priority mode stays deliberately flat: policy selects point at the
    // existing GLOBAL fallback (RULE-SET → policy select → GLOBAL → flat P/F),
    // never at category AUTO groups inside the fallback (#2588 contract).
    const policies = getDomainPolicyPolicies(opts);
    const policyArtifacts = policies.length ? buildDomainPolicyArtifacts(policies, {
        mode: 'priority',
        existingGroupNames: groups.map(g => g.name),
        urlTest: probe.url
    }) : null;
    if (policyArtifacts) groups.push(...policyArtifacts.groups);
    return {
        proxies,
        providers,
        groups,
        rules: [...(policyArtifacts ? policyArtifacts.rules : []), `MATCH,${GLOBAL_GROUP_NAME}`],
        ...(policyArtifacts ? { ruleProviders: policyArtifacts.ruleProviders, warnings: policyArtifacts.warnings } : {})
    };
}

export {
    buildMihomoPriorityConfig,
    buildMihomoProxy,
    buildMihomoConfig,
    buildMihomoSubscriptionConfig,
};
