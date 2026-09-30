function quoteYamlString(value) {
    // JSON string literals are valid YAML double-quoted scalars and correctly
    // escape quotes, backslashes, control characters and line breaks.
    return JSON.stringify(String(value));
}

function isYamlPlainStringSafe(value) {
    const s = String(value);
    if (!/^[A-Za-z0-9_.:@#\-]+$/.test(s)) return false;
    if (s.startsWith('#') || s === ':' || s === '-') return false;

    // Values resolved by common YAML schemas as non-strings must stay strings.
    if (/^(?:null|true|false|\.nan|[+-]?\.inf)$/i.test(s)) return false;
    if (/^[+-]?(?:[0-9][0-9_]*|0[bBoOxX][0-9A-Fa-f_]+)$/.test(s)) return false;
    if (/^[+-]?(?:(?:[0-9][0-9_]*)?\.[0-9_]+|[0-9][0-9_]*\.)(?:[eE][+-]?[0-9]+)?$/.test(s)) return false;
    if (/^[+-]?[0-9][0-9_]*[eE][+-]?[0-9]+$/.test(s)) return false;
    if (/^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt ]|$)/.test(s)) return false;

    return true;
}

function toYamlScalar(value, key) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(value);
    const s = String(value);
    if (key === 'exclude-filter' || key === 'grpc-service-name') return quoteYamlString(s);
    if (isYamlPlainStringSafe(s)) return s;
    return quoteYamlString(s);
}

function toYAML(obj, indent = 0) {
    const space = '  '.repeat(indent);
    if (Array.isArray(obj)) {
        return obj.map(item => {
            if (item && typeof item === 'object') {
                const body = toYAML(item, indent + 1);
                const lines = body.split('\n');
                const indentPrefix = '  '.repeat(indent + 1);
                const firstLine = (lines[0] || '').replace(new RegExp('^' + indentPrefix), '');
                const rest = lines.slice(1).join('\n');
                return space + '- ' + firstLine + (rest ? '\n' + rest : '');
            }
            return space + '- ' + toYamlScalar(item, null);
        }).join('\n');
    }
    if (obj && typeof obj === 'object') {
        const lines = [];
        const comments = (obj.__comments && typeof obj.__comments === 'object') ? obj.__comments : null;
        for (const [k, v] of Object.entries(obj)) {
            if (v === undefined) continue;
            if (k === '__comments') continue;
            if (v && typeof v === 'object') {
                const child = toYAML(v, indent + 1);
                lines.push(space + k + ':');
                if (child) {
                    lines.push(child);
                }
            } else {
                lines.push(space + k + ': ' + toYamlScalar(v, k));
                if (comments && typeof comments[k] === 'string' && comments[k].trim()) {
                    lines.push(space + '# ' + comments[k].trim());
                }
            }
        }
        return lines.join('\n');
    }
    return space + toYamlScalar(obj, null);
}

function upsertSection(lines, key, sectionYaml) {
    const findSection = () => {
        const start = lines.findIndex(l => new RegExp('^' + key + '\\s*:\\s*$', 'i').test(l));
        if (start === -1) return {start: -1, end: -1};
        let end = start + 1;
        while (end < lines.length) {
            if (/^[^\s#][^:]*:\s*/.test(lines[end])) break;
            end++;
        }
        return {start, end};
    };

    const {start, end} = findSection();

    const inject = [
        key + ':',
        ...toYAML(sectionYaml, 1).split('\n'),
        ''
    ];

    if (start === -1) {
        if (lines.length && lines.at(-1) !== '') lines.push('');
        lines.push(...inject);
    } else {
        lines.splice(start, end - start, ...inject);
    }
}

function overlayMihomoYaml(baseYamlText, proxies, groups, providers, rules, listeners) {
    const text = (baseYamlText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');

    if (Array.isArray(proxies) && proxies.length > 0) {
        upsertSection(lines, 'proxies', proxies);
    }

    if (Array.isArray(groups) && groups.length > 0) {
        upsertSection(lines, 'proxy-groups', groups);
    }

    if (providers && typeof providers === 'object' && Object.keys(providers).length > 0) {
        upsertSection(lines, 'proxy-providers', providers);
    }

    if (Array.isArray(rules) && rules.length > 0) {
        upsertSection(lines, 'rules', rules);
    }

    if (Array.isArray(listeners) && listeners.length > 0) {
        upsertSection(lines, 'listeners', listeners);

        const hasSocksListener = listeners.some(
            l => l && typeof l === 'object' && String(l.type || '').toLowerCase() === 'socks'
        );

        if (hasSocksListener) {
            const mixedPortIndex = lines.findIndex(l => /^mixed-port\s*:/i.test(l));
            if (mixedPortIndex !== -1) {
                lines.splice(mixedPortIndex, 1);
            }
        }
    }
    return lines.join('\n');
}

const MIHOMO_DEFAULT_TEMPLATE = [
    'mixed-port: 7890',
    'allow-lan: false',
    'tcp-concurrent: true',
    'mode: rule',
    'log-level: warning',
    'ipv6: false',
    'unified-delay: true',
    'profile:',
    '  store-selected: true',
    '  store-fake-ip: true',
    '',
    'proxy-groups:',
    'rules:',
    '  - "MATCH,GLOBAL"'
].join('\n');

const MIHOMO_TUN_STACKS = new Set(['gvisor', 'system', 'mixed', 'mips']);

function resolveMihomoTunStack(tunOpt) {
    const raw = tunOpt && typeof tunOpt === 'object' ? tunOpt.stack : '';
    const stack = String(raw || 'gvisor').trim().toLowerCase();
    if (!MIHOMO_TUN_STACKS.has(stack)) {
        throw new Error(`Mihomo: invalid TUN stack "${stack}"`);
    }
    return stack;
}

const MIHOMO_WG_DIALER_DEFAULT_GROUP = 'WARP-DIALER';

// dialer-proxy contract (Mihomo >= 1.19.x, verified against v1.19.31 sources):
// the value must name an existing proxy or proxy-group; the target's UDP relay
// carries the WireGuard handshake, so TCP-only targets (http) cannot serve WG.
// opts.wgDialerProxy — target name (Variant A) or the name of the auto-created
// select group (Variant B/C); opts.wgDialerGroupMembers — Variant B static
// member list; opts.wgDialerProviders — Variant C list of subscription URLs
// already present in `providers` (resolved to provider names via their url
// field; node types are unknown at build time — UDP support must be picked
// manually in the dashboard). Members and providers combine into one select
// group (proxies + use). WireGuard proxies are exempt when they ARE the target
// (a transit WG profile must dial directly) or when they are listed as group
// members (same reason); otherwise a member dialing through a group that
// selects itself would loop at dial time — a cycle Mihomo's static validator
// does not catch. A provider-backed group can never contain the WG proxy
// itself, because providers are separate from static proxies.
function resolveMihomoWgDialer(proxies, groups, providers, opts) {
    const target = String((opts && opts.wgDialerProxy) || '').trim();
    const membersRaw = (opts && Array.isArray(opts.wgDialerGroupMembers)) ? opts.wgDialerGroupMembers : [];
    const members = membersRaw.map((s) => String(s).trim()).filter(Boolean);
    const providersRaw = (opts && Array.isArray(opts.wgDialerProviders)) ? opts.wgDialerProviders : [];
    const providerUrls = providersRaw.map((s) => String(s).trim()).filter(Boolean);
    if (!target && members.length === 0 && providerUrls.length === 0) return null;
    const proxyList = Array.isArray(proxies) ? proxies : [];
    const groupList = Array.isArray(groups) ? groups : [];
    const proxyNames = new Set(proxyList.map((p) => String((p && p.name) || '')));
    const groupNames = new Set(groupList.map((g) => String((g && g.name) || '')));
    const groupName = target || MIHOMO_WG_DIALER_DEFAULT_GROUP;
    if (members.length || providerUrls.length) {
        // Variant B/C: the group name must be fresh (this also rejects
        // GLOBAL/⚡ Fastest, which contain the WG proxy itself).
        if (proxyNames.has(groupName) || groupNames.has(groupName)) {
            throw new Error(`Mihomo: dialer group name "${groupName}" conflicts with an existing proxy or group`);
        }
        if (members.length) {
            const missing = members.filter((m) => m !== 'DIRECT' && !proxyNames.has(m));
            if (missing.length) {
                throw new Error(`Mihomo: dialer group member(s) not found among proxies: ${missing.join(', ')}`);
            }
        }
        const providerNames = [];
        if (providerUrls.length) {
            const providerList = (providers && typeof providers === 'object' && !Array.isArray(providers)) ? providers : {};
            const urlToName = new Map();
            Object.entries(providerList).forEach(([name, provider]) => {
                if (provider && typeof provider === 'object' && provider.url) urlToName.set(String(provider.url), name);
            });
            for (const url of providerUrls) {
                const name = urlToName.get(url);
                if (!name) {
                    throw new Error(`Mihomo: dialer provider URL not found among proxy-providers (enable URL-подписки mode and pass the same URL): ${url}`);
                }
                providerNames.push(name);
            }
        }
        const group = { name: groupName, type: 'select' };
        if (members.length) group.proxies = members.slice();
        if (providerNames.length) group.use = providerNames;
        return { target: groupName, members: new Set(members), group };
    }
    // Variant A: the target must exist (mirrors mihomo config validation).
    if (target !== 'DIRECT' && !proxyNames.has(target) && !groupNames.has(target)) {
        throw new Error(`Mihomo: dialer-proxy target "${target}" not found among proxies or groups`);
    }
    return { target, members: new Set(), group: null };
}

function applyMihomoWgDialer(proxies, dialer) {
    if (!dialer) return proxies;
    let applied = 0;
    const out = (Array.isArray(proxies) ? proxies : []).map((p) => {
        if (p && p.type === 'wireguard' && p.name !== dialer.target && !dialer.members.has(String(p.name || ''))) {
            applied++;
            return Object.assign({}, p, { 'dialer-proxy': dialer.target });
        }
        return p;
    });
    if (applied === 0) {
        throw new Error(`Mihomo: dialer-proxy "${dialer.target}" applies to no wireguard proxy (self-named and member profiles are excluded)`);
    }
    return out;
}

// Full dialer dependency-graph model (WireGuard-over-WireGuard support).
// The Mihomo config is treated as a directed graph; a chain is valid as long as
// its handshake route never returns to the starting outbound. Vertices: proxies,
// proxy-groups, proxy-providers, DIRECT/REJECT. Edges:
//   proxy P --dialer-proxy--> T
//   group G -> static members (proxies) AND provider members (use) — a mixed
//     group contributes both edge categories
//   provider U -> U.override['dialer-proxy'] when configured
// A provider WITHOUT an override adds no static edge: its remote node set is
// unknown at config time, so the branch is dynamic/unknown — never claimed
// cycle-free. The build gate only rejects PROVEN cycles (no false errors);
// analyzeDialerGraph() surfaces the dynamic branches for warning semantics.
// DIRECT/REJECT terminate a route.
const MIHOMO_DIALER_DEAD_ENDS = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE']);

function buildDialerDependencyGraph(proxies, groups, providers) {
    const dialerOf = new Map();
    (Array.isArray(proxies) ? proxies : []).forEach((p) => {
        if (p && typeof p === 'object' && typeof p.name === 'string' && p['dialer-proxy']) {
            dialerOf.set(p.name, String(p['dialer-proxy']));
        }
    });
    const staticMembers = new Map();
    const providerMembers = new Map();
    (Array.isArray(groups) ? groups : []).forEach((g) => {
        if (!g || typeof g !== 'object' || typeof g.name !== 'string') return;
        if (Array.isArray(g.proxies)) staticMembers.set(g.name, g.proxies.filter((m) => typeof m === 'string'));
        if (Array.isArray(g.use)) providerMembers.set(g.name, g.use.filter((m) => typeof m === 'string'));
    });
    const providerDialer = new Map();
    if (providers && typeof providers === 'object' && !Array.isArray(providers)) {
        Object.entries(providers).forEach(([name, provider]) => {
            const override = provider && typeof provider === 'object' ? provider.override : undefined;
            const dp = override && typeof override === 'object' ? override['dialer-proxy'] : undefined;
            if (typeof dp === 'string' && dp.trim()) providerDialer.set(name, dp.trim());
        });
    }
    return { dialerOf, staticMembers, providerMembers, providerDialer, deadEnds: MIHOMO_DIALER_DEAD_ENDS };
}

function nextDialerNodes(graph, node) {
    const out = [];
    if (graph.dialerOf.has(node)) out.push(graph.dialerOf.get(node));
    // Mixed groups (proxies: AND use:) contribute BOTH edge categories; skipping
    // use: edges because proxies: exists would hide provider-override cycles.
    if (graph.staticMembers.has(node)) out.push(...graph.staticMembers.get(node).filter((m) => !graph.deadEnds.has(m)));
    if (graph.providerMembers.has(node)) {
        for (const u of graph.providerMembers.get(node)) {
            if (graph.providerDialer.has(u)) out.push(graph.providerDialer.get(u));
        }
    }
    return out;
}

// Returns every cycle reachable from a dialer-configured outbound back to itself,
// as { start, route: [start, ..., start] }.
function findDialerCycles(graph) {
    const cycles = [];
    for (const start of graph.dialerOf.keys()) {
        const path = [start];
        const visit = (node) => {
            if (node === start) {
                cycles.push({ start, route: path.slice().concat(start) });
                return true;
            }
            if (path.includes(node) || graph.deadEnds.has(node)) return false;
            path.push(node);
            for (const n of nextDialerNodes(graph, node)) {
                if (visit(n)) return true;
            }
            path.pop();
            return false;
        };
        for (const n of nextDialerNodes(graph, start)) {
            if (visit(n)) break;
        }
    }
    return cycles;
}

// Build-time gate: a cycle is a real handshake deadlock, fail closed.
function detectMihomoDialerCycles(proxies, groups, providers) {
    const graph = buildDialerDependencyGraph(proxies, groups, providers);
    if (graph.dialerOf.size === 0) return;
    const cycles = findDialerCycles(graph);
    if (cycles.length) {
        const c = cycles[0];
        throw new Error(`Mihomo: circular dialer-proxy dependency for "${c.start}" (route: ${c.route.join(' -> ')}) — the handshake route returns to its own outbound`);
    }
}

// Public validator API: analyze a parsed final YAML document. Returns:
//   cycles        — every dialer cycle found, each with the full readable route;
//   dynamicGroups — groups reachable from a dialer route whose member set is
//                   partially or fully provider-backed;
//   dynamicProviders — providers referenced by those groups WITHOUT a static
//                   override.dialer-proxy. Their remote node set is unknown at
//                   config time: such branches are dynamic/unknown, NOT provably
//                   cycle-free — callers must warn (never invent a verdict about
//                   provider contents; runtime compatibility stays a field test).
function analyzeDialerGraph(doc) {
    const d = doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : {};
    const graph = buildDialerDependencyGraph(d.proxies, d['proxy-groups'], d['proxy-providers']);
    const cycles = findDialerCycles(graph);
    const dynamicGroups = [];
    const dynamicProviders = [];
    // Walk from every dialer-configured outbound; any group reachable via dialer
    // edges that carries use: introduces an unknown remote branch. A provider with
    // a static override is already an explicit edge; one without is unknown.
    const dialerRoots = [...graph.dialerOf.values()];
    const seen = new Set();
    const visit = (node) => {
        if (seen.has(node) || graph.deadEnds.has(node)) return;
        seen.add(node);
        if (graph.staticMembers.has(node)) {
            graph.staticMembers.get(node).forEach(visit);
        }
        if (graph.providerMembers.has(node)) {
            dynamicGroups.push(node);
            for (const u of graph.providerMembers.get(node)) {
                if (!graph.providerDialer.has(u) && !dynamicProviders.includes(u)) dynamicProviders.push(u);
                if (graph.providerDialer.has(u)) visit(graph.providerDialer.get(u));
            }
        }
    };
    for (const root of dialerRoots) visit(root);
    for (const start of graph.dialerOf.keys()) visit(start);
    return { cycles, dynamicGroups: [...new Set(dynamicGroups)], dynamicProviders };
}

function buildMihomoYaml(proxies, groups, providers, rules, listeners, opts) {
    opts = opts || {};
    const wgDialer = resolveMihomoWgDialer(proxies, groups, providers, opts);
    if (wgDialer && wgDialer.group) groups = [wgDialer.group, ...groups];
    if (wgDialer) proxies = applyMihomoWgDialer(proxies, wgDialer);
    detectMihomoDialerCycles(proxies, groups, providers);
    const addSocks = opts.addSocks !== false;
    const webUI = opts.webUI === true;
    const tunOpt = opts.tun;
    const perProxyGroupName = (name) => `🔒 ${name}`;
    let template = MIHOMO_DEFAULT_TEMPLATE;
    if (!addSocks) {
        template = template
            .split('\n')
            .filter(line => !/^mixed-port\s*:/i.test(line))
            .join('\n');
    }
    if (webUI) {
        const lines = template.split('\n');
        const ipv6Index = lines.findIndex(l => /^ipv6\s*:/i.test(l));
        if (ipv6Index !== -1) {
            // Custom dashboard URL (validated upstream in build.js); default stays metacubexd.
            const externalUiUrl = String(opts.webUiUrl || 'https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz');
            lines.splice(ipv6Index + 1, 0,
                'external-controller: 0.0.0.0:9090',
                'external-ui: ui',
                'external-ui-url: ' + externalUiUrl,
                'secret: '
            );
            template = lines.join('\n');
        }
    }
    if (tunOpt) {
        const lines = template.split('\n');
        const proxiesIndex = lines.findIndex(l => /^proxy-groups\s*:/i.test(l));
        const mode = (tunOpt && typeof tunOpt === 'object' && tunOpt.mode) ? String(tunOpt.mode) : 'tun';
        const stack = resolveMihomoTunStack(tunOpt);
        if (mode === 'listeners') {
            const buildTunListener = (idx, proxyName) => {
                const offset = idx * 4 + 1;
                const oct3 = Math.floor(offset / 256);
                const oct4 = offset % 256;
                const inet4 = `198.19.${oct3}.${oct4}/30`;
                const out = {
                    name: `mihomo-tun-${idx + 1}`,
                    type: 'tun',
                    device: `mitun${idx}`,
                    stack,
                    'auto-route': false,
                    'auto-detect-interface': false,
                    'inet4-address': [inet4],
                };
                if (proxyName) out.proxy = proxyName;
                return out;
            };

            const tunListeners = [];
            const proxyList = Array.isArray(proxies) ? proxies : [];
            const providerKeys = (providers && typeof providers === 'object') ? Object.keys(providers) : [];
            const hasGroup = (name) => Array.isArray(groups) && groups.some(g => g && g.name === name);

            const targets = [];
            if (providerKeys.length > 0) {
                providerKeys.forEach(pn => {
                    const groupName = `SUB-${pn}`;
                    if (pn && hasGroup(groupName)) {
                        targets.push(groupName);
                    }
                });
                if (targets.length === 0 && providerKeys.length === 1) {
                    const fastestGroup = Array.isArray(groups)
                        ? groups.find(g => g?.type === 'url-test' && Array.isArray(g.use))
                        : null;
                    const name = (fastestGroup && fastestGroup.name) ? fastestGroup.name : 'PROXY';
                    targets.push(name);
                }
                proxyList.forEach(p => {
                    const proxyName = p?.name;
                    const targetName = proxyName && hasGroup(perProxyGroupName(proxyName))
                        ? perProxyGroupName(proxyName)
                        : proxyName;
                    if (targetName) targets.push(targetName);
                });
            } else {
                proxyList.forEach(p => {
                    const proxyName = p?.name;
                    const targetName = proxyName && hasGroup(perProxyGroupName(proxyName))
                        ? perProxyGroupName(proxyName)
                        : proxyName;
                    if (targetName) targets.push(targetName);
                });
            }

            targets.forEach((name, idx) => {
                tunListeners.push(buildTunListener(idx, name));
            });

            const merged = Array.isArray(listeners) ? listeners.slice() : [];
            merged.push(...tunListeners);
            listeners = merged;
        } else {
            const tun = {
                enable: true,
                stack,
                'auto-route': false,
                'auto-detect-interface': true,
                device: 'mitun0',
            };
            const inject = [
                'tun:',
                ...toYAML(tun, 1).split('\n'),
                ''
            ];
            if (proxiesIndex !== -1) {
                lines.splice(proxiesIndex, 0, ...inject);
            } else {
                lines.push(...inject);
            }
            template = lines.join('\n');
        }
    }
    return overlayMihomoYaml(template, proxies, groups, providers, rules, listeners);
}

export {
    buildMihomoYaml,
    analyzeDialerGraph,
};
