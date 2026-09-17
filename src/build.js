import { buildBeansFromInput, computeTag, getAllowedCoreProtocols, resolveUrlTest, validateBean } from './main.js';
import { buildSingBoxConfig, buildSingBoxOutbound, buildSingBoxWireGuardEndpoint } from './core/singbox.js';
import { buildXrayConfig, buildXrayOutbound } from './core/xray.js';
import { buildMihomoConfig, buildMihomoSubscriptionConfig, buildMihomoPriorityConfig } from './core/mihomo.js';
import { buildMihomoYaml } from './core/yaml.js';

function assertCoreSupports(beans, core, label, options) {
  const allowed = new Set(getAllowedCoreProtocols(core, options));
  const unsupported = new Set();
  for (const b of (Array.isArray(beans) ? beans : [])) {
    const p = b?.proto;
    if (!p) continue;
    if (!allowed.has(p)) unsupported.add(p);
  }
  if (unsupported.size) {
    throw new Error(`${label} does not support: ${Array.from(unsupported).join(', ')}`);
  }
}

function splitLines(raw) {
  return String(raw || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitMihomoSubscriptionInput(raw) {
  const lines = splitLines(raw);
  const subUrls = [];
  const proxyLines = [];
  for (const line of lines) {
    if (line.startsWith('#')) continue; // comment lines are skipped
    if (/^https?:\/\//i.test(line)) {
      try {
        const u = new URL(line);
        const hasCreds = !!(u.username || u.password);
        (hasCreds ? proxyLines : subUrls).push(line);
      } catch {
        proxyLines.push(line);
      }
    } else {
      proxyLines.push(line);
    }
  }
  return { subUrls, proxyText: proxyLines.join('\n') };
}

const WEB_UI_DASHBOARD_URLS = {
  yacd: 'https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip',
  zashboard: 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip',
};

function resolveWebUiUrl(options) {
  const dashboard = String(options.webUiDashboard || '').trim().toLowerCase();
  if (!dashboard || dashboard === 'metacubexd') return undefined; // legacy byte-parity
  if (WEB_UI_DASHBOARD_URLS[dashboard]) return WEB_UI_DASHBOARD_URLS[dashboard];
  if (dashboard === 'custom') {
    const raw = String(options.webUiCustomUrl || '').trim();
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error('Invalid Web UI URL (expected absolute http/https URL)');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Invalid Web UI URL (expected http/https)');
    }
    return parsed.href;
  }
  throw new Error('Unknown Web UI dashboard: ' + dashboard);
}
function splitHostPortEntry(s) {
  // "host", "host:port", "[ipv6]", "[ipv6]:port"; bare IPv6 (no brackets) is
  // treated as host-only because ':' is ambiguous there.
  const bracket = s.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  if (bracket) return { host: bracket[1], port: bracket[2] };
  const hp = s.match(/^([^:]+):(\d{1,5})$/);
  if (hp) return { host: hp[1], port: hp[2] };
  return { host: s, port: undefined };
}

function normalizeRealityModernHosts(raw) {
  if (raw === undefined || raw === null || raw === '') return [];
  const arr = Array.isArray(raw) ? raw : [raw];
  const out = [];
  const seen = new Set();
  for (const item of arr) {
    let entry;
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (!trimmed) continue;
      entry = splitHostPortEntry(trimmed);
    } else if (item && typeof item === 'object') {
      entry = { host: String(item.host || '').trim(), port: item.port };
    } else {
      throw new Error('Invalid modern REALITY host entry');
    }
    const host = String(entry.host || '').trim().toLowerCase();
    if (!host) throw new Error('Invalid modern REALITY host entry: missing host');
    let port;
    if (entry.port !== undefined && entry.port !== null && entry.port !== '') {
      port = Number(entry.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Invalid modern REALITY host entry: port ' + entry.port);
      }
    }
    const key = host + (port !== undefined ? ':' + port : '');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(port === undefined ? { host } : { host, port });
  }
  return out;
}

function applyRealityModernHosts(beans, modernHosts) {
  if (!modernHosts.length) return;
  for (const bean of beans) {
    const reality = bean.stream && bean.stream.reality;
    if (!reality || !reality.pbk) continue; // REALITY nodes only
    // Bean hosts may keep IPv6 brackets (the YAML emitter re-adds them).
    const host = String(bean.host || '').trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
    const matched = modernHosts.some((e) => e.host === host && (e.port === undefined || e.port === bean.port));
    if (!matched) continue;
    reality.supportX25519MLKEM768 = true;
    if (!bean.stream.fp) bean.stream.fp = 'chrome'; // PQ key share rides only on chrome-family uTLS
  }
}

export function buildFromRequest(req) {
  const core = String(req?.core || '').toLowerCase();
  const input = String(req?.input || '');
  const optionsIn = (req && typeof req.options === 'object' && req.options) ? req.options : {};
  const options = Object.assign({}, optionsIn);
  const wgBeans = Array.isArray(req?.wgBeans) ? req.wgBeans : [];
  options.urlTest = resolveUrlTest(options.urlTest);

  // Selectable external dashboard: metacubexd (default, byte-parity with
  // legacy output), yacd-meta, zashboard, or a validated custom archive URL.
  options.webUiUrl = resolveWebUiUrl(options);
  // Selective modern REALITY: [{host, port?}] — only matched REALITY nodes
  // get support-x25519mlkem768 (+ default chrome fingerprint); absent/empty
  // keeps the legacy output byte-for-byte.
  const modernHosts = normalizeRealityModernHosts(options.mihomoRealityModernHosts);
  options.modernHosts = modernHosts;

  if (!core) throw new Error('Missing core');
  if (core !== 'singbox' && core !== 'xray' && core !== 'mihomo') throw new Error('Invalid core: ' + core);

  if (core === 'singbox') {
    if (options.addTun === undefined) options.addTun = false;
    if (options.addSocks === undefined) options.addSocks = true;
    if (options.webUI === undefined) options.webUI = false;
  } else if (core === 'xray') {
    if (options.addTun === undefined) options.addTun = false;
    if (options.addSocks === undefined) options.addSocks = true;
  } else if (core === 'mihomo') {
    if (options.webUI === undefined) options.webUI = true;
    if (options.addTun === undefined) options.addTun = false;
    if (options.addSocks === undefined) options.addSocks = true;
  }

  // Optional generic primary/fallback request; legacy requests keep their exact path.
  if (core === 'mihomo' && req.fallbackInput !== undefined) {
    if (!options.addTun && !options.addSocks) throw new Error('Mihomo: enable at least one inbound (TUN or SOCKS5)');
    if (options.mihomoPerProxyTun || options.perProxyPort) throw new Error('Mihomo primary/fallback groups do not support per-proxy listeners');
    const parseSide = (text, profiles, label) => {
      const { subUrls, proxyText } = splitMihomoSubscriptionInput(text);
      if (subUrls.length && !options.mihomoSubscriptionMode) throw new Error('Enable Sub Mode for subscription URLs (' + label + ')');
      const beans = [...(proxyText.trim() ? buildBeansFromInput(proxyText) : []), ...profiles];
      beans.forEach(validateBean);
      assertCoreSupports(beans, core, 'Mihomo', options);
      if (!beans.length && !subUrls.length) throw new Error('Mihomo: ' + label + ' input is empty');
      return { beans, subUrls };
    };
    const modernHosts = options.modernHosts;
    const primarySide = parseSide(input, wgBeans, 'primary');
    const fallbackSide = parseSide(req.fallbackInput, [], 'fallback');
    applyRealityModernHosts(primarySide.beans, modernHosts);
    applyRealityModernHosts(fallbackSide.beans, modernHosts);
    const cfg = buildMihomoPriorityConfig(primarySide, fallbackSide, options);
    return { kind: 'yaml', data: buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, [], {
      addSocks: !!options.addSocks, webUI: !!options.webUI,
      webUiUrl: options.webUiUrl,
      tun: options.addTun ? { mode: 'tun', stack: options.mihomoTunStack } : null,
    }) };
  }

  const beans = input.trim() ? buildBeansFromInput(input.trim()) : [];
  const allBeans = beans.slice();
  if (wgBeans.length) allBeans.push(...wgBeans);
  if (!allBeans.length) throw new Error('No valid links or profiles provided');

  allBeans.forEach(validateBean);

  if (core === 'xray' || core === 'mihomo') {
    assertCoreSupports(allBeans, core, core === 'xray' ? 'Xray' : 'Mihomo', options);
  }

  if (core === 'singbox') {
    const useExtended = !!options.useExtended;
    if (!useExtended) {
      const hasExtendedOnly = allBeans.some((b) => b.proto === 'mieru' || b.proto === 'sdns');
      if (hasExtendedOnly) throw new Error('Enable Extended to generate Mieru/SDNS configurations');
    }

    const dnsBeans = useExtended ? allBeans.filter((b) => b.proto === 'sdns') : [];
    const wgBeans = allBeans.filter((b) => b.proto === 'wireguard');
    const outboundBeans = allBeans.filter((b) => b.proto !== 'sdns' && b.proto !== 'wireguard');
    const used = new Set();
    const endpoints = wgBeans.map((b) => {
      const tag = computeTag(b, used);
      return Object.assign({ tag }, buildSingBoxWireGuardEndpoint(Object.assign({}, b, { name: tag })));
    });

    const outbounds = outboundBeans.map((b) => {
      const ob = buildSingBoxOutbound(b, { useExtended: !!useExtended });
      const tag = computeTag(b, used);
      return Object.assign({ tag }, ob);
    });

    const detour = !!options.detour;
    if (detour && outbounds.length > 1) {
      const mainTag = outbounds[0].tag;
      for (let i = 1; i < outbounds.length; i++) outbounds[i].detour = mainTag;
    }

    const cfg = buildSingBoxConfig(outbounds, {
      addTun: !!options.addTun,
      addSocks: !!options.addSocks,
      perTunMixed: !!options.perTunMixed,
      tunName: String(options.tunName || ''),
      genClashSecret: !!options.genClashSecret,
      useExtended: !!useExtended,
      androidMode: !!options.androidMode,
      dnsBeans,
      endpoints,
      urlTest: options.urlTest,
    });

    return { kind: 'json', data: cfg };
  }

  if (core === 'xray') {
    let cfg;
    const addTun = !!options.addTun;
    const addSocks = !!options.addSocks;
    if (!addTun && !addSocks) {
      throw new Error('Xray: enable at least one inbound (TUN or SOCKS5)');
    }
    if (allBeans.length === 1) {
      cfg = buildXrayConfig(buildXrayOutbound(allBeans[0]), { addTun, addSocks, urlTest: options.urlTest });
    } else {
      const used = new Set();
      const outbounds = allBeans.map((b) => {
        const ob = buildXrayOutbound(b);
        ob.tag = computeTag(b, used);
        return ob;
      });
      cfg = buildXrayConfig(outbounds, { enableBalancer: !!options.enableBalancer, addTun, addSocks, urlTest: options.urlTest });
    }
    return { kind: 'json', data: cfg };
  }

  // mihomo
  const webUI = !!options.webUI;
  const addSocks = !!options.addSocks;
  const perProxyPort = !!options.perProxyPort;
  const addTun = !!options.addTun;
  if (!addTun && !addSocks) {
    throw new Error('Mihomo: enable at least one inbound (TUN or SOCKS5)');
  }
  const perProxyListeners = perProxyPort || !!options.mihomoPerProxyTun;
  const mihomoTunOpts = addTun ? { mode: (options.mihomoPerProxyTun ? 'listeners' : 'tun'), stack: options.mihomoTunStack } : null;
  applyRealityModernHosts(allBeans, modernHosts);

  const subMode = !!options.mihomoSubscriptionMode;
  if (subMode) {
    const { subUrls, proxyText } = splitMihomoSubscriptionInput(input);
    if (!subUrls.length) {
      throw new Error('Provide one or more HTTP(S) URLs for Mihomo subscription (one per line)');
    }
    const extraBeans = [];
    if (proxyText.trim()) extraBeans.push(...buildBeansFromInput(proxyText));
    if (wgBeans.length) extraBeans.push(...wgBeans);
    extraBeans.forEach(validateBean);
    assertCoreSupports(extraBeans, core, 'Mihomo', options);
    applyRealityModernHosts(extraBeans, modernHosts);

    const cfg = buildMihomoSubscriptionConfig(subUrls, extraBeans, {addSocks, perProxyPort, perProxyListeners, urlTest: options.urlTest, excludeFilter: options.excludeFilter, modernHosts});
    const yaml = buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, cfg.listeners, {
      addSocks,
      webUI,
      webUiUrl: options.webUiUrl,
      tun: mihomoTunOpts,
    });
    return { kind: 'yaml', data: yaml };
  }

  const outBeans = allBeans.filter((b) => b.proto !== 'sdns');
  const cfg = buildMihomoConfig(outBeans, {addSocks, perProxyPort, perProxyListeners, urlTest: options.urlTest});
  const yaml = buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, {
    addSocks,
    webUI,
    webUiUrl: options.webUiUrl,
    tun: mihomoTunOpts,
  });
  return { kind: 'yaml', data: yaml };
}


