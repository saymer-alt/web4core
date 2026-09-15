# Optional Mihomo primary/fallback request

`buildFromRequest({ core: 'mihomo', input, wgBeans, fallbackInput, options })`:
`input` and `wgBeans` form PRIMARY; `fallbackInput` forms FALLBACK. Both must be
nonempty. Omit `fallbackInput` to preserve the legacy API/output path exactly.

Each side supports links and HTTP(S) subscription URLs. Subscription URLs require
`options.mihomoSubscriptionMode`; in this path the option does not require a URL.
URLs with userinfo remain proxy links. Parsing, validation and core restrictions
reuse the existing functions. No browser fetch or new protocol is introduced.

`buildMihomoPriorityConfig` composes existing proxy/provider builders into a single
flat GLOBAL fallback containing terminal proxies and provider nodes. The ordered
filter `^(PRIMARY-|primary-)` followed by `^(FALLBACK-|fallback-)` (backtick separator)
reorders the combined `proxies`/`use` list in Mihomo 1.19.31. Every primary precedes
every fallback, including mixed input. Within a tier, the first alive node wins;
there is no latency minimization. Nested groups are forbidden because #2588 is
reproducible on v1.19.31. Prefixes and this ordered filter are one contract.

GLOBAL and every provider have active health checks (300s, same URL/status,
lazy=false). GLOBAL uses `empty-fallback: REJECT`. Provider downloads retain their
existing DIRECT route; DIRECT is never a traffic target. Names are scoped per tier;
provider override prefixes also scope dynamically loaded proxy names.

Per-proxy listener options are rejected in this request path. Ordinary TUN stack,
mixed port and Web UI options retain their meaning. Consumer policy and UI terms
remain outside engine. See the consumer's `docs/AUTO-WHITELIST.md` for UX details,
full YAML structure, test results and health-check timing limitations.

Run `node --test tools/tests/mihomo-priority.test.mjs` with the existing source
regressions; then build runtime, run consumer runtime/browser tests and actual
Mihomo validation. The consumer workflow requires this test before publication.
Run consumer `tests/mihomo-failover.cjs` for actual local traffic failover/recovery
with static/providers/mixed; `--nested-repro` reconstructs the rejected architecture
and proves #2588 with a dead wrapper, alive child, and traffic sent to fallback.
