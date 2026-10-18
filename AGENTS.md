# AGENTS.md — web4core

## Owner architecture contract: independent autonomous layers (2026-10-18)

The owner is an architect of complex, multi-layer abstraction systems. **Autonomous layers** are an intentional design, not accidental duplication. Respect them when implementing Mihomo/YAML generation, engine rules and integration adapters.

- The HOME Keenetic/other client has its own independent Mihomo and GLOBAL/MAIN_AUTO. For this owner, the v1.11.1 router config is sufficient; a server request is not permission to redesign it.
- Each VPS (SE/SE2/EE/MSK) maintains its **own** Mihomo: local GLOBAL manual selector; EXIT_STRATEGY/MAIN_AUTO fallback between egress tiers; url-test **within** each tier. Order and number of tiers vary by VPS; never assume five fixed tiers or a fleet-wide central controller.
- Inbound services (Xray/3x-ui, Mieru, AmneziaWG) are logically independent from Mihomo's egress engine. Neither service has to know the other's internal configuration. Traffic can be connected through SOCKS, TUN, Linux policy routing, Docker and firewall, each with an explicit, verifiable interface contract.
- VPS→VPS is an optional transport hop (e.g. MSK→EE→external proxy); every server still makes its own local decisions, without coordinated cross-host policy.
- User data-plane egress must not silently fall back to host/VPS public IP when selected proxies fail. Service/control transport (provider updates, DNS/bootstrap, dialer) is evaluated separately. No global ban on the literal token DIRECT; validate routing semantics and positive feature regressions.

**For agents:** preserve layer boundaries and existing functionality; avoid one giant omniscient controller, disabling features, or making OS/Xray/router changes as a side-effect of an engine task. When the layer boundary or trade-off is unclear, stop and ask the owner (anti-monkey-paw: removing dust is not permission to burn a house).

This is architectural intent, not verified current VPS state. No deploy/merge to production without explicit owner approval. See: [link-generators constitution](https://github.com/saymer-alt/link-generators/blob/main/CONSTITUTION.md) and [VPS Gateway documentation](https://github.com/saymer-alt/link-generators/blob/main/docs/VPS-GATEWAY.md) (pending their corresponding documentation PRs).
