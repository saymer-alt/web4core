# AGENTS.md - web4core fork for link-generators

## Repositories and branches

- spatiumstas/web4core - upstream.
- saymer-alt/web4core:main - base branch kept as close as possible to upstream/main; do not add our extensions here. Update this mirror by fast-forward only, without rewriting history.
- saymer-alt/web4core:link-generators - working source-level branch. Parser, builder, and protocol support for link-generators are implemented here.
- Remotes: origin -> https://github.com/saymer-alt/web4core.git, upstream -> https://github.com/spatiumstas/web4core.git.
- saymer-alt/link-generators - separate UI/browser consumer of the built runtime. Its forms, UX, and UI-specific post-processing live in that repository.

Overall architecture and layer selection: [WEB4CORE-FORK.md](https://github.com/saymer-alt/link-generators/blob/main/docs/WEB4CORE-FORK.md).
The rules in this file apply to the custom branch; main remains an upstream mirror.

This AGENTS.md is intentionally in English for agent efficiency. User-facing UI, README, comments, and project documentation remain Russian unless the owner explicitly requests a translation.

## Sources and generated files

- src/main.js: share/input parsing, beans, validation/core support; before changing anything, find the actual functions and tables instead of relying only on schema names.
- src/build.js: public buildFromRequest, option normalization/passthrough.
- src/core/mihomo.js: Mihomo proxies/config/subscriptions.
- src/core/yaml.js: YAML emission, ordinary TUN, and Per-Proxy listeners.
- src/entry-web4core.js: browser runtime entry point and public exports.
- tools/tests/: existing native node:test suite; new tests must follow this style.
- package.json and the lockfile define the build. Run npm ci, then npm run build:web:runtime -> src/web4core.runtime.js.
- Never edit generated runtime, src/ui.js, or worker dist by hand, and never add them to Git against .gitignore. The consumer receives only build output. Do not introduce textual patches against the finished bundle.

## Contracts and scope

A new protocol must pass through the whole chain:

~~~text
share/input parser -> bean -> validation/core support -> Mihomo builder -> tests -> build
~~~

A parser alone does not prove end-to-end support. Add positive and negative cases, map fields against the target core version, and synchronize the consumer validator, README, and docs only after the full chain and a real mihomo -t check are confirmed.
New protocols require a separate owner task; do not add them opportunistically.

Backward compatibility: existing API calls and defaults must preserve behavior.
Check baseline output and classify every difference before migrating the consumer.
Do not change sing-box/xray/AWG or neighboring builders outside the approved scope.
Keep diffs minimal and preserve existing style and line endings; upstream contains mixed EOL.

Current MIPS extension: buildFromRequest passes options.mihomoTunStack into opts.tun.stack; buildMihomoYaml uses it for ordinary TUN and every TUN listener.
Only exact 'mips' selects MIPS; missing/invalid falls back to 'gvisor'. No-TUN remains no-TUN.
MIPS requires Mihomo >= 1.19.31.

## Mandatory checks before changes

1. Read this file and the consumer documentation for the affected contract.
2. Run git status --short, git branch --show-current, git remote -v, and git log -5 --oneline. Confirm work is happening on a custom/candidate branch.
3. Do not overwrite unrelated or foreign changes. Identify whether the change belongs to the engine or UI layer and define scope.
4. Inspect source functions, existing tests, and build scripts; record the baseline consumer runtime and source SHA. Do not start by editing the bundle.

## Mandatory checks after changes

Run commands sequentially and stop on any non-zero exit code:

~~~bash
npm ci
node --test tools/tests/mihomo-exclude-filter.test.mjs tools/tests/mihomo-tun-stack.test.mjs
npm run build:web:runtime
node --check src/web4core.runtime.js
npm run test:amnezia
node ../link-generators/tests/runtime.cjs src/web4core.runtime.js
git diff --check
git diff --stat
git status --short
~~~

Adapt the neighboring checkout path to the actual workspace. In addition:
compare the generated runtime with the consumer copy (bytes/SHA-256, accounting for CRLF separately),
run the consumer browser suite and baseline tests; for new Mihomo output contracts, run a real mihomo -t of the target version on synthetic fixtures.
Do not present browser validation as a core-level validation or handshake.
Run tests for other affected cores according to their contracts.
Update docs and provide a review summary: files, diff-stat, tests, build, runtime comparison, and risks.
Commit/push only after explicit owner instruction.

## Upstream sync and security

Use a controlled merge: fetch upstream and origin, create a separate candidate branch from origin/link-generators, run merge --no-commit --no-ff upstream/main, review it, run tests/build/consumer regressions, then use an approved PR and review before merge.
The detailed procedure and option comparison are in [UPDATES.md](https://github.com/saymer-alt/link-generators/blob/main/docs/UPDATES.md).
If there is a conflict, stop and publish nothing; use git merge --abort when needed.
If tests fail, do not publish the candidate.
Do not force-push, reset the custom branch to upstream, suppress conflicts with blanket ours/theirs, or disable tests.
Do not enable scheduled auto-merge/rebase without a separate security review.

Upstream sources, npm install scripts, and dependencies execute code.
Before running them, review source/package-lock/build/workflows.
CI build/test must run without write tokens, secrets, or persisted Git credentials.
A write job must not execute external source code or a generated artifact.
Green tests do not replace supply-chain review.

The inherited .github/workflows/build.yml targets upstream main, Pages, and Cloudflare deployment and expects secrets.
Do not enable it in the fork or add secrets just to "fix CI" without a separate owner decision.
It is not the custom-branch CI.
The consumer workflow validates the custom branch; the local checks above remain mandatory.

Use only synthetic TEST-NET addresses and test keys.
Never put real private configs, subscription URLs with credentials, keys, or tokens into fixtures, logs, commits, issues, or third-party services.
Do not add telemetry or network calls to user flows without separate approval.

## Primary/fallback extension

Optional fallbackInput is a generic Mihomo contract; see [tools/tests/PRIMARY-FALLBACK.md](tools/tests/PRIMARY-FALLBACK.md).
Run node --test tools/tests/mihomo-priority.test.mjs together with the existing source tests.
Consumer-specific whitelist policy stays outside the engine.
