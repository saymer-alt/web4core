# AGENTS.md — web4core fork для link-generators

## Репозитории и ветки

- `spatiumstas/web4core` — upstream.
- `saymer-alt/web4core:main` — база, максимально близкая к upstream/main; не вносить
  сюда наши расширения. Обновление зеркала — fast-forward, без переписывания истории.
- `saymer-alt/web4core:link-generators` — рабочая source-level ветка. Parser, builder
  и protocol support для link-generators реализуются здесь.
- Remotes: `origin` → `https://github.com/saymer-alt/web4core.git`,
  `upstream` → `https://github.com/spatiumstas/web4core.git`.
- `saymer-alt/link-generators` — отдельный UI/browser consumer готового runtime.
  Его формы, UX и UI-specific post-processing находятся в том репозитории.

Общая карта и выбор слоя: [WEB4CORE-FORK.md](https://github.com/saymer-alt/link-generators/blob/main/docs/WEB4CORE-FORK.md).
Правила этого файла относятся к custom branch; main остаётся зеркалом upstream.

## Исходники и generated-файлы

- `src/main.js`: share/input parsing, beans, validation/core support; перед изменением
  найти реальные функции и таблицы, не ориентироваться только на имя схемы.
- `src/build.js`: публичный `buildFromRequest`, нормализация/передача options.
- `src/core/mihomo.js`: Mihomo proxies/config/subscriptions;
  `src/core/yaml.js`: YAML emission, ordinary TUN и Per-Proxy listeners.
- `src/entry-web4core.js`: browser runtime entry point и публичные exports.
- `tools/tests/`: существующий native `node:test`; новые тесты следуют этому стилю.
- `package.json` и lockfile определяют сборку. `npm ci`, затем
  `npm run build:web:runtime` → **`src/web4core.runtime.js`**.
- Generated runtime, `src/ui.js`, worker dist руками не редактировать и не добавлять
  в Git вопреки `.gitignore`. Consumer получает только результат сборки.
  Textual patches по готовому bundle не вводить.

## Контракты и scope

Новый протокол проходит всю цепочку:

```text
share/input parser → bean → validation/core support → Mihomo builder → tests → build
```

Parser сам по себе не доказывает end-to-end поддержку. Добавить позитивные и негативные
кейсы, сопоставить поля с целевой версией ядра; синхронизировать consumer validator,
README и docs только после подтверждения всей цепочки и реального `mihomo -t`.
Новые протоколы добавляются только по отдельной задаче владельца, не попутно.

Backward compatibility: старые вызовы API и дефолты должны сохранять поведение.
Проверять baseline output; любые отличия классифицировать до миграции consumer.
Не менять sing-box/xray/AWG и соседние builders без согласованного scope.
Минимальные diff; сохранять существующий стиль и переводы строк (в upstream есть mixed EOL).

Текущее расширение MIPS: `buildFromRequest` передаёт `options.mihomoTunStack` в
`opts.tun.stack`; `buildMihomoYaml` использует его в ordinary TUN и каждом TUN listener.
Только точное `'mips'` → MIPS; missing/invalid → `'gvisor'`. No-TUN остаётся no-TUN.
Требование ядра для MIPS — Mihomo >= 1.19.31.

## Обязательные проверки до изменения

1. Прочитать этот файл и документацию consumer по затронутому контракту.
2. `git status --short`, `git branch --show-current`, `git remote -v`,
   `git log -5 --oneline`. Убедиться, что работа ведётся в custom/candidate branch.
3. При чужих изменениях не перезаписывать их. Определить engine/UI слой и scope.
4. Изучить source-функции, existing tests и build scripts; зафиксировать baseline
   consumer runtime и source SHA. Не начинать с редактирования bundle.

## Обязательные проверки после изменения

Команды выполняются последовательно, с остановкой при ненулевом exit code:

```bash
npm ci
node --test tools/tests/mihomo-exclude-filter.test.mjs tools/tests/mihomo-tun-stack.test.mjs
npm run build:web:runtime
node --check src/web4core.runtime.js
npm run test:amnezia
node ../link-generators/tests/runtime.cjs src/web4core.runtime.js
git diff --check
git diff --stat
git status --short
```

Путь соседнего checkout адаптировать к фактическому workspace. Дополнительно:
сравнить generated runtime с consumer (байты/SHA-256, отдельно учесть CRLF),
запустить consumer browser suite и baseline; для новых Mihomo output contracts
запустить настоящий `mihomo -t` целевой версии на синтетических fixtures.
Не выдавать browser validation за проверку ядром или handshake.
Тесты других затронутых cores запускать по их контрактам.
Обновить docs и показать review: файлы, diff-stat, тесты, build, сравнение runtime,
риски. Commit/push — только после явной инструкции владельца.

## Upstream sync и безопасность

Использовать controlled merge: fetch upstream и origin, отдельная candidate branch
от origin/link-generators, `merge --no-commit --no-ff upstream/main`, review,
tests/build/consumer regressions, затем разрешённый PR и review до merge.
Подробная процедура и сравнение вариантов —
[UPDATES.md](https://github.com/saymer-alt/link-generators/blob/main/docs/UPDATES.md).
При конфликте остановиться, ничего не публиковать; при необходимости `git merge --abort`.
При падении тестов не публиковать candidate. Не делать force-push, reset custom branch
на upstream, подавление конфликтов через blanket ours/theirs или отключение тестов.
Не включать scheduled auto-merge/rebase без отдельного security review.

Upstream исходники, npm install scripts и зависимости исполняют код. Перед запуском
review source/package-lock/build/workflows; CI build/test — без write-token, secrets
и сохранённых Git credentials. Write-job не должен исполнять внешние исходники
или generated artifact. Зелёные тесты не заменяют supply-chain review.

Унаследованный `.github/workflows/build.yml` ориентирован на upstream main, Pages и
Cloudflare deployment и ожидает secrets. Не включать его в fork и не добавлять secrets
для «починки CI» без отдельного решения владельца. Он не является custom-branch CI.
Consumer workflow проверяет custom branch; локальные проверки выше обязательны.

Использовать только синтетические TEST-NET адреса и тестовые ключи. Реальные приватные
конфиги, subscription URLs с credentials, ключи и токены не помещать в fixtures,
логи, коммиты, issues или сторонние сервисы. Не добавлять телеметрию и сетевые вызовы
в пользовательские потоки без отдельного согласования.
