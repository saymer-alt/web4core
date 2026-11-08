# kas-mini — KAS Mini Mihomo Generator (Phase 0, experiment-only)

Изолированный прототип к issue [saymer-alt/keenetic-auto-setup#425](https://github.com/saymer-alt/keenetic-auto-setup/issues/425):
очень маленький **локальный** генератор нового полного `config.yaml` для Mihomo, только для роутера KAS.
**Не** копия Link Generator 1.12, **не** интеграция в KAS Web beta.8, без merge/release без отдельного owner GO.

## Что это

- Каталог целиком экспериментальный: 5 файлов + `dist/`, ничего в `src/`, `src/build.js`, UI и парсерах main не меняется.
- Переиспользует неизменённые модули web4core main: `src/main.js` (парсинг URI), `src/core/mihomo.js`,
  `src/core/yaml.js`, `src/core/wireguard.js`. Новый код — только glue-слой `entry-kas-mini.js`:
  построчный честный разбор ссылок, нативные провайдеры без fetch и без HWID-заголовка,
  слой отказа для WG/AWG-полей, безопасные дефолты (owner-таблица из issue #425 от 08.11.2026).

## Сборка (только ПК/CI)

```bash
npm ci                          # esbuild ^0.27.2 уже в devDependencies
node kas-mini/build-mini.mjs    # → kas-mini/dist/{index.html, kas-mini.js} + JSON-размер
node --test kas-mini/kas-mini-tests.mjs
```

Без npm esbuild можно подставить standalone-бинарником: `ESBUILD_BIN=/path/esbuild node kas-mini/build-mini.mjs`.

## Дефолты (owner-таблица, 08.11.2026)

| Переключатель | Дефолт | Семантика |
| --- | --- | --- |
| 🌐 Allow LAN | ON | `allow-lan: true` + `bind-address: '*'` (все интерфейсы; WAN ограничивает firewall роутера) |
| 🔌 Mixed Port | ON, 7890 | комбинированный HTTP+SOCKS5 `mixed-port`, целое 1–65535; выключение переключателя убирает слушатель из YAML; порт 9090 при включённом Web UI → отказ (конфликт слушателей), остальные «занятые» порты → warning |
| 🖥️ Web UI | ON | `external-controller: 0.0.0.0:9090` + MetaCubeXD preset + **сгенерированный secret** (небезопасный шаблонный блок web4core с пустым secret не используется) |
| 📡 URL-подписки | OFF | при включении URL становятся нативными `proxy-providers` + `proxy-groups.use`; без fetch в браузере; URL при выключенном тумблере — явная ошибка-подсказка |
| 🛡️ TUN | ON | `tun` c `auto-route: false`, без авто-маршрутов/DNS hijack/NAT |
| ⚡ MIPS stack | ON при TUN ON | `tun.stack: mips`, требует Mihomo ≥ 1.19.31; gvisor — только явным отключением |

## Границы (Phase 0)

- Ровно три входа: ссылки (построчно, честный счёт принятых/отклонённых), URL-подписки (нативные провайдеры),
  WG/AWG `.conf/.wg/.awg` (мультивыбор; поля, которые web4core потерял бы молча — DNS, неизвестные ключи,
  нечисловые MTU/keepalive, не-boolean AWG-флаги — отклоняют **весь файл** с понятной ошибкой).
- Вывод: read-only предпросмотр → «Скачать YAML». Никакого импорта/автоприменения из прототипа.
- Свежесть результата (round-2 ревью): любое изменение входных данных (ссылки, подписки, настройки,
  WG-файлы) инвалидирует сгенерированный YAML — предпросмотр очищается, скачивание блокируется
  до следующего «Создать YAML»; при ошибке генерации предыдущий YAML также удаляется
  (централизованно: чистая машина `createMiniUiState` + `invalidateGeneratedYaml()` в index.html).
- Асинхронная гонка выбора WG/AWG-файлов закрыта (round-3 ревью): инвалидация выполняется
  синхронно до первого `await` чтения файлов; на время чтения «Создать YAML» заблокирована
  (восстановление в `finally`); чтение — all-or-nothing (`readWgFileEntries`), ошибка чтения
  показывается явно, частичный «успех» и необработанные исключения исключены.
- Нет: второго exclude-filter-редактора, YAML round-trip, изменения существующих конфигов,
  хранения ввода (localStorage/cookies), сетевых запросов во время генерации, VPS-режимов, rule-providers,
  per-proxy TUN/SOCKS, маршрутизации, автозапуска.

## Известные ограничения (честно)

- WG/AWG `.conf` с `DNS =` отклоняется: парсер DNS читает, но builder его в wireguard-proxy не эмитит
  (проверено и на main, и на ветке link-generators). Отказ вместо молчаливой потери параметра.
  Кнопка помечена «экспериментально, ограниченная поддержка».
- **Post-POC решение (требуется owner GO, вне этого PR):** доказанное представление WG DNS в Mihomo-конфиге,
  либо явный информированный opt-in на пропуск file-local DNS, — с тестами `mihomo -t`. Без silent-drop и
  без правок общих парсеров в Phase 0.
- URL-подписки валидируются строгим разбором URL (http/https, обязательный хост, без userinfo-секретов,
  без пробелов/табов внутри); некорректные строки отклоняются с redact-эхом, не попадают в провайдеры.
- Ограниченный `mihomo -t` выполнялся вне этой PR-среды на ПК (официальный Mihomo Meta v1.19.33
  windows-amd64-compatible, изолированный temp-каталог): 4/4 синтетических конфигов, сгенерированных
  самим kas-mini, — «test is successful». FIELD на реальном роутере остаётся **NOT_TESTED**.
- Тестированное подмножество форматов: VLESS Reality (TCP), Hysteria2 (obfs), Trojan (WS), WG/AWG single+multi-peer.
  Остальные протоколы проходят через неизменённые парсеры web4core, но не тестировались здесь.
- FIELD на реальном роутере не выполнялся и не заявляется.
