# 0094. macOS: явный Seatbelt launcher без Apple Developer

Статус: принято. Дата: 2026-11-26.

## Решение

У проекта нет Apple Developer identity. Не считаем наличие plist, ad-hoc подписи
или `com.apple.security.app-sandbox` доказательством ограничения самостоятельно
запущенного CLI. Используем `/usr/bin/sandbox-exec` с deny-default Seatbelt:
это работающий механизм для unsigned/ad-hoc бинарников, а не подписанный App
Sandbox bundle. `sandbox-exec` устарел; его исчезновение или отказ политики
завершает запуск, без повторного exec исходного бинарника.

`nw-sandbox::macos::Profile` и одноимённый CLI встраивают SBPL из репозитория.
Роли: `nymwrapd`, `nw-api`, `nw-llmd`, `nw-netd`, `nw-drift-host`,
`nw-audit-worker`, `ui`. Полоса обязательна: Drift — cover, API/LLM/netd/импорт —
shadow, core/UI запускаются отдельным экземпляром для выбранной полосы.
Одна роль `nw-netd` получает исходящий IP и bind, без IP listen/inbound.
Это не Tor-only firewall: leakcheck, разрешённый транспорт и fail-closed
остаются обязательны. Доступ к геолокации, Wi-Fi, IOKit и Mach-службам не выдаётся.

По умолчанию доступны только чтение публичных системных библиотек, метаданных,
timezone, случайных устройств и собственного executable. Дополнительные права:

- Один уже существующий приватный каталог процесса/полосы, владелец — текущий
  пользователь, без group/world доступа. Корень ФС, системные деревья-родители,
  домашний каталог и его родители отвергаются. Внутри хранится только шифротекст;
  sandbox не заменяет шифрование. Без `--container` пользовательских файлов нет.
- Точные read-only regular files только для модели/импорта; целые деревья не
  выдаются. Пути передаются через `-D`, не вставляются в язык SBPL.
- Точные существующие Unix-сокеты текущего пользователя с mode 0600; произвольные
  служебные сокеты недоступны. Это клиентские подключения; существующие
  peer/PID/AEAD проверки `nw-ipc` по-прежнему обязательны.
  Создавать серверные Unix-сокеты можно только внутри собственного контейнера.

Пути абсолютные, UTF-8, канонические, без управляющих символов. Среда очищена;
секретов в argv/env нет. CLI делает exec, сохраняя PID и bootstrap pipes.
Доверенный coordinator выбирает executable и раздельные, не вложенные контейнеры,
не передаёт посторонние открытые файлы/сетевые fd и подключает children отдельно:
fork/exec произвольных children, Keychain и WebView/XPC этот минимальный профиль
не разрешает. Сам coordinator не является песочницей.

## Проверка и границы

Обязательный `macos-sandbox` CI на `macos-latest` проверяет реальные процессы под
каждой ролью и допустимой полосой: `PermissionDenied` при чтении/записи внешней
синтетической канарейки, symlink из контейнера, TCP connect и TCP/UDP bind
IPv4/IPv6 у offline-ролей; положительные чтение/запись контейнера и точный IPC.
Только netd доставляет TCP/UDP к локальным контролируемым endpoints, внешняя
канарейка ему также недоступна. Создание socket fd не используется как oracle.
CLI отдельно проверяется на успешный exec и закрытые коды ошибок.

Существующие `nw-probe`, `macos_probe.rs` и самопроверка `bind`/`connect` ADR 0085
не меняются и запускаются в том же CI. Probe намеренно имеет собственный
read-only профиль источников устройства; помещение его в обычный offline
профиль сломало бы инвентаризацию.

Это проверяемые профили и интерфейс запуска, не завершённая интеграция всех
production демонов: desktop/core пока не вызывают новый launcher автоматически.
Также не проверены GUI/WebView, Keychain, supervisor всех children и полный
Tor bootstrap внутри нового netd-профиля. Обычный desktop нельзя объявлять
изолированным по результату теста роли. M6 целиком остаётся открытым, Linux и
Windows не меняются. Внешних зависимостей не добавлено; cargo-vet не получает
новых внешних пакетов (в leak tests добавлена существующая workspace-связь).

Источники: [Apple: App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox),
[Apple: embedded helper и ad-hoc подпись](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app),
[реализация Seatbelt launcher](https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt.rs).
