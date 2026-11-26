# Полнота источников устройства и обязательная изоляция PT

## Контекст

Список `unavailable` не доказывает, что worker вообще проверил каждый источник:
старый или неполный отчёт мог ошибочно разрешить внешний выход. macOS не имела
нативного worker; успешный запуск Lyrebird из ADR 0048 не доказывал ни bridge
bootstrap, ни изоляцию от файлов core. Отдельно согласовано пользователем:
strict/paranoid сохраняют запрет L3, хвост недоступен до более сильного маршрута.

## Решение

Отчёт содержит явное `observed` для каждого из девяти источников. Успешное пустое
перечисление и ошибка различаются; неполный/непредставимый источник неизвестен.
Core требует свежесть, отсутствие ошибки и полное покрытие. Старые сохранённые
отчёты обновляются один раз по версии покрытия, без цикла повторов при отказе.
Найденные значения частичного источника всё равно защищаются; ручные удаления
сохраняются. Hints окружения дополняют значения, но не доказывают полноту.

Windows получает домашний путь из токена и локальной API, без поиска в домене.
macOS читает passwd, CoreFoundation/SystemConfiguration/IOKit и getifaddrs;
до входного IPC доверенный worker применяет deny-default Seatbelt, без сети,
записи и spawn. Git передаётся отдельным read-only fd. Старый KnownNetworks не
доказывает полноту современного Wi-Fi, источник остаётся неизвестным. Новые
location/Wi-Fi capabilities не запрашиваются. При отказе sandbox нет fallback.

Нативный run 45769281372 подтвердил, что Seatbelt на GitHub macOS runner
устанавливается, но Darwin разрешает создать пустой IP socket fd и применяет
запрет при сетевой операции. Поэтому самопроверка до чтения IPC требует именно
`PermissionDenied` от `bind` и `connect` для TCP/UDP IPv4/IPv6; успешная операция
или иной код ошибки завершает worker. Если уже `socket` возвращает
`PermissionDenied`, это также строгий запрет. Ошибка `sandbox_init` остаётся
явным `probe_sandbox_unavailable`, падает в обязательном CI и не превращается в
skip или запуск без песочницы.

Гигиена использует только трёхзначные наблюдения: NetBIOS по всем прочитанным
Windows-интерфейсам, Linux read-only adjtimex и ограниченный буквальный JSON
политик Firefox по умолчанию. Для положительного browser verdict нужны оба
`Value=false, Status=locked`, однозначная установка и отсутствие непроверенного
переопределения. macOS не получает Pass по одному файлу при неизвестных managed
preferences. mDNS и неизмеренные часы неизвестны; наличие службы не подтверждает
расхождение. Multicast Pass требует трёх подтверждённых отключений. Оценка Pass/6
из ADR 0051 сохраняется, ошибка последней проверки не даёт свежую оценку.

Runtime-managed PT всегда требует изоляцию: Linux bwrap оставляет транспортный
netns netd, но отделяет user/mount/PID/IPC/UTS/cgroup, снимает capabilities,
нормализует окружение и монтирует только публичную систему, закреплённый бинарник
и собственное шифрованное состояние. macOS применяет фиксированный sandbox-exec
профиль. Windows отклоняет запуск до интеграции изолированного SOCKS-процесса;
UI показывает ограничение. Повтора без песочницы нет. Низкоуровневый тестовый
IPC launcher сохраняет прямой запуск синтетических environment/lifetime fixtures;
production TransportConfig принудительно включает изоляцию. Новых внешних
зависимостей нет; включена только возможность Shell уже закреплённого windows-sys.
Управляющие строки и ошибки PT возвращаются/журналируются только как фиксированные
коды; канареечная регрессия проверяет восемь вариантов, чтобы сырой параметр
не попал в журнал вызывающего слоя через Display/Debug ошибки.

Backend и UI разрешают автоматический хвост только standard/Tor L3 с валидной
конфигурацией. Старое согласие strict/paranoid не обходит запрет; L1/L2 и очередь
индивидуальных одобрений не реализуются в этой задаче.

## Почему

Неизвестность безопаснее ложной полноты и запуска PT с доступом к vault.
Отдельный trusted probe читает только необходимые источники, не ослабляя запрет
сети для процессов с пользовательскими данными. Частичные наблюдения полезны
для защиты найденных значений и ручной гигиены, но не заменяют доказательств.

CI расширяет локальный Tor-сценарий ADR 0084 вариантом obfs4: единственный
разрешённый внешний порт — локальный мост, проверяются настоящие PT namespaces,
завершение PT при живом Tor/provider и отсутствие fallback в pcap. Те же 16
канареек покрывают девять источников и семь детекторов. Отдельный CI job сравнивает
реальные нормализованные HTTP/ClientHello bytes из Windows/Linux/macOS artifacts;
обновление golden в CI запрещено. Профиль TLS и правила нормализации не меняются.

Закреплённый Chutney раскрывает `${path:obfs4proxy}` только поиском исполняемого
файла в `PATH`; произвольное поле Node с абсолютным путём он игнорирует. Поэтому
CI создаёт в закрытом fixture-каталоге две сверенные байт-в-байт копии уже
проверенного по manifest Lyrebird из Tor Expert Bundle: `lyrebird` для Arti и
ожидаемую Chutney `obfs4proxy`; затем добавляет только этот каталог перед
системными `/usr/bin:/bin` в очищенный `PATH` Chutney. Отсутствие или изменение
закреплённого бинарника завершает job; поиск неуправляемого PT и fallback
запрещены.

Run 45770464485 подтвердил следующий независимый pre-log отказ Tor 0.4.9.11:
его встроенный `Sandbox 1` несовместим с любым managed
`ServerTransportPlugin`. Поэтому `Sandbox 0` задан только синтетическому
Chutney bridge-серверу внутри relay netns без default route. Это не production
PT и не проверяемая клиентская граница: production Lyrebird всё равно обязан
пройти отдельные bwrap, namespace, UID/capability/NNP и stop-with-live-Tor
проверки; fallback без этой песочницы не добавляется.

В том же run все семь узлов достигли bootstrap 100%, но строгая проверка
дескриптора моста отказала: custom topology не содержала bridge authority.
Проверка не пропускается: как в закреплённой upstream `networks/bridges-obfs4`,
четвёртый authority имеет отдельную роль bridge authority. Три обычных authority
сохраняют consensus, а номера exit/bridge/client 004/005/006 не меняются.

Run 45775540765 подтвердил strict bridge-authority bootstrap, полную нагрузку и
наблюдение PT isolation, но обнаружил границу владения evidence: root-only observer с
`umask 077` создаёт `bridge-evidence.json` с режимом `0600`, а следующий шаг
проверки намеренно возвращается к UID/GID runner. После проверки, что это
обычный файл, а не symlink, CI явно передаёт его закреплённым UID/GID и
проверяет результат. Режим `0600` не расширяется, сетевые и namespace-
проверки не меняются.
Отдельный obfs4 job run 45778330605 для 523554d затем прошёл полностью:
100 HTTPS-запросов, из них 84 M3 cover, ноль canary/direct-provider/DNS packets,
все isolation и stop-with-live-Tor признаки `true`. XML PDML объёмом
47 403 763 байта прошёл ограничение ADR 0084.

Runs 45775540765 и 45778330605 выявили отдельное окно готовности тестовой
сети: Chutney считает клиента bootstrapped после internal circuit, но первый
подписанный microdescriptor consensus ещё не содержит единственный exit. В
первом run Arti потерял достаточную долю microdescriptors после 23 запросов;
во втором production preflight отказал до первого HTTP-запроса, а Chutney
затем зафиксировал `The current consensus contains exit nodes`.

Тестовая сеть теперь до запуска Arti ожидает `Exit` в подписанном
`cached-microdesc-consensus` Chutney client. Ожидание ограничено теми же 180
секундами, что и fixture bootstrap; отсутствие exit явно падает. Production
повторы, таймауты и fail-closed поведение не меняются.

## Границы

M3H закрыт run 45780888200 для 1e1ae69: нативный macOS sandbox, Linux
PT/pcap, obfs4 isolation и межплатформенное совпадение protocol golden зелёны.
Obfs4 report содержит 100 запросов, 84 cover, ноль canary/direct/DNS и все
isolation/stop признаки `true`. Snowflake/WebTunnel пока имеют только проверку
запуска/lifetime, не локальный bootstrap. Windows PT, macOS encrypted
transport directory, WSL2 агентов и общие песочницы core/netd остаются открытыми.
Наблюдение настроек браузера не является инспекцией всех пользовательских профилей.

Первичные источники: [Mozilla Preferences](https://firefox-admin-docs.mozilla.org/reference/policies/preferences/),
[расположение политик](https://firefox-admin-docs.mozilla.org/guides/policies-configuration/),
[adjtimex](https://www.man7.org/linux/man-pages/man2/adjtimex.2.html),
[Apple IOService](https://developer.apple.com/documentation/iokit/1514535-ioservicegetmatchingservice),
[LaunchServices binding](https://developer.apple.com/documentation/coreservices/1448824-lscopydefaultapplicationurlforur?language=objc).
