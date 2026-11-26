# Состояние реализации

Обновлено: 2026-11-26. Работа продолжается по SPEC. Этапы закрываются только после
проверки всех критериев в CI. Tor с ключом провайдера (L3) требует standard и
полной проверки секретов устройства либо явного отключения автоматического сбора
в конфигурации. Текущий Windows probe сообщает недоступные user/Wi-Fi источники;
при включённой защите устройства удалённая отправка закрыта, L0 доступен.
strict/paranoid отклоняют маршрут L3. Интерфейс показывает фактический уровень ответа.

## Задача 11 — воспроизводимая сборка

Добавлены общий `scripts/repro-build.mjs`, два независимых CI job на разных
Linux runner'ах и обязательное сравнение фактических SHA-256 полного набора.
Чистые Docker-окружения закрепляют Rust/Node по OCI digest, Debian snapshot,
lockfile, CPU target, пути и время архивов; Cargo/CMake ограничены четырьмя
заданиями. Архив включает desktop, core/API/workers, netd, lyrebird и оба
расширения. Прилагаются файловый манифест, buildinfo и проверяемый source SBOM.
ADR [0098](adr/0098-reproducible-linux-release.md) фиксирует область Linux x86_64
и честные границы Windows/macOS и SBOM; новых зависимостей приложения нет.

`release.yml` допускает только ручной запуск на version tag или push тега.
После успешной независимой пересборки он создаёт неподписанный draft Release.
Подпись остаётся локальной у владельца (существующие скрипт/ключ ADR 0080);
секреты Actions, updater и runtime-сеть не добавлены. ADR
[0099](adr/0099-owner-signed-release-handoff.md) и USER_GUIDE описывают скачивание,
локальную пересборку, сравнение, sign, загрузку SHA256SUMS/SHA256SUMS.sig и verify.
Release workflow и теги при выполнении задачи не запускаются/не создаются.
Результаты локальных проверок и CI фиксируются после прогона; полное M6 остаётся
открытым до остальных критериев THREAT_MODEL §9 и подписи владельцем.

## Задача 10 — фаззинг 24 часа

Проверена подготовленная кампания на a120a5f: три цели `audit_import`,
`ipc_frames`, `shield_roundtrip`, для каждой шесть последовательных сегментов
по четыре часа с передачей корпуса. Лимит segment job — пять часов, меньше
шестичасового ограничения GitHub-hosted runner. Итог требует все 18 receipts,
проверяет commit/run/attempt, SHA бинарника и цепочку корпуса, wall/engine time;
preflight в 24 часа не входит. Это 24 часа с перезапусками, не непрерывный процесс.
[ADR 0096](adr/0096-task10-hosted-fuzz-campaign.md) фиксирует проверку; workflow не
менялись. Локальный фаззинг не запускается.

Статус на 2026-11-26: preflight [run 45810869006](https://github.com/dsahakyan15/NymWrap/actions/runs/45810869006)
зелёный (три цели собраны). Суточная кампания запущена на main 916a5e8:
[run 45813366602](https://github.com/dsahakyan15/NymWrap/actions/runs/45813366602).
Кампания и пункт M6 пока не закрыты; run ID и результаты будут внесены после запуска.

## cargo-vet: граф desktop

2026-11-26: история **514 → 343 → 292 → 89**; четвёртый проход от `2791eb5`
в `agent/vet-desktop-4` дал **89 → 10 → 9 пробелов**. Добавлены **77 решений
доверия 60 identities**, **2 source audits** и **1 точечное exemption**.
Критерий `safe-to-deploy`, версии, все tracked Cargo.lock и другие графы сохранены.

У каждой новой записи — «Проверено агентом, не человеком», SHA архива,
прочитанный материал и ограничения. Registry evidence повторно взято из
закоммиченного третьего отчёта; архивы сверены с desktop lockfile и cached
sparse index. Publisher snapshots обновлены cargo-vet и сверены с решениями.
77 однодневных записей — product publisher trust, не независимые построчные
проверки этих пакетов. Source pins шести imports и их audit sections сохранены.

Собственные аудиты: `version-compare 0.2.1` (весь production-код;
best-effort ordering, ограничения CPU и build-time consumer отражены в notes)
и `foreign-types-macros 0.2.4` (все source modules и generated unsafe contracts).
Прошли **30 upstream tests**, Unicode/overflow/bounds probe и synthetic
owner/borrow/Clone/borrowed-ToOwned/Drop integration test макросов.

`portable-atomic 1.15.0`: все **66 негenerated-файлов** архива совпали с тегом.
VCS SHA — release commit, OIDC SHA — его родитель, на котором workflow
запустился до создания release commit; прочитан pinned release workflow.
Расхождение объяснено, добавлено ограниченное доверие официальному workflow.
Все **9 DLL/LIB WebView2** совпали с upstream и Microsoft-owned NuGet package;
инструкции бинарей построчно не проверялись, signature chain не проверялась.

`dirs-sys 0.5.0`: две slice panics воспроизведены на published parser с ASCII
OS-string shim на Windows. Native Unix run не заявляется. В текущем deployment
нет вызывающих native path calls, core path permissions и download handler;
дополнительный путь Wry проверен. Safe-to-deploy audit не выдан; добавлено
exemption только для этой версии со ссылкой на анализ и условиями пересмотра.
Registry latest остаётся 0.5.0, исправленной опубликованной версии не найдено.
Обязательное обновление по завершённому анализу не установлено; остаток ещё
может выявить проблемы, версии для него не выдумывались.

Финальный `node scripts/vet-dependencies.mjs desktop` — **failed, 9 gaps**,
locked inputs неизменны. **Wrapper дополнительно отвергает любое exemption**;
его правило сохранено, поэтому даже устранение девяти пробелов недостаточно
для зелёного gate. Desktop `cargo-deny 0.22.0` — **exit 0**, все четыре checks ok.

Остаток: `dbus-secret-service`, `ordered-stream`, `recvmsg`, оба
`serialize-to-javascript*`, `sqlcipher-src`, `vswhom`, два GNU winapi packages.
Причины, версии, SHA, checkpoints и дальнейшая работа — в
[четвёртом отчёте](../supply-chain/desktop/review-2026-11-26-desktop-4.json);
решения и раздел «Требуют обновления» — в
[ADR 0104](adr/0104-desktop-dependency-audit-sources.md).
История сохранена в [третьем отчёте](../supply-chain/desktop/review-2026-11-26-desktop-3.json).
Workspace tests/clippy/leak tests и extension tests в этом проходе **не запускались**
по указанному пользователем scope metadata/docs; прежние failures не объявляются
зелёными. CI не запускался, результат неполный, M6 и gate остаются открытыми.

## cargo-vet: граф root

Задача 9, третья партия от `61c17b5` — 2026-11-26: **88 → 67 пробелов**.
Добавлен **21 исходный аудит агента** с неизменным **safe-to-deploy**.
Версии, все Cargo.lock, policy, imports и остальные графы сохранены;
новых exemptions и доверий публикаторам нет.

История: первая партия `89f3b08` дала **268 → 107**, вторая `9c2fc56` —
**107 → 88**. Предыдущие отчёты сохранены.
[Третий отчёт](../supply-chain/root/review-2026-11-26-batch-3.json) содержит
инвентаризацию всех 88 крейтов по размеру/unsafe/build/proc-macro/FFI/ОС,
SHA архивов и просмотренных файлов, режим чтения, замеры **88 → 72 → 67**
и все оставшиеся 67 пар с критериями и дальнейшей работой.
Метод и ограничения продолжены в [ADR 0102](adr/0102-root-dependency-audit-sources.md).

У каждой новой записи явно стоит «Проверено агентом, не человеком».
Прочитаны manifests и production-код; у ordered-stream большие rustdoc-примеры
не прочитаны целиком, а data tables web_atoms проверены строгим полным разбором
(2231 entity и 1108 имён), без сверки каждого значения со стандартом HTML.
Архивы проверены по Cargo.lock и cached sparse index, crates.io API не вызывался.
В notes разобраны unsafe/FFI/SIMD, генерируемый код, escaping и полномочия build
helpers. Явно сохранены ограничения memoffset на закреплённый Rust 1.100,
локальные allocation leaks xdg-home и воспроизведённая ошибка position_hint
ordered-stream; metadata hints не сертифицированы как граница безопасности.

Без аудита оставлены async-broadcast (рост очереди при capacity=0 + overflow)
и zvariant_derive (паника TryFrom<Value> на короткой Structure), оба случая
воспроизведены; remote reachability в NymWrap не установлена. blocking,
phf_generator и частично прочитанный siphasher также остаются открытыми.
Крупные реализации, getrandom/typenum/generic-array/errno, native C/ASM/FFI
и llama-cpp-2 base/fork не получили неподтверждённых сертификатов.

Проверки: финальный `node scripts/vet-dependencies.mjs root` — failed,
**67 gaps**, imports locked и входы неизменны. Root cargo-deny 0.22.0 — exit 0,
advisories/bans/licenses/sources ok.
[Аудиторский стенд](../supply-chain/root/review-tests-2026-11-26-batch-3.mjs)
прошёл **11/11** в debug, release и ptrhash debug; wrapper — 3/3, расширение —
24/24. Это не полный upstream/cross-platform/timing аудит.
`cargo test --workspace --locked`, `cargo clippy -- -D warnings` и leak tests
вызваны, но завершились exit 1 на сборке OpenSSL: executable perl не найден.
Инструменты не устанавливались. Root vet fmt, rustfmt стенда и
`git diff --check` выполнены. CI не запускался; root gate и M6 остаются открытыми.


## cargo-vet: граф netd

2026-11-26, [ADR 0103](adr/0103-netd-dependency-audit-sources.md): **499 → 312 → 253 пробела**
для `daemons/nw-netd/Cargo.toml`. Критерий продукта `safe-to-deploy` сохранён;
версии, все Cargo.lock, манифесты и остальные stores не менялись. Новых exemptions нет.
Результат промежуточный, M6 и dependency-audits netd остаются открытыми.

Четыре импорта закреплены по commit: Bytecode Alliance, ISRG, Zcash, Embark.
Замеры: **499 → 475 → 470 → 464 → 461**. Проверка полного дерева официального Arti
не нашла cargo-vet store на рассмотренной ревизии; импорт Tor не добавлен.
145 записей доверия для конкретных пакетов, публикаторов и исторических UTC-дней
с отдельным обоснованием для продукта дали **461 → 316**. После HTTP 429 у crates.io
для 19 точных версий использованы сохранённые подтверждения ADR 0088; это отмечено
в [JSON-отчёте](../supply-chain/netd/review-2026-11-26.json). Там же находятся
метаданные publisher lock, хеши, каждый промежуточный замер и полный остаток.

Первые четыре исходных аудита имеют SHA архивов и пометку «проверено агентом, не человеком»:
wasm-bindgen-shared, wasm-bindgen-macro, version_check, crypto-common.
Последовательность — **316 → 315 → 314 → 313 → 312**.

Продолжение от `265e336`: все **36 Arti/Tor** получили отдельное доверие
публикатору `gabi-250` (crates.io user-id 31201) только на UTC-сутки
`[2026-11-04, 2026-11-05)`: **312 → 276**. Связь с Tor подтверждена официальной
страницей команды, совпадением отпечатка ключа Tor/GitHub, GitLab identity и
тегом Arti 2.8.0, перечисляющим точные версии; VCS всех архивов совпадает с его
commit. Ещё девять вспомогательных пакетов того же релиза дали **276 → 267**.
Это доверие сопровождению для `safe-to-deploy`, не независимый исходный аудит;
локальные изменения трёх forks по-прежнему требуют отдельного просмотра.

Восемь проверенных GitHub publisher identities и отдельное доверие libm дали
**267 → 255**. Два новых исходных аудита агента — strum 0.28.0 и displaydoc 0.2.7 —
дали **255 → 254 → 253**. Для всех записаны SHA архивов; критерий не ослаблен.
Все шаги, основания, URL/SHA ответов реестра и полный остаток находятся в
[отчёте продолжения](../supply-chain/netd/review-2026-11-26-continuation.json).
Запросы crates.io выполнялись последовательно, с паузами и кэшем в target/.

Среди остатка — typenum, r-efi, bitflags, once_cell, strum_macros и другие
генераторы/unsafe/native-библиотеки. convert_case 0.10.0 не сертифицирован:
на `split(&"a:::b", &[delim_boundary!("::")])` воспроизведён panic;
достижимость из NymWrap не установлена. errno оставлен до проверки контрактов ABI.

Финальный `node scripts/vet-dependencies.mjs netd` подтверждает **253 пробела**,
`check --locked`, неизменность входов и красный gate. `cargo-deny` для netd зелёный.
В изолированных копиях прошли четыре doctest strum; для displaydoc отдельный
harness с неизменёнными upstream-тестами прошёл 3 теста со std и 2 без std.
Полный offline-набор displaydoc не запустился из-за отсутствующего pretty_assertions.
Полноценный Perl подготовлен штатными скриптами; workspace tests, clippy,
leak tests и тесты расширения в этой партии не запускались по согласованному объёму.
Это локальные результаты, не CI; M6 остаётся открытым.

## Задача 9: M6 cargo-vet, только fuzz; локальный gate зелёный — 2026-11-26

Продолжение от `4691e27`: **79 → 0 пробелов**, накопительно **248 → 0**.
Изменены только `supply-chain/fuzz/`, [ADR 0088](adr/0088-fuzz-dependency-audit-sources.md)
и этот существующий раздел. Root/netd/desktop, версии, все Cargo.lock и
fuzz config.toml сохранены. Новых exemptions или wildcard audits нет.
M6 и общий CI остаются открытыми; подтверждён только локальный fuzz gate.

Замеры командой job dependency-audits `node scripts/vet-dependencies.mjs fuzz`:

| Состояние | Пробелов |
|---|---:|
| Исторический baseline 94e6bf9, safe-to-deploy | 248 |
| Первая партия, a120a5f: imports, fuzz safe-to-run и 16 аудитов агента | 193 |
| Предыдущее продолжение, 4691e27: проверенные публикаторы и восемь аудитов | 79 |
| Ещё 64 подтверждённые публикации: 29 user-id и семь GitHub identities | 15 |
| Аудит enumflags2_derive 0.7.12 | 14 |
| Аудит redox_syscall 0.5.18 | 13 |
| Аудит enumflags2 0.7.12 | 12 |
| Аудит blocking 1.7.0 | 11 |
| Аудит async-recursion 1.2.0 | 10 |
| Аудит doctest-file 1.1.1 | 9 |
| Аудит matchit 0.8.4 | 8 |
| Аудит ordered-stream 0.2.0 | 7 |
| Аудит recvmsg 1.0.0 | 6 |
| Аудит uds_windows 1.2.1 | 5 |
| Аудит dtoa-short 0.3.5 | 4 |
| Аудит secret-service 4.0.0 | 3 |
| Аудит constant_time_eq 0.6.1 | 2 |
| Аудит ego-tree 0.11.1 | 1 |
| Аудит scraper 0.29.0 | **0** |
| Финальный check --locked, без обновления imports | **0** |

У новых trusted entries однодневные исторические UTC-окна, отдельные для
каждого пакета/дня и только safe-to-run. API uploader/workflow, дата, отсутствие
yank и SHA-256 каждого архива проверены по API crates.io и sparse index.
Cargo.toml.orig сопоставлен с официальным upstream commit; для workflow также
совпали repository и SHA из реестра с VCS commit архива. У widestring разрешена
только разница CRLF/LF. Это свидетельства происхождения, а решение доверять
конкретному публикатору, его основание и остаточные риски перечислены отдельно
в ADR/отчёте. Native bundles/IPC не выданы за независимый исходный аудит;
незаконченный просмотр typenum покрыт доверием к paholg, не сертификацией агента.

Шесть imports сохранены на прежних commits. Ariel OS рассмотрен и не добавлен:
его исторические futures-lite delta не нужны поверх выбранного точного
публикатора. В imports.lock изменились только publisher-метаданные, чужие
audits/criteria сохранены; чужие exemptions или imports не наследуются.

15 новых аудитов точных версий честно помечены Codex agent, имеют SHA-256 и
только safe-to-run. Приоритет — число транзитивных потребителей (сначала 10,
9 и 8). В notes перечислены прочитанные пути и пределы: raw Redox ABI/pointers,
unsafe/FFI contracts, необязательные квоты recvmsg, caller closures blocking,
доверенный session bus Secret Service и явные file/man-page операции CLI scraper.
Большие обёртки получили целевой просмотр полномочий, не доказательство каждого
unsafe; production-парсеры, криптография и safe-to-deploy не сертифицированы.
Upstream crate-specific tests не запускались.

[Первый отчёт](../supply-chain/fuzz/review-2026-11-26.json) сохраняет 248 → 193,
[предыдущее продолжение](../supply-chain/fuzz/review-2026-11-26-continuation.json) —
193 → 79. [Отчёт завершения](../supply-chain/fuzz/review-2026-11-26-completion.json)
содержит 79 → 15 → 0, каждую точную публикацию и источник доверия, SHA архивов,
границы исходных проверок, промежуточные хеши и финальный receipt.

Проверено локально Windows x86_64, cargo-vet 0.10.4, cargo-deny 0.22.0:

- Финальный `node scripts/vet-dependencies.mjs fuzz`: **check_passed**, exit 0,
  conclusion success, **273 fully vetted**, 0 partial/exemptions, все четыре
  входа неизменны; JSON/stderr/receipt — `target/vet/fuzz.*`.
- `cargo deny --manifest-path fuzz/Cargo.toml --all-features check --hide-inclusion-graph`:
  exit 0, advisories/bans/licenses/sources ok; предупреждения о дубликатах.
- `cargo vet fmt` только manifest/store fuzz; `git diff --check`.
- `cargo test --workspace --locked`: exit 0.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  exit 0.
- `cargo test -p nw-leak-tests --locked`: exit 0, 14 passed, один прежний ignored.
- Тесты расширения: **24/24**.

Логи этой партии — `target/vet/fuzz-task9/completion/`. После исходной ошибки
отсутствующего Perl применены закреплённые Windows build tools; clippy/leak tests
использовали существующий общий target cache при совпадающем Cargo.lock,
workspace tests — target этого worktree. Условия и хеши логов есть в отчёте.
Пользовательское поведение
не менялось. Остаток fuzz — **0**; другие графы и приёмка M6 вне этой задачи.

## Задача 5: оценка Shield/linkcheck отрицательная; этап открыт — 2026-11-26

ADR 0086 фиксирует одноразовый эксперимент. Проверены и объединены восемь
сохранённых development-частей: 384 EN/RU/HY разговора, реальные ответы и
модельный/literal оценщики, production Engine. Сохранённые client/worker SHA
совпали с текущими release-файлами и provenance исходных измерений. Коммит
исходников этих бинарников не аттестован: в freeze явно null, не текущий HEAD.
Измеряется этот удерживаемый кандидат, default production не меняется.

Development отрицательный: remote 86/384 (приватных 33), L0 в 293 разговорах,
отказ в 14, ошибки в 62, полезные арифметические ответы 243/384, канареек 0.
Модельный top-1 приватного выхода — 6/33 (18,18%, CI95 6,98–35,46%) при 1/64
(1,5625%); p=0,0000112. Raw private — 226/296; literal — 296/296, ошибок формата
raw нет. Это не успешная защита; нулевой literal top-1 выхода её не доказывает.

По development сохранены top_k=3/max_margin=0.03, Qwen3-Embedding-0.6B Q8_0 и
Qwen2.5-7B Q4_K_M для защиты, реальных ответов и фактов оценщика. Пороги не
подбирались заново. `freeze.json` создан до held-out; SHA политики, бинарников,
моделей и скриптов проверяется перед каждым запуском. Новый corpus — 360
разговоров, по 24 в каждой EN/RU/HY × пять групп. Новый случайный seed, отдельные
словари всех шести фактов и формулировки задач; пересечения с development
по фактам, секретам и полным вопросам нулевые. Генераторные unit-тесты используют
отдельные validation seeds, не seed настоящего эксперимента.

`linkcheck-experiment.mjs` реализует исходный freeze → generate → восемь частей →
report. До исполнения часть эксклюзивно пишет attempt receipt; повтор/resume
запрещены даже после сбоя. Результаты остаются локальными, без внешних запросов
и реального устройства. L0/отказы не включаются в промахи оценщика; полезность
требует точного настоящего ответа на каждый арифметический ход. Основной
показатель — модельный top-1 приватных отправленных разговоров; CI95 точные,
разрезы описательные с p без поправки. Это не качество произвольных ответов.

Held-out завершён: 336/360 полных наблюдений, по 112/120 на язык; 24 позиции
остались неизвестными, по восемь на язык. Модельный top-1 приватного выхода —
5/39 (12,82%, CI95 4,30–27,43%), p=0,0003444 против 1/64. Один из 40 приватных
выходов имеет невалидную атаку, не засчитан как промах; статус invalid_attacker.
Raw model 213/271 (две невалидные атаки отдельно), raw literal 273/273.
Literal выхода 1/40 не доказывает защиту. На тех же 39 отправленных разговорах
raw model 25/39; это парное сравнение, не смешение с общим raw-знаменателем.

L0 был в 242 разговорах: подтверждённая доля от planned 360 — 67,22%, верхняя
граница с неизвестными — 73,89%; только L0 без отправки — 236 разговоров.
Принятых локальных ходов 284/403 измеренных (70,47%); удалённых 97, отказов 19,
не начатых после отказа 3. Ошибки были в 63 разговорах. Полезные настоящие
арифметические ответы — 249/360 (69,17% подтверждённых от planned; 249/336
измеренных). Отправлены 82 разговора, 40 приватных. Канареек в измеренном
выходе 0; неизвестные 24 случая безопасными не считаются.

При старте восемь одновременных
non-mmap загрузок создали давление на память; приостановка четырёх частей не
устраняла унаследованный общий лимит 4 часа. ADR 0087 фиксирует отклонение:
исходные собственные процессы остановлены, 8 полных наблюдений сохранены,
16 прерванных/буферных позиций неизвестны. Продолжение шло по два процесса,
части до 12 и лимит 6 часов на часть. После перезагрузки хоста сохранились
123 полных наблюдения; ещё 8 позиций в уже заявленных частях 10/11 оставлены
неизвестными. Завершены только остальные 20 не заявленных ранее частей.
Никаких повторов разговоров. Freeze/статистика/модели/бинарники и пороги
сохранены; планы и хеши координаторов закреплены отдельными amendment до
разбора исходов. Recovery переиспользует исходный код исполнения части с
добавлением только exports во временную копию, чей SHA тоже закреплён.
`runtime-deviation.json`, `initial-stop.json`, `host-restart*.json` и RUN_NOTES
сохраняют отклонения; publication-spec заранее задаёт отчёт об неизвестности.
Условия запуска ограничивают интерпретацию ошибок и полезности; первоначальный
протокол не считается исполненным без отклонений.

Свидетельства: [отчёт](evaluations/shield-linkcheck-task5/REPORT.md), числовые
development/held-out/paired JSON, график и receipts в том же каталоге;
corpus/manifest — `tests/models/privacy-v3-held-out.*`. Unit-тесты независимо
восстанавливают опубликованный JSON из исходных частей и проверяют отсутствие
повторов, неизменность политики и архивов. После просмотра held-out стал
регрессией: любые следующие изменения требуют нового development и нового
невиденного held-out. Пороги после начала held-out не менялись.
Локально на Windows прошли `cargo test --workspace --locked`,
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
`cargo test -p nw-leak-tests --locked` (32 passed, один штатный model/AppContainer
тест ignored), app 13, extension 24, scripts 65, fmt и diff check.
Штатные ignored native/model/OS-store/bootstrap проверки workspace отдельно
не запускались; Linux/macOS и OS pcap в этой задаче не проверялись.
Логи: `target/task5-{workspace,clippy,leak,app,extension,scripts,fmt}-final.log`.
Linkcheck и этап остаются открытыми: результат отрицательный, есть невалидные
атаки и неизвестные случаи; CI этой задачи не запускался.

## Задача 4: границы M3H усилены; M3H закрыт — 2026-11-26

ADR 0085 вводит явное подтверждение полноты каждого из девяти источников probe.
Отсутствующий `observed`, частичное чтение, ошибка, устаревший или будущий снимок
не разрешают удалённый выход при включённой защите устройства. Legacy-снимки
обновляются один раз, отказ доступа не вызывает бесконечного повторного запуска.
Найденные значения защищаются и при частичном источнике; удаления сохраняются.
Домашний путь теперь подтверждается нативно, hints окружения недостаточно.

Windows использует токен профиля и локальные API без доменных запросов.
На этом хосте настоящий AppContainer probe подтвердил семь источников, а
`user`/`wifi` явно оставил неизвестными. Никаких дополнительных capabilities.
Добавлен macOS worker с CoreFoundation/SystemConfiguration/IOKit/getifaddrs,
нативным домашним путём и системным часовым поясом независимо от TZ=UTC.
До запроса worker применяет deny-default Seatbelt; передаётся только read-only
git fd, сеть/запись/spawn запрещены. Старый KnownNetworks не подтверждает
полноту Wi-Fi macOS. Нативный macOS CI подтвердил Seatbelt и реальные
отказы TCP/UDP `bind`/`connect`; недоступность sandbox остаётся явным
отказом, а не skip.

Гигиена дополнена чтением Windows NetBIOS всех доступных интерфейсов, read-only
оценкой часов ядра Linux и ограниченным JSON политик Firefox по умолчанию.
Нет исполнения JS или изменения настроек ОС. Browser Pass требует двух явных
заблокированных false, однозначной установки и проверенного источника политики;
managed preferences macOS не считаются проверенными. mDNS и остальные недоступные
источники неизвестны. Multicast Pass требует всех трёх отключений; ошибка новой
проверки не позволяет показывать старую оценку как свежую. Pass/6 сохранён.

По решению пользователя strict/paranoid завершают сеанс без сетевого хвоста.
UI явно блокирует согласие до появления L1/L2 и индивидуального одобрения,
backend отклоняет даже прежнее сохранённое согласие с L3. Реализация новых
маршрутов не начата. Хвост standard и его бюджеты сохранены.

Production managed PT теперь обязательно требует песочницу: Linux bwrap
отделяет user/mount/PID/IPC/UTS/cgroup, снимает capabilities и оставляет только
транспортный netns, публичную систему, закреплённый бинарник и собственное
шифрованное состояние. Для macOS добавлен обязательный sandbox-exec профиль.
На Windows запуск PT fail-closed до реализации изоляции; UI сообщает, что
мосты недоступны, обычный Tor автоматически вместо них не включается.
Сырые LOG/control/error-строки PT не выдаются изменёнными обработчиками;
возвращаемые ошибки тоже содержат фиксированные коды. Регрессия проверяет
восемь синтетических ошибок/параметров, включая некорректный control line.

`tor-pcap` расширен вариантами `tor`/`obfs4`. Новый локальный Chutney bridge
использует закреплённый Lyrebird; firewall разрешает клиенту только 192.0.2.2:9905.
CI observer проверяет настоящие PT namespaces, UID/caps/NNP и отсутствие core
storage/IPC, останавливает PT при живом Tor/provider. Независимый oracle требует
fail-closed и все прежние 100 HTTP-запросов, включая девять Device и семь detector
канареек. Артефакты: `local-tor-os-pcap-tor` и `local-tor-os-pcap-obfs4`.
Новый `protocol-golden` сравнивает настоящие HTTP/ClientHello artifacts трёх ОС,
а не только копии ожидаемого golden. Генерация golden в CI запрещена.

Локально на Windows прошли workspace tests, workspace Clippy со всеми
targets/features и `-D warnings`, отдельные leak tests и тесты/Clippy `nw-netd`,
app 13, extension 24, scripts 54, fmt, workflow lint и bash syntax check.
Настоящие AppContainer отрицательные проверки TCP/UDP/FS/spawn/read-handle
прошли (3), настоящий probe прошёл (1); закреплённый PT подтвердил запрет
неизолированного запуска на Windows для всех трёх протоколов. Cargo-deny обоих
workspaces прошёл (имеющиеся duplicate warnings не являются ошибками).
Журналы: `target/m3h-{workspace-final,clippy,leak-final,netd-final,netd-clippy,
app-final,extension-final,scripts-final,workflow-lint,windows-probe,windows-pt,
appcontainer,macos-check,deny-root,deny-netd,pt-canary}.log`; реальные Windows golden —
`target/protocol-windows/`.

**M3H закрыт CI-приёмкой.** [Run 45780888200](https://github.com/dsahakyan15/NymWrap/actions/runs/45780888200)
для 1e1ae69: `core` зелёный на Ubuntu, macOS и Windows; `tor-pcap` зелёный для
Tor и obfs4; `protocol-golden` подтвердил совпадение bytes трёх ОС. Obfs4 report
содержит 100 запросов, 84 M3 cover, ноль canary/direct-provider/DNS packets и
все признаки PT isolation/stop равны `true`. Общий workflow красный только
из-за четырёх неизменённых cargo-vet jobs задачи 9.

Остаются bootstrap Snowflake/WebTunnel, изолированный Windows PT, шифрованный каталог
транспорта macOS, недоступные автоматические наблюдения и WSL2 агентов. Последние общие
песочницы core/netd относятся к M6; новый worker их не заменяет. Хвост
strict/paranoid остаётся явно недоступным до сильного маршрута, по согласованию.

## Задача 3: сквозная приёмка M3; M3 закрыт — 2026-11-26

ADR 0084 расширяет обязательный `tor-pcap`: новый координатор `nw-core`
использует настоящие сохраняемые слоты Workspace и общий сетевой бюджет,
затем передаёт тела через production launcher/Client и AEAD dispatcher
отдельному `nw-netd` с локальной Chutney-сетью. Весь трафик синтетический,
внешних маршрутов, публичной Tor-сети и реальных аккаунтов нет.

Четыре независимых сценария — Poisson/Constant × лимит числа/расхода — проходят
по семь виртуальных дней. Разрешены три отправки по 3 microUSD в день:
лимиты 3 запроса / 14 microUSD либо 5 запросов / 10 microUSD. Проверяются
реальные задания и приманки, сохранение счётчиков после переоткрытия SQLCipher,
отказ до слота и повторного слота, два отказа сверх бюджета в каждые сутки,
откат часов и возобновление на следующие сутки. Отправка и завершение задания
не переигрываются при переоткрытии.

Независимый Node oracle требует ровно 100 восстановленных HTTP-запросов в OS
pcap: прежние 16 M2 и новые 84 M3. SHA-256 и длины каждого тела сверяются
с provider receipts и `cover-week.json`; бюджет пересчитывается для всех 28
scenario/day. Все пять корзин 2048/4096/8192/16384/32768 байт обязательны
отдельно у real и decoy в каждом сценарии. Лишние и отсутствующие запросы,
канарейки, неверные длины, подменённые лимиты и сбросы счётчиков отвергаются.
Артефакты `local-tor-os-pcap` включают семидневный учёт и хеши свидетельств.

Пакетное выравнивание не добавлено: критерии M3 SPEC §9 требуют корзин и
семидневного бюджета. Слоты проверяются на виртуальных часах; точный ритм
пакетов реального времени не заявляется. Полный production Route, FIFO backend,
OS credential pool и локальная генерация модели остаются за границей этого
захвата; прежние проверки этих компонентов сохранены. Strict/paranoid с L3
не включаются. Существующий лёгкий `nw-net` coordinator и VM probe M2 сохранены.

Локально на Windows прошли `cargo test --workspace --locked`,
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
отдельный `cargo test -p nw-leak-tests --locked`, тесты `nw-netd`, extension 24,
app 12, scripts 52, Rust fmt, workflow lint и `bash -n` pcap-скрипта.
Журналы: `target/m3-{workspace,clippy-final,leak,netd,extension,app,scripts-final,workflow-lint}.log`.
Семидневный core-драйвер также прошёл отдельной командой
`cargo test -p nw-core --example core-cover-egress --locked`: 84 синтетические
доставки и 140 переоткрытий хранилища, 375,28 с. Журнал — `target/m3-driver-final.log`.

M3 закрыт тем же [run 45780888200](https://github.com/dsahakyan15/NymWrap/actions/runs/45780888200).
Оба `tor-pcap` jobs зелёны; Tor `report.json` подтверждает 100 запросов,
84 cover, четыре сценария по семь дней, ноль canary/direct-provider/DNS packets
и `teardown_complete=true`. `provider.pcap` — 1 761 680 байт; `provider.pdml` —
обычный XML PDML 47 651 977 байт, ниже обоснованного предела 64 MiB.
Все три `core` jobs и прежние критерии M2 в этом run также зелёны.

## M2 закрыт по Linux-критериям SPEC §9 — 2026-11-25

ADR 0083 добавляет ограниченную проверку настоящего Tor-потока до первой
отправки: до 10 попыток по 8 с с паузой 2 с, без TLS/HTTP, внутри общего
180-секундного bootstrap deadline. Production отправки не повторяются;
проверка явной ошибки после остановки Tor сохранена. Исправлен также probe
пустого core netns: IPv6 может вернуть `EADDRNOTAVAIL` до поиска маршрута.
Три локальные регрессии ожидания прошли. Три последовательных независимых
процессных `tor-pcap` в CI зелёные; критерии и ссылки приведены ниже.

ADR 0082 подключает ADR 0078 к Linux `nymwrapd`. До Tokio создаётся пустой netns
core; проверенный fd отдельного транспортного netns используется в pre-exec
того же retained child через `Client::spawn_prepared`. До чтения bootstrap core и данных
сбрасываются UID/GID/groups, ставятся NNP и seccomp TSYNC. Ошибка exec и отмена
также необратимо сбрасывают права. Неверный fd, текущий netns и нулевой UID/GID
отвергаются. Ключи остаются в anonymous pipe/памяти, kernel PID не подменён.

Обычный Linux desktop без административной подготовки теперь работает только
в L0, без запуска netd в host netns. Production CLI принимает `--netns/--uid/--gid`
только от уже привилегированного coordinator с private bootstrap. Маршруты/firewall
транспорта подготавливаются вне процесса. Прикладные IPC/Tor проверки сохранены;
USER_GUIDE и THREAT_MODEL §7 описывают эти ограничения.

**Открытые долги M6:** установщик службы и административный coordinator GUI;
полная файловая песочница Linux-демонов; запуск core/netd в AppContainer на
Windows и production App Sandbox на macOS. Изоляция отдельных LPAC workers
не даёт такой гарантии для core/netd. До выполнения этих долгов Linux desktop
без подготовленного netns остаётся в L0, а эквивалентная Linux защита от сокетов
скомпрометированного core на Windows/macOS не заявляется.

Обязательный job `tor-pcap` теперь запускает настоящий `nymwrapd` с настоящими
idle netd/API и проверяет namespace всех threads, сброс прав, seccomp, запрет
маршрута core и lifecycle. Процессный coordinator использует тот же production
launcher, retained test-only netd, настоящий AEAD dispatcher и Tor/TLS/HTTP.
16 синтетических канареечных запросов проверяются по pcap и квитанциям;
circuit IDs берутся из actual HTTP streams. Остановка локальных Tor-релеев
требует явной ошибки транспорта при живом provider. Oracle не принимает
таймаут, пустую запись, одинаковые circuits или отсутствие daemon evidence.
`full_core_pipeline=false`: локальная модель/одобрения не входят в этот pcap.
VM job дополнен проверкой сброса прав при ошибке запуска и отмене future.

**Приёмка M2 в CI:** один и тот же проверенный SHA
`f0e1438cbcc8b06f5fd45b5e2c10f3074e705013`, без изменений кода между прогонами.
Следующий `tor-pcap` запускался после завершения предыдущего; каждый создавал
свои реле, namespace, зашифрованное состояние и захват.

| Прогон `tor-pcap` | Начало — завершение (UTC, 2026-11-25) | Результат |
|---|---|---|
| [45561266129 / job 139025281640](https://github.com/dsahakyan15/NymWrap/actions/runs/45561266129/job/139025281640) | 06:31:47 — 06:38:22 | success |
| [45562125147 / job 139028090034](https://github.com/dsahakyan15/NymWrap/actions/runs/45562125147/job/139028090034) | 06:39:12 — 06:47:12 | success |
| [45563271763 / job 139031850183](https://github.com/dsahakyan15/NymWrap/actions/runs/45563271763/job/139031850183) | 06:48:00 — 06:54:56 | success |

Во всех трёх артефактах `local-tor-os-pcap` подтверждены критерии SPEC §9:

- Core в отдельном netns не может открыть внешний сокет: настоящий production
  `nymwrapd`, все runtime threads со сброшенными правами и seccomp; отдельный
  процессный coordinator требует `PermissionDenied` TCP/UDP IPv4/IPv6.
  Свидетельства — `daemon-result.json` и `rust-result.json`.
- После остановки Tor получен явный AEAD-ответ с ошибкой при живом provider;
  внешний таймаут не принимается. `report.json` и `health-after-stop.json`
  подтверждают fail-closed, ноль прямых пакетов и DNS; provider pcap содержит
  ровно 16 безопасных запросов, все пять корзин и ноль канареек.
- Два разговора используют разные цепочки: `circuit-receipt.json` содержит
  circuit IDs actual HTTP streams; независимый oracle проверяет их различие.
  В каждом `report.json` также `teardown_complete=true`.

Все три скачанных артефакта повторно проверены локально: `auditCapture`, поиск
канареек в обоих raw pcap и все 12 SHA-256 каждого report. Копии —
`target/m2-tor-ci-{1,2,3}/`. После этих прогонов изменён только этот отчёт;
исполняемые исходники, тесты, workflow и lock-файлы совпадают с проверенным SHA.

Первый полный workflow завершён: все 16 jobs вне `dependency-audits` зелёные,
включая core/network трёх ОС, frontends, браузеры, desktop/native Firefox и
Linux VM. Общий conclusion — **failure** из-за четырёх известных cargo-vet
jobs (долг M6); отключений или allowed-failure нет. Закрыт только M2 по Linux,
остальные этапы, включая M6 и M3H, этой приёмкой не закрываются.

На этой задаче локально на Windows зелёные `cargo test --workspace --locked`,
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
отдельный `cargo test -p nw-leak-tests --locked`, полные netd test/clippy всех
targets (включая три новые регрессии ожидания), extension 24, app 12, scripts 50,
Rust fmt workspace/netd и workflow lint. Журналы — `target/m2-exit-*.log`.
Linux netns/Tor pcap локально на Windows не запускались; их приёмка выполнена
в трёх указанных GitHub Actions jobs. Предыдущая локальная QEMU/Alpine проверка
launcher остаётся дополнительным свидетельством:
`target/linux-isolation/{report.json,serial.log}`.

Далее — история предыдущих работ; прежние пометки об открытом M2 заменены
приведённой выше Linux-приёмкой.

Рабочий каталог первоначально не содержал `.git`; источник remote отсутствовал
также в метаданных T3. Создан [приватный репозиторий](https://github.com/dsahakyan15/NymWrap)
для требуемого CI (ADR 0049). [Первый run](https://github.com/dsahakyan15/NymWrap/actions/runs/45082675972)
выявил отказы IPC на macOS. Полный [run 45091002400](https://github.com/dsahakyan15/NymWrap/actions/runs/45091002400)
для 56d67c7 прошёл все 14 заданий: core/network трёх ОС, зависимости, frontends,
браузеры, Windows owner, Linux VM, desktop и native Firefox. Более поздние
изменения требуют собственного CI; диагностический privacy workflow отдельно
остаётся красным и не является частью этого успешного результата.
Локальные результаты не считаются зелёным CI и не закрывают
этапы. M3H остаётся открыт; linkcheck подключён, но усиленная held-out приёмка,
независимый split и полнота оценки ещё не выполнены.

**CI снова работает (ADR 0079).** С 654d788 GitHub отклонял задания из-за оплаты
приватного аккаунта. По решению пользователя репозиторий сделан публичным; run
[45481719481](https://github.com/dsahakyan15/NymWrap/actions/runs/45481719481)
для 259dd56 запустил все задания на трёх ОС. Результат этого run и последующих
записывается отдельно; сам запуск этап не закрывает.
Первый публичный run: красные dependency-audits (известный непокрытый cargo-vet),
network/ubuntu (Tor убрал 16.0.1 с dist — источник переведён на archive, ADR 0048)
и tor-pcap: закреплённый chutney 62b54a5 (он же последний upstream) импортирует
`cgitb`, удалённый в Python 3.13, а runner использует Python 3.14. Исправление —
ADR 0081 и результат ниже.
Run 45482671411 (a73683a): network зелёный на трёх ОС после перехода на archive.
Красные: core/ubuntu (rpc_process, авторизация RPC 3d262fa впервые в CI),
desktop (Firefox native: fixture_core_start_failed), tor-pcap, dependency-audits.

**Задача 1 — CI восстановлен в согласованном объёме (ADR 0081).**
Run [45503957290](https://github.com/dsahakyan15/NymWrap/actions/runs/45503957290)
для кода c337c22 завершён 2026-11-25: все 16 заданий вне dependency-audits зелёные,
включая core/network на Ubuntu, Windows и macOS, desktop и Firefox Native Messaging.
Общий conclusion workflow остаётся failure только из-за четырёх cargo-vet jobs;
они не менялись и относятся к задаче 9. Allowed-failure и отключений проверок нет.
Предшествующий run 45503174436 выявил kernel IPv6 router solicitation в IPv4-only
pcap fixture. Теперь IPv6 выключен и проверен только в созданных тестом namespace
до поднятия veth; oracle по-прежнему отвергает IPv6-пакеты. Исправление вошло
в полный успешный прогон выше; хостовые настройки не менялись.

- Core штатно закрывает parent pipe API и ждёт retained child перед выходом:
  Unix socket удаляется самим API, повторный запуск после Lock проходит.
  Исходный actual_ regression проверил точные PID, чужой процесс/экземпляр,
  bootstrap, повторный запуск и потерю parent pipe на всех трёх ОС.
- Firefox fixture использует production авторизованный Client в отдельном
  тестовом Cargo example; привилегированный CLI RPC остаётся отключённым.
  CI-артефакт firefox-native.json: Firefox 160.0.1, connect/pause/resume,
  независимое состояние core, ноль сетевых резервов и восстановленная регистрация.
- Chutney: закреплён Python 3.12.16, явный интерпретатор в netns, минимальный
  патч неиспользуемого импорта Traffic, адаптер authorities для Arti 0.48 и
  обязательная готовность всех релеев. Tshark анализирует сверенные копии в
  приватном /tmp, со штатным AppArmor. report.json: 16 запросов, пять корзин,
  ноль канареек/прямых пакетов/DNS, разные circuits, fail-closed при живом provider,
  teardown_complete=true. Это библиотечный Tor::send, не полный core/process pcap.
- Windows fixture выделяет TCP/UDP-порты независимо и проверяет положительную
  доставку до проверки запрета AppContainer; все отрицательные требования сохранены.

Локально на Windows зелёные workspace test, clippy всех targets/features с
`-D warnings`, nw-leak-tests, netd test/clippy, extension 24, app 12, browser 10,
Firefox native 1, actual AppContainer 3, scripts 49, Rust fmt и workflow lint.
Скачанный CI pcap повторно прошёл oracle и сверку всех хешей локально.
Логи — target/ci-*. Локальные результаты не заменяют указанный CI;
этапы SPEC и оставшиеся критерии M2/M3H/M6 этой задачей не закрываются.

**Подпись выпуска (ADR 0080).** `scripts/release-signature.mjs`: keygen/sign/verify
ключом Tauri signer, проверка на `node:crypto`, тест с настоящим Tauri CLI.
Владелец создал ключ выпуска 2026-11-25: публичная часть закреплена в
`release/nymwrap-release.pub` (minisign key id A1F9B182A82829E0), приватная
хранится только у владельца. Пункт THREAT_MODEL §9 «релиз подписан» остаётся
открытым, пока не подписан первый выпуск и сборка не воспроизведена на двух машинах.

## Запуск дочернего процесса в netns — локальная проверка, M2/M6 открыты

- ADR 0078: доверенный launcher может подготовить namespace/identity до exec
  того же сохранённого child. Client::spawn_prepared сохраняет проверку точного
  kernel PID, liveness, private bootstrap pipe и kill_on_drop; чужой stdin
  заменяется. Режим не присоединяется к существующему процессу и не получает root.
- В Linux дочерний процесс входит только в CLONE_NEWNET и теряет supplementary
  groups, real/effective/saved UID/GID и KEEP_CAPS; включается NO_NEW_PRIVS.
  Неверный fd останавливает запуск до payload. Coordinator теряет права через
  синхронизирующие libc wrappers и ставит seccomp TSYNC до обработки данных.
  Production launcher, файловая песочница и весь процессный pcap ещё не подключены.
- Настоящий regression actual_child_network_namespace_and_identity_cannot_escalate
  прошёл в одноразовой QEMU/Alpine VM (kernel 6.18.60-0-virt): другой netns,
  UID/GID 1000, пустые supplementary groups, отказ вернуть root и прочитать
  root-only канарейку, проверка уже существующего thread и неверного fd.
  Teardown завершён. Логи target/netns-vm-identity-green.{serial.log,report.json};
  report v2 связывает hashes crates, tests/leak, harness, package lock, Cargo.lock
  и ELF. Это локальная административная fixture, не приёмка production M2/M6.
- ADR 0079: probe закрепляет официальные Python 3.14.10-r2 и bubblewrap 0.12.0-r0
  APK с размерами, лицензиями и SHA-256; обычный apk проверяет исходный подписанный
  APKINDEX. Три предшествующие попытки остановились до приёмки из-за устаревшего
  Python pin, diskless local-package restriction и ошибки копирования metadata;
  их failed reports сохранены и успехом не считаются. Transitive APK-граф не
  закреплён полностью, воспроизводимость M6 этим не заявляется.
- После изменений повторены: workspace test, clippy всех targets/features, leak,
  полные netd test/clippy (native lifecycle 3 pass), Rust fmt, app 12,
  extension 24, scripts 44 и actionlint — все зелёные локально. Логи
  target/netns-launch-*.log. Cross clippy для Linux musl также зелёный.
  CI VM job уже вызывает тот же probe, включая явный root regression; новый CI
  не выполнялся. 2026-11-25 annotation checks 45101662588 повторно подтвердила
  внешний payment/spending blocker. Никакой этап не закрыт.

## Подготовка процессного сетевого сценария — M2/M3 остаются открыты

- ADR 0077: настоящий AEAD dispatcher nw-netd выделен из main в server;
  release entry point всегда использует production Tor constructor. Частные
  фабрики нужны для будущего тестового worker, runtime переключателя нет.
  Текущий pcap по-прежнему вызывает библиотечный Tor::send: его scope и
  production_daemon_namespace_integration/full_core_pipeline=false не менялись.
- Native тест воспроизвёл задержку разрешённого Reset одним пустым same-user
  соединением (4,13 с, target/netd-idle-peer-red.log). До проверки ключа теперь
  действует 2-секундный предел чтения. Затем разрешённый запрос проходит.
  Защита от непрерывного потока DoS-соединений этим не заявлена.
- Canary в tests/leak/src/netd_dispatcher.rs проходит настоящий dispatcher,
  подменяя только транспорт. Неправильный ключ и старый sequence не вызывают
  отправку, Send/SendOnce передают точное подготовленное тело без Device-канарейки,
  ответ защищён AEAD, Reset отзывает соединение. Новая проверка и полные
  сетевые test/clippy зелёные; native lifecycle — 2 pass. Логи
  target/netd-{dispatcher-canary,shared-dispatcher-tests-final,
  shared-dispatcher-clippy-final,shared-dispatcher-lifecycle}.log.
  Ни процессный pcap, ни production netns этой частью ещё не реализованы.

## Авторизация core RPC M6 — процессная проверка в CI, M6 открыт

- ADR 0076: исходный отрицательный тест снова воспроизвёл выдачу канарейки
  неразрешённому same-user клиенту (target/core-rpc-authorization-red.log).
  Ignore снят. Теперь ephemeral ключи UI/API передаются только через inherited
  pipe; kernel PID и сохранённый child проверяются до отправки команды.
  На соединение выдаётся новый challenge, AEAD связывает роль и направление.
  API получает только chat/embeddings/submit/status/cancel, без vault и одобрений.
- Канареечные тесты разрешённого control и ограниченного API, replay,
  отражения ответа, другого ключа/роли и старого plaintext протокола зелёные.
  Неверная авторизация закрывает соединение, затем разрешённый клиент всё ещё
  читает синтетический vault. Все эти проверки входят в обычный workspace.
  Логи target/core-rpc-{authorization-canary-green,replay-green}.log.
- На Windows настоящий nymwrapd сам запустил настоящий nw-api; bootstrap,
  отказ другому PID и другой копии того же образа, закрытие endpoints после
  Lock и потери parent pipe проверены в отдельном data/runtime namespace.
  Реальные workspace/keyring/accounts не использовались. TempDir удалён;
  после проверки nymwrapd/nw-api не осталось в списке процессов.
  Лог target/core-rpc-native-final-process.log. Этот actual_ тест добавлен
  в CI core matrix всех трёх ОС и scripts/check; теперь он прошёл на всех ОС
  в run 45503957290 после исправления штатного завершения API (ADR 0081).
- Bootstrap core/API и начальный ключ nw-netd читаются напрямую из read-only
  duplicate pipe, без дополнительной копии в общем буфере std::io::Stdin.
  Native тест pipe/read-only/file/null прошёл; копия handle не наследуется.
  Лог target/core-rpc-stdin-pipe-test.log. Версии зависимостей не менялись:
  прямые edges используют закреплённые chacha20poly1305/sha2, windows-sys
  получил feature Console. Все четыре lock-файла обновлены без смены версий.
- После изменений зелёные полный workspace (core lib: 50 pass, 1 ignored —
  отдельный тест OS credential store), clippy всех targets/features, leak,
  network tests/clippy, native Tauri check, fuzz harness check, app 12,
  extension 24, scripts 43 и actionlint. Логи target/core-rpc-*.log.
  cargo-vet повторён на новых locks: 268 / 514 / 499 / 248 пробелов,
  все четыре красные. Это не полный scripts/check и не прохождение M6.
- Изоляция core/API/drift-host, защита их памяти и OS keyring остаются
  открытыми. Native matrix не проверяет этот RPC внутри bwrap PID namespace
  или AppContainer; их интеграция требует отдельных проверок. Новая UI не
  наследует ключ предыдущей UI и ждёт окончания её согласованного хвоста.
  Привилегированный CLI rpc отключён; запуск API теперь выполняет core.
  USER_GUIDE и SPEC обновлены. Интерактивный smoke новой UI не проведён.

## Аудиты зависимостей M6 — критерий красный

- ADR 0073: установлен закреплённый cargo-vet 0.10.4 с проверкой архивов и
  исполняемого файла. Для root/desktop/netd/fuzz созданы отдельные stores и
  imports.lock с опубликованными аудитами Mozilla/Google из immutable commits.
  Exemptions не добавлялись; path forks требуют аудита
  опубликованной базы, а проверка их локальных изменений остаётся открытой.
- После явного refresh все четыре check --locked завершились неуспешно:
  не покрыты root 273 / desktop 517 / netd 502 / fuzz 253 версий пакетов.
  Графы пересекаются, числа не суммируются. Это реальные незакрытые пробелы
  аудита, не сбой запуска инструмента. Логи target/vet-four-locked.log и
  JSON/receipts в target/vet/. Их нельзя считать прохождением cargo-vet.
- В checks добавлены четыре независимых Ubuntu job без continue-on-error;
  JSON и receipts публикуются даже при провале. Receipt связан с хешами lock,
  policy, audits, imports и инструмента; stale/missing/partial/exempted выдача
  не зелёная. Основные check.ps1/check.sh тоже завершаются провалом на пробелах.
  CI не запускался из-за прежнего внешнего блокера Actions.
- Локально 40 scripts-тестов зелёные, закреплённый actionlint проверил новый
  workflow (exit 0). Логи target/vet-tooling-tests-final.log и
  target/vet-workflow-lint.log. Зелёные функциональные Rust/frontend проверки
  предыдущего раздела не подменяют красный аудит или открытый M6.
- ADR 0074: новый RUSTSEC-2026-0594 сначала сделал desktop deny красным.
  Транзитивный cookie обновлён 0.18.2 → 0.18.3 с закреплённым checksum;
  исключение для advisory не добавлялось. После обновления deny всех четырёх
  workspace зелёный, native desktop check зелёный, app 12 / extension 24.
  Логи target/cookie-*.log, target/vet-deny-{root,netd,fuzz}.log. Desktop vet
  повторён на новом lock: всё ещё 517 непокрытых версий, результат красный.
- Затем Codex просмотрел полный diff equivalent 1.0.2 → 1.0.3 и исходный
  модуль: изменились только документация и метаданные. Оба архива из локального
  Cargo cache проверены по SHA-256; записан именно AI delta review, не
  независимый человеческий аудит и не аудит исходной базы. Google base/delta
  достроили цепочку. После refresh: root 272 / desktop 516 / netd 501 / fuzz 252,
  equivalent больше не в failures. Все четыре проверки остаются красными.
  Прямой metadata API crates.io вернул HTTP 403; обход не выполнялся. Для этого
  ревью использованы только уже скачанные локальные архивы и индекс.
- Продолжен просмотр исходников из кеша: полный diff proc-macro2
  1.0.106 → 1.0.107, serde_spanned 1.1.1 → 1.1.3, toml_datetime
  1.1.1+spec-1.1.0 → 1.1.3+spec-1.1.0 и полный cfg-if 1.0.5.
  SHA архивов проверены по кешированному registry index; области и ограничения
  каждого AI review записаны в audits.toml всех четырёх stores. Полные базы
  дельтааудитов и optional dependency cfg-if этим не сертифицированы.
  Cargo test --offline для cfg-if не разрешил некешированную optional dependency
  и не запустил тесты. Прямые default-feature проверки тем же rustc/rustdoc:
  2 unit, 1 cross-crate и 1 doctest прошли; временные каталоги удалены в finally.
  После refresh и check --locked: root 268 / desktop 514 / netd 499 / fuzz 248,
  **все четыре красные**. TOML delta покрыта в root/fuzz, но цепочки desktop/netd
  ещё неполны. Логи target/vet-four-local-reviews.log и
  target/audit-reviews/cfg-if-{default,direct-default}-tests.log. Это локальное
  свидетельство source review, не зелёный CI и не закрытие M6.

## Подготовка длительного фаззинга M6 — проверки ещё не проведены

- ADR 0070: добавлены ручной fuzz-campaign и reusable segment workflow на Ubuntu
  24.04. Preflight проверяет native бинарник 10 секунд; полный режим требует
  всех 18 четырёхчасовых исполнений — по 24 часа на каждый из трёх targets.
  Это шесть процессов на target с передачей corpus, не непрерывный процесс 24h.
- Агрегатор проверяет binary/source/build SHA, corpus/receipt chain, одинаковые
  run/attempt/commit, полную длительность по wall clock и статистике libFuzzer.
  Пропуск, crash, ранний exit 0, частичный rerun или preflight не проходят как 24h.
  CI не запускался из-за внешнего блокера; доказательств длительного фаззинга нет.
- Четыре unit-теста протокола кампании прошли локально; scripts всего 37.
  Закреплённый actionlint 1.7.12 на Windows проверил все YAML/schema/expression
  types, exit 0. Shellcheck/pyflakes не запускались. В checks добавлено отдельное
  workflow-lint задание; новый checks и новый fuzz workflow требуют реального CI.

## Linkcheck — 2026-11-24, этап открыт

Ниже — исторические записи. Завершённая локальная оценка удерживаемого
многоязычного кандидата, отрицательный результат и ограничения приведены в
разделе «Задача 5» выше; это не аттестация сборки текущего HEAD.

- ADR 0075: отчёт получил счётчики совпавших фактов/nonce/ничьих и категорию
  каждого ответа correct_integer/wrong_integer/not_integer/unavailable, без
  содержания. Каждый top-1, включая ничью без фактов, остаётся в статистике.
  Строки и resume-checkpoint проверяются до продолжения; итоговый валидатор
  использует ту же схему. Регрессия фиксирует dev_0023: literal top-1 true при
  0 совпадений и ничьей 64, без исключения этого успеха из числителя.
- На client 8e812ac0c1917440df42ac0ae8cba82c0d94255296a1be52f55c74b6f0ef3682,
  diagnostic receipt 4199cf5f6f770cabd1e0: dev_0011 прошёл generalize,
  rank 17/risky → 24/safe. Оба outbound-атакующих: top-1 false, 0 фактов,
  nonce false, ничья 64; raw model: 6 фактов, nonce true, один максимум,
  top-1 true. Канареек 0, useful false/not_integer. Эти два состояния rank и
  медианы закреплены отдельной реконструированной геометрией в tests/leak,
  без записи векторов. HY dev_0003: L0, useful false/not_integer, канареек 0;
  raw model: 5 фактов, уникальный максимум, top-1 true. Семантическая правильность
  нецелого ответа не оценивалась. Это два diagnostic, не полный результат.
- Диагностика прошла example tests (6), scripts (43), clippy всех
  targets/features, полный workspace/leak; новая rank-регрессия прошла отдельно.
  Логи target/linkcheck-diagnostics-*.log и target/linkcheck-dev-0011-regression.log.
  Полный development текущей конфигурации ещё не завершён; held-out не создан.

- ADR 0071: прежние трёхфактные приманки заменены 64 шестифактными. Покрытие
  отдельных признаков/пар, уникальность и независимость от пользовательского
  досье прошли регрессию после воспроизведения прежней асимметрии. Пороги и
  default embedding не менялись. Это структурная поправка; качество настоящей
  модели и статистическая приёмка ею не подтверждены.
- ADR 0072: окончательный L0 отвечает по исходному диалогу, сохраняя условия
  задачи; NER/canonicalize/generalize остаются минимизированными. После L0
  разговор больше не отправляется удалённо, включая encrypted reopen. Три
  регрессии сначала воспроизвели потерю числа, Block при известной канарейке и
  попадание неизвестной канарейки локального ответа в перехват отправки; после
  исправления все три зелёные. Неупомянутый Device-секрет модели не добавляется.
  Найден также обход через старый snapshot version 1: он не отмечал каждый L0
  и разрешал review. Добавлена четвёртая отрицательная регрессия; новые snapshots
  version 2, старые восстанавливаются только локально. Все четыре регрессии
  прошли; повторные полные проверки ниже включают эту миграцию.
- После обеих поправок локально зелёные полный workspace, clippy всех
  targets/features, leak, privacy_linkcheck example (5), native Tauri check,
  app (12), extension (24), scripts (37). После миграции: логи
  target/local-context-final-*.log; frontend/scripts — target/local-context-*.log.
  Это не CI и не измерение качества генеративной модели. Первый development-
  shard на d435c6e остановлен как устаревший после 35/48 случаев (35/384 всего):
  status failed, не полный прогон и не приёмка. Его данные не смешиваются с новыми.
- На release client f9b50c96cc928d8022bf357ccad0d425f536c5b50a688a3e205b36a1cbe21693
  выполнены два отдельных diagnostic, receipt f7fc3be040560582141e, Qwen/Qwen.
  HY dev_0003: L0, полезность false, канареек 0, raw model/literal top-1 true.
  Public dev_0006: rank 1/65 до и после generalize, L0, полезность true,
  канареек 0. Новые приманки не устранили этот ложный отказ. Оба случая остаются
  в корпусе; отдельные diagnostic не принимаются merger и не дают held-out
  статистику. Полный development, freeze и слепая приёмка по-прежнему открыты.

- ADR 0068/0069: явно подключён многоязычный Qwen3-Embedding-0.6B Q8_0 с
  официальным immutable SHA, pooling last/1024; default остаётся Nomic. SHA,
  recipe и размерность проверяются вместе, кеш связан с ними. Старый identified
  ответ без recipe сохраняет L0; Windows stdio broker проверяет метаданные worker.
  После нового протокола оба native CPU/private-IPC теста прошли за 17,02 с,
  оба настоящих Windows LPAC — за 23,14 с, включая независимость вектора от
  предыдущего текста и размера партии/контекста. Логи target/recipe-native-*.log.
- На том же dev_0002 проведены две отдельные diagnostic оценки. Nomic:
  rank 4 → generalize → rank 13/65, один синтетический provider-ход, utility false.
  Qwen: rank 43/65, generalize не понадобился, один provider-ход, utility true.
  В обоих: canaries 0, model/literal top-1 false. Это один public_control,
  без внешних запросов; качество приватных фактов этим не измерено. Потеря
  полезности Nomic остаётся открытым наблюдением на существующем dev_0002 с
  точным expected_answer. Нельзя выводить её причину из одного агрегата.
- `--sample` не становится complete/held-out даже при успехе; отчёт отвергается
  общим валидатором и merger. Полный workflow получил явный выбор embedding,
  а core CI трёх ОС — настоящие native CPU тесты, Windows также LPAC. Эти CI
  изменения не выполнены из-за внешнего блокера. Локально зелёные полный workspace,
  clippy всех targets/features, leak, evaluator (5), Tauri check; app 12,
  extension 24, scripts 33. Логи target/recipe-checkpoint-*.log и recipe-final-*.log.
- ADR 0065/0066: новый model fact extractor с детерминированным ранжированием
  и действующий отрыв от медианы прошли локальные регрессии. Native CPU/private
  IPC проверка грамматики прошла за 20,69 с, Windows LPAC/private IPC — 97,28 с.
  Pilot 5/384: raw model valid 5/5, correct 4/5 (включая два HY linkage), remote 0,
  полезность 3/5, канареек 0. Это partial development, не приёмка/held-out.
  Все локальные workspace/clippy/leak/evaluator/Tauri проверки зелёные;
  app 12, extension 24, scripts 31. Логи target/fact-final-*.log.
- ADR 0067: public_control rank 1/65 воспроизвёл ложный отказ; регрессия также
  подтвердила метаданные хранения в embedding настоящего досье. Введена полная
  текстовая проекция фактов без JSON envelope и маркера fiction у приманок.
  Новая версия требует отдельного pilot и CI; старые числа к ней не относятся.
- Все исходные 12 linkage/linkage_multiturn из privacy-v2 теперь исполняются
  отдельной Engine-регрессией. При сохранённом сочетании после generalize нет
  раскрывающего remote хода, а новый публичный вопрос не снимает L0. Это
  управляемая геометрия, не повторная оценка настоящей модели или точности top-1.
- Pilot текстовой проекции без JSON (0f7dd7af1329bc6b558e) завершил 5/384:
  remote 0, useful 3/5, raw valid 5/5 и correct 4/5, канареек 0. Public_control
  изменился с rank 1 на 3/65, но остался risky. Причинный эффект/приёмка не
  доказаны. Позднее исключена точная служебная строка ручного подтверждения;
  эта последняя версия ещё не измерялась настоящим evaluator.
- После проекции и 12 исходных регрессий локально зелёные fmt, workspace,
  clippy всех targets/features, leak, evaluator (5), native Tauri check:
  target/factual-checkpoint-*.log. App 12 / extension 24 / scripts 31 прошли
  без изменения соответствующего кода. Для этой версии нет зелёного CI.
- ADR 0053: между canonicalize и финальным leakcheck подключены ранжирование
  закреплёнными embeddings (SHA-256 в ответе проверенного nw-llmd), 64 независимых
  синтетических досье, профильные top_k/max_margin, generalize/recheck и L0 с
  объяснением при оставшемся риске/ошибке. Проверяется вся provider-visible история;
  отправленный префикс не переписывается. Досье включает только подтверждённую
  персону, все личные/Device-секреты и сводку импорта, без скрытого усечения.
- Досье/кеш в shadow памяти с zeroize. Изменения импорта/персоны инвалидируют
  разрешения и Engine. Проверка образа peer до HTTP-тела запрещает отдать досье
  постороннему same-user endpoint. Это не закрывает найденную ниже авторизацию
  входящего shadow RPC в M6.
- Новые регрессии: связка двух ходов, равенство рангов и перестановка альтернатив,
  плохие векторы/идентичность модели, полнота досье после encrypted reopen,
  generalize только нового хода, инъекция канарейки при generalize, L0 без сети
  при ошибках. Настоящий CPU worker прошёл embed_identified через private IPC.
- Локально после подключения прошли workspace, clippy со всеми targets/features,
  leak, privacy_pipeline example (2), extension (24), app (11), scripts (16),
  native Tauri check и suite nw-netd. Отдельно прошёл настоящий Windows LPAC
  model → Engine → checked output → shape (85,56 с), с канарейкой и закреплёнными
  файлами. Это проверяет путь отправки, но не качество ранжирования на held-out.
  Логи: target/linkcheck-*.log; известная отрицательная RPC-регрессия M6 открыта.
- Открыты: независимый split (при L3 отсутствует),
  полный development-прогон, заморозка настроек и blind held-out с интервалами 95% и
  честной полезностью. Nomic v1.5 обозначен upstream как English; качество RU/HY
  не подтверждено. Старый privacy-v2 остаётся регрессией, не held-out приёмкой.
- Development-корпус расширен отдельными 384 случаями: EN 127 / RU 124 / HY 133,
  по 64 синтетических досье на случай. Хеш/seed закреплены в fixtures; проверяются
  воспроизведение и языки. Held-out не создан, качество защиты этим не измерено.
  ADR 0054 задаёт заморозку, точные binomial интервалы 95%, контроль raw-атакующего
  и отдельный учёт приватных задач, L0, ошибок и полезности. Статистический модуль
  используется development-evaluator ниже. Регрессии ловят all-L0, невалидного атакующего
  и разбавление частных утечек публичными вопросами.
- Причина L0 перенесена в метаданные и сохраняется с разговором; UI выводит её
  отдельно. Core/API регрессии проверяют, что JSON-ответ остаётся JSON, и наличие
  объяснения не зависит от того, читает ли пользователь тело ответа как текст.
  Encrypted reopen сохраняет причину и запрещает повторную отправку. После этого
  локально прошли workspace, clippy всех targets/features, leak, app (12), scripts
  (20) и native Tauri check. Held-out измерений по-прежнему нет.
- Добавлен development-evaluator privacy_linkcheck: production Engine, полное
  досье через временный encrypted Workspace, настоящие ответы вместо заглушек,
  отдельный реальный атакующий и literal matcher, полная видимая история и
  проверка канареек в shape-байтах. Проверка полезности — точная арифметика для
  каждого хода, а не сохранённые слова. Хешируются бинарники, корпус, политика
  и скрипты; partial/failed не дают статистической приёмки. Unit/структурные
  проверки прошли (Rust 4 / scripts 23). Первый release pilot: dev_0000 был
  остановлен на invalid_model_output NER; реальный атакующий вернул
  local_model_unavailable. Отчёт partial (1/384), статистическая приёмка не
  засчитана. Диагностика содержит только этапы и коды, без текстов запросов.
  Полного development-измерения, freeze и held-out ещё нет. Локально также
  прошли workspace, clippy всех targets/features, leak, extension (24), app (12).
- Находка dev_0000 оформлена регрессией и ADR 0057: недоступный/отклонённый NER
  сохраняет локальный ответ и запрещает remote retry следующих ходов. Тест
  воспроизвёл отказ Model, затем прошёл для недоступности, выдуманного фрагмента
  и совпадения внутри Device-плейсхолдера. После изменения локально прошли
  workspace, clippy всех targets/features, leak, extension (24), app (12),
  scripts (23) и native Tauri check; CPU/private-IPC с фиксированной грамматикой
  choice прошёл за 20,30 с. Известная отрицательная RPC-регрессия M6 открыта.
  В повторном pilot dev_0000 получил L0,
  но арифметический ответ smoke-модели оказался неверным; атакующий снова вернул
  local_model_unavailable. Run failed (1/384), не принят. Полезность не выводится
  из наличия локального ответа. Добавлен отдельный Ubuntu workflow для
  настоящей development-оценки; freeze и held-out остаются открытыми.
- ADR 0058: причины Timeout/TooLarge проходят worker → broker → private HTTP →
  UnixModel отдельными фиксированными кодами, без native-строк или входного текста.
  Канареечная регрессия сначала увидела 503 вместо 504, затем прошла для chat и
  embeddings. Прогон настоящего Windows LPAC с ограниченной choice-грамматикой
  и переполнением контекста прошёл за 84,87 с. Это диагностика и проверка пути,
  не успешная калибровка атакующего или held-out оценка.
- ADR 0059: управляемый model client связан с удерживаемым Child, а не с PID из
  сообщения. Проверка пути /proc несовместима с non-dumpable Linux worker;
  защита памяти сохраняется. Core использует receipt для Engine и остальных
  model-вызовов. Локально прошли два настоящих helper-процесса, проверка чужого
  peer с тем же образом и отсутствующего владельца, Core suite и teardown.
  Linux/macOS подтверждены полным run 45098535892 для 089aafa ниже.
  Повторный локальный 7B pilot завершил dev_0000 за 96,78 с: NER был отвергнут,
  ответ сохранился в L0 и прошёл точную проверку полезности; raw-атакующий дал
  валидный правильный top-1. Канареек 0. Отчёт partial (1/384), приёмки нет.
- Первый Ubuntu privacy pilot 45094291240 не дошёл до оценки: ENOSPC при копировании
  client после native CPU теста. Данных для top-1 нет. ADR 0060 переводит оценку
  на единый release-профиль, закрепляет merged 7B hash и удаляет только полностью
  проверенные source shards после merge. Регрессии проверяют границы cleanup и
  сохранение merged. Все факты передаются атакующему; случайные nonce сопоставляет
  код, без раскрытия индекса субъекта. Калибровка усилена по язык × группа.
- После ADR 0059/0060 локально прошли fmt, весь workspace, clippy всех
  targets/features, leak, evaluator (4), scripts (24), extension (24), app (12)
  и native Tauri check. Логи: target/owned-peer-*.log. CI нового изменения
  требуется отдельно; один диагностический случай не заменяет полный корпус.
- ADR 0061: досье до 1 MiB делится на перекрывающиеся UTF-8 фрагменты без
  усечения; оценка человека — максимум, число кандидатов не увеличивается.
  Лимит всего набора 2 MiB; превышение/ошибка сохраняет L0. Полная история
  остаётся единственным запросом. Регрессия большого EN/RU/HY досье сначала
  воспроизвела отказ, затем проверила каждый факт, хвост и размер множества людей.
  Качество новой агрегации ещё требует development/held-out измерения.
- ADR 0062: полный development-прогон делится по целым разговорам на восемь
  заданий с общей сборкой бинарников. Объединитель требует все 384 случая,
  одинаковые хеши/политику/CI run и ни одного повтора или пропуска. Partial,
  failed и отдельный complete_shard не дают полный отчёт. Unit/файловые
  регрессии проверяют также несовпадение бинарника, настроек и запуска.
  Этот workflow пока не выполнен, held-out не создан.
- Проверка после ADR 0061/0062: workspace, clippy всех targets/features, leak,
  evaluator (4), scripts (28), extension (24), app (12), native Tauri check
  локально зелёные. Логи: target/segmented-dossier-*.log. Критерии этапов этим
  не закрыты; новый workflow и версия ранжирования требуют CI.

## Продолжение M3H — 2026-11-23

- ADR 0063: матрица 9 Device-источников × 6 кодировок и 7 детекторов × 6
  воспроизвела обход Base64 полного пути при сохранённом в vault имени.
  Добавлена ограниченная проверка декодированного содержимого, включая два
  слоя, переносы и бинарную обёртку. Регрессии полного пути, Device в route
  label и GEO прошли; вся матрица теперь зелёная локально. PCAP пока не снят.
- Полный [run 45098535892](https://github.com/dsahakyan15/NymWrap/actions/runs/45098535892)
  для 089aafa прошёл все 14 заданий, включая owned-child peer на Linux/macOS.
  Поздние ADR 0061–0063 требуют своего CI. Ubuntu privacy pilot
  [45098545114](https://github.com/dsahakyan15/NymWrap/actions/runs/45098545114)
  теперь дошёл до случая: ответ L0 полезен, raw-атака получила local_model_timeout.
  Run failed (1/384), метрика top-1 не засчитана. ENOSPC устранён в этом прогоне.
- ADR 0064: добавлен CI-сценарий настоящего локального Tor, двух netns, fscrypt
  и tcpdump/tshark. Синтетические provider/DNS работают без выхода в интернет;
  test-only PKI/key log позволяет проверить HTTP в pcap. Oracle требует все
  запросы/корзины и совпадение тел с provider receipt, отвергает пустую запись,
  утечки и прямые пакеты. Локально проверен только код/матрица/oracle; сценарий
  Linux ещё не выполнен. Production launcher и полный Core путь остаются открыты.
- После ADR 0063/0064 локально зелёные workspace, clippy всех targets/features,
  leak, nw-netd и его clippy, app (12), extension (24), scripts (31), native
  Tauri check; bash -n подтвердил синтаксис coordinator. Логи: target/base64-*.log,
  target/pcap-*.log. Настоящий Linux pcap пока требует CI.
- Локальный development pilot завершил 8/384 случаев: удалённых ходов 0,
  полезных ответов 6/8, канареек 0. Raw model valid 8/8, top-1 correct 2/8
  (оба — nonce-инъекции). EN/RU/HY связывание редких фактов этим атакующим не
  откалибровано. Полного отчёта/приёмки нет; все-L0 не считается защитой remote.
- Полный [run 45099848732](https://github.com/dsahakyan15/NymWrap/actions/runs/45099848732)
  для d806acb прошёл все 14 заданий. Он покрывает ADR 0061/0062 code/unit,
  но не исполняет manual development workflow и поздний pcap/B64 код.
- ADR 0065 меняет атакующий протокол: LLM выделяет факты, код ранжирует все
  64 досье, nonce и равенства; невалидный вывод не заменяется случайным ID.
  Для linkage-грамматик предел CPU 200 с, прочие операции остаются 110 с.
  Добавлены агрегаты настоящего linkcheck для разбора all-L0; observer не может
  изменить решение. Native CPU/private-IPC с новой грамматикой прошёл за 20,69 с.
  Новый полный development-прогон и калибровка ещё не проведены; CI заблокирован.
- ADR 0066 исправляет неработающий max_margin: положительный отрыв от лучшей
  приманки уже означал top-1, поэтому порог ничего не менял. Теперь фон — нижняя
  медиана приманок; регрессия проверяет решение для rank 4/65 при двух порогах.
  Начальные пороги не считаются откалиброванными; требуется новый полный замер.
- Подготовлен [ручной чек-лист аккаунтных адаптеров](ACCOUNT_ADAPTER_CHECKLIST.md):
  Google/YouTube Drift, YouTube Mirror, ручные снимки/ИИ-задачи, login/CAPTCHA,
  отмена, сохранение и отсутствие replay. Неподдержанные DOM-адаптеры отмечены
  manual only; реальные аккаунты агентом не открывались и не проверялись.

- Run 45085560190 завершился красным: Windows AppContainer отклонён до запуска
  worker с appcontainer_profile_acl:foreign_directory_owner. Desktop release и
  настоящий Firefox Native Messaging прошли; их успешный отчёт не подменяет
  ошибку Windows core. Добавлена короткая CI-регрессия создания одного профиля
  без выполнения кода worker. Исправление владельца нового каталога PT не решило
  владельца хранилища, создаваемого Windows API профиля; этот пункт открыт.
- Минимальная регрессия run 45090415120 воспроизвела тот же отказ без worker.
  ADR 0056 выбирает TokenUser владельцем новых объектов текущего процесса;
  привилегии и ACL существующих объектов не меняются. Локально прошли проверка
  области токена в дочернем процессе, создание профиля и все три настоящих
  AppContainer-теста. Та же короткая проверка прошла на Windows runner:
  [run 45091002400, job 137420285407](https://github.com/dsahakyan15/NymWrap/actions/runs/45091002400/job/137420285407).
  Полный run завершился зелёным; M6 этим не закрыт.
- [CI 45085560190](https://github.com/dsahakyan15/NymWrap/actions/runs/45085560190)
  подтвердил core macOS, network всех трёх ОС (включая настоящий Lyrebird Windows
  и Linux fscrypt), frontends/browser, зависимости, SBOM и Linux VM. На момент
  записи полный run завершился красным из-за Windows core и не засчитан.
  [Fuzz smoke 45085560256](https://github.com/dsahakyan15/NymWrap/actions/runs/45085560256)
  зелёный: audit_import / ipc_frames / shield_roundtrip, ASan, по 30 с,
  отчёты соответственно 31,515 / 31,740 / 31,277 с. Это не 24h и не закрывает M6.
- Текущий локальный пакет после наблюдений гигиены: workspace, clippy со всеми
  targets/features, leak, extension (24), app (11), scripts (16), native Tauri
  check и четыре cargo-deny прошли. Настоящий Windows probe и Lyrebird для
  трёх протоколов прошли отдельно. Отрицательная регрессия M6 ниже остаётся
  открытой и не засчитывается. Логи: target/hygiene-*.log.
- Run 45084257527 подтвердил network Ubuntu/macOS, frontends, browser и Linux VM;
  macOS core нашёл ещё один публичный tempfile parent в drift-host, исправленный
  на private/cover.sock. Полный run красный из-за этого и Windows PT fixture.
  Fuzz smoke дошёл до завершения shield, но не записал отчёт из-за отсутствия
  root target/ в чистом checkout. Инициализация каталога отчётов исправлена с
  отрицательной регрессией на symlink; новый реальный fuzz run обязателен.
- Реальный CI выявил Unix-фикстуры с публичным tempfile parent и отсутствие PID
  в Darwin xucred. Исправлены приватные подкаталоги и создание недостающего runtime;
  PID читается LOCAL_PEERPID без ослабления проверок uid/образа (ADR 0050).
  Локальная канареечная регрессия IPC прошла; macOS/Linux ждут нового полного CI.
- В аудите A6 выявлена отдельная незакрытая задача M6: один ACL пользователя
  недостаточен для авторизации shadow RPC против постороннего процесса того же
  пользователя при уже открытом vault. Добавлена явная негативная регрессия
  `unapproved_same_user_shadow_client_cannot_read_unlocked_secrets` в tests/leak.
  Она запускается отдельно и до исправления помечена открытым M6, не включается
  в доказательства прохождения укрепления. Нужны сессионная авторизация/роли,
  ограничения CLI rpc и отрицательный тест неразрешённого клиента в CI.

- Исправлено наследование hostname. В bwrap заданы localhost, uid/gid 1000,
  HOME=/home/user, USER/LOGNAME=user, TZ=UTC, LANG/LC_ALL=C.UTF-8. Passwd/group,
  machine-id, UTC localtime и gitconfig — общие неизменяемые memfd, без дискового
  staging. Linux-гость с намеренно другим hostname сначала воспроизвёл утечку,
  затем прошёл нормализацию и запреты сети/скрытых путей. Расширенный прогон
  с настоящим nw-probe тоже прошёл: target/linux-isolation/report.json.
- Добавлены Device и GEO/MAC/IMEI/USER_PATH/TZ/DATETIME/GUID, диапазоны координат,
  Лун, домашние пути Windows/WSL/Linux/macOS. DATETIME с явным смещением получает
  UTC-час внутри восстанавливаемого плейсхолдера. В tests/leak добавлены форматы,
  вредоносный echo модели, кодировки Device и reopen/rehydrate.
- Оба chat API явно отвергают вложения с 415/attachments_not_supported до модели.
  Единственный успешный путь разбора — строгая типизированная схема; повторяющиеся
  JSON-ключи не схлопываются. Есть регрессии вложений и дублей.
- Настоящие байты Hyper-заголовков и rustls ClientHello сверяются с golden. Порядок
  расширений закреплён минимальным локальным патчем rustls 0.23.46 (ADR 0044),
  без замены RNG. Windows тесты и cargo-deny nw-netd прошли; межплатформенный CI и
  pcap не проведены.
- X-NymWrap-Defer: целые 0–168 часов только для async submit, случайный not_before,
  зашифрованная очередь, запрет ранней отправки и повторов после restart. Окно входит
  в idempotency fingerprint; прежние квитанции без заголовка совместимы.
- nw-probe: отдельный ограниченный shadow worker, read-only git handle, системные
  идентификаторы, точный framed IPC, автоматический сбор раз в сутки, шифрованный
  список и сохранение пользовательских удалений. Настоящий Windows AppContainer
  и отдельные отрицательные TCP/UDP/FS/spawn тесты прошли. User/Wi-Fi недоступны и
  показаны как incomplete, без дополнительных capabilities (ADR 0045).
- Добавлен экран «Гигиена» с покрытием probe и ручными инструкциями. Начаты
  наблюдения настроек и hygiene_score (ADR 0051): доступные WLAN/NM профили,
  нейтральное имя, явные Windows-политики геолокации и LLMNR. Три состояния,
  покрытие и Pass/6 не позволяют считать непрочитанные пункты зелёными; снимок
  старше суток, будущее время и legacy без наблюдений не дают оценку. Проверены
  строгий WLAN namespace/parser и зашифрованное переоткрытие. Полные OS-источники,
  mDNS и недоступные OS-источники остаются неизвестными. Дополнения NetBIOS,
  часов Linux и политик Firefox описаны в задаче 4 выше. App сохраняет XSS-safe
  вывод буквальным текстом; полноценное наблюдение всех браузеров не заявляется.
- Новые планы получают детерминированное UTC-окно каждого этапа (ADR 0046).
  Окно входит в хеш одобрения; шаг не больше 2 часов, полночь поддержана. Core
  проверяет окно при выдаче задач, каждом validate search permit и завершении.
  Вне окна день не начинается; начатый день не продлевает разрешённые часы.
  Старые планы сохраняют хеш без поля activity. Полный локальный пакет после
  добавления окна прошёл: workspace, clippy со всеми targets/features, leak,
  extension (24), app (8). CI и аккаунтные проверки этим не подменяются.
- Начальная задержка 5–30 минут и явно согласованный хвост 10–60 минут реализованы
  для текущего standard/Tor адаптера (ADR 0047). Монотонный барьер стоит перед
  bootstrap/стоимостью/сетью; wall deadline может только сократить хвост после сна.
  Закрытие отменяет реальные задания и закрывает доступ к данным, Lock завершает
  всё сразу. Регрессии tests/leak/src/core_session.rs проверяют отсутствие выдачи
  секретов/истории и удаления без разблокировки, отмену queued/sending, недоступный
  транспорт/согласие, срок хвоста и отмену начального ожидания. Core/cover и app
  локально прошли; реальный pcap и CI остаются открыты. Хвост strict/paranoid
  явно недоступен до L1/L2 и одобренной очереди (решение задачи 4).
- Добавлены управляемые obfs4/Snowflake/WebTunnel через tor-ptmgr 0.48.0 и
  закреплённый Lyrebird Expert Bundle 16.0.1 (ADR 0048). Подпись официального
  списка и хеши архивов/бинарников пяти платформ проверены. Схема не принимает
  команды/пути/argv; приватные строки — в Vault и в запретах Shield. Контекст
  одобрения учитывает мосты; при сбое нет прямого fallback. В fork ptmgr закрыты
  наследование окружения и тихий живущий ребёнок при Drop: настоящий синтетический
  регрессионный тест прошёл. На Windows прошёл также закреплённый Lyrebird для
  всех трёх локальных слушателей и их завершение, cargo-deny зелёный. Linux CI
  с fscrypt прошёл в run 45084257527. Windows CI выявил владельца Administrators
  у нового temp-каталога: новые каталоги получают явного владельца при создании
  (ADR 0052), существующий чужой владелец по-прежнему отвергается; повтор CI
  ещё нужен. Задача 4 добавляет обязательную песочницу PT и локальный obfs4
  bootstrap/pcap в CI; новая CI-приёмка и остальные bootstrap остаются открытыми.
- Актуальные ограничения и локальные журналы M3H перечислены в задаче 4 выше.
  Частичное покрытие и добавление CI не закрывают этап без зелёной приёмки.

| Область | Реализовано | Остаётся |
|---|---|---|
| Shield | Classify/minimize/leakcheck/rehydrate, секреты, IPv4/IPv6, кодировки, транслитерация, нечёткая проверка, локальная NER с проверкой буквальных фрагментов, canonicalize, полный удалённый конвейер; детерминированные ограничения личных/чувствительных сведений и неполностью скрытых составных имён; локальный оценщик на 62 синтетических кейсах | Независимая оценка на новых данных, одиночные/строчные имена и косвенные признаки, независимый split и поиск |
| Локальная модель | nw-llmd с CPU llama.cpp, SHA-256, свежие контексты, greedy generation/nomic; Windows native worker в одноразовом LPAC с двумя read handles; запуск из UI с контролем PID, таймаутом, kill_on_drop и stdin-lifetime | Изоляция брокера и остальных ОС, оптимизация повторной загрузки |
| IPC/API | Общий типизированный RPC, SID ACL/peer, версии/полосы/лимиты/PID; local/remote-модели, min-trust, одноразовый human review; async HTTP submit/poll/cancel; сохраняемый Idempotency-Key для submit с tombstones и без replay | Проверки на всех ОС |
| Хранение | SQLCipher по доменам, XChaCha записей, OS key store + Argon2id, блокировка store, защищённые ключи, атомарная ротация root и crypto-shredding с восстановлением очистки | Проверка сбоев на всех ОС и полный аудит жизненного цикла памяти |
| Разговоры | Раздельные версии vault и истории, immutable prefix, provider binding, retention; замороженный review с TTL/nonce; сохраняемые задания, опрос/отмена/Uncertain без replay, параллельный L0 | Проверки на всех ОС |
| Audit | JSON/ZIP/HTML/SQLite; отдельный worker, Linux bwrap/seccomp и Windows LPAC без сетевых capabilities/записи; stdio-only, job limits, точная схема и EOF, единый путь CLI/UI; запрет nested ZIP с учётом BOM | macOS App Sandbox, расширенные реальные форматы экспортов и длительный fuzz |
| Persona | Локальная модель получает ограниченную сводку, доказательства берутся по индексам источника, каждую черту подтверждает человек | Дополнительные проверки качества на закреплённой рабочей модели |
| Drift | Reference math, 3 попытки плана, детерминированные проверки, hash-bound approval, отдельные дневные варианты, прогресс/пауза/12 часов, задержка по Mirror; поиск Google/YouTube в человеческом темпе по одноразовому permit, повторный финальный leakcheck; настоящие Chromium/Firefox MV3 на синтетических HTTPS-страницах | Аккаунтные DOM и сквозная работа с реальными сервисами, дополнительные адаптеры видео/ИИ |
| Purge | Ранжирование импорта, просмотр/выбор партии, хеш одобрения, локальный шаблон; пять отдельных offline-инструкций с официальными источниками, сохраняемые ручные отметки и наблюдаемый результат партии | Живая проверка актуальных интерфейсов сервисов пользователем |
| Mirror | Снимки, реальные embeddings/позиции, график по источникам, таблица, ручной account activity; наблюдаемые cover/challenge rates; ежедневный YouTube по opt-in с суточным резервом и safety stop; реальные Chromium/Firefox alarms на синтетической ленте | Персонализированный DOM реальных аккаунтов, периодические снимки остальных источников; MyAdCenter пока вручную |
| Расширение | MV3 Chrome/Firefox сборки, native messaging, строгий cover-only протокол, ручные задачи и snapshots; opt-in Mirror и поисковый executor с optional permissions, CAPTCHA/login stop и no replay, XSS-safe текст; изолированные Chromium/штатный Firefox integration tests и чтение публичного DOM | Аккаунтные интерфейсы и сквозная работа с реальными сервисами, адаптеры видео/ИИ |
| Сеть | nw-netd/arti, отдельный клиент на разговор, проверяемый HTTPS, DNS через Tor, EFS/fscrypt до bootstrap, AEAD IPC, полный Route, nonce-bound review, budget reserve, watcher cancellation и parent lifetime; Linux production launcher, настоящий startup core и процессный Tor/TLS/HTTP pcap: M2 подтверждён тремя CI-прогонами | M6: установщик службы/coordinator GUI, файловая песочница Linux, изоляция core/netd Windows/macOS; очередь paranoid |
| Удостоверения | OS credential store, mlock, зашифрованный staging/каталог, постоянные привязки ключей к разговору, интеграция Route, восстановление и удаление OS-записей | zkAPI |
| Cover traffic | Poisson/Constant standard, FIFO реальных заданий в слотах, независимая предварительная подготовка приманок, одноразовые Tor-клиенты, encrypted slots/jobs, общий бюджет, Uncertain без replay; семидневный core → netd OS pcap и пять корзин тел подтверждены зелёной CI-приёмкой M3 (ADR 0084) | Точный ритм пакетов реального времени, paranoid с более сильным маршрутом; выравнивание реальных пакетов по корзинам |
| Жёсткие данные (M3H, ADR 0043–0048, 0085) | Device и семь детекторов; нормализованный bwrap; явное покрытие девяти источников с fail-closed, Windows/macOS native adapters и ограниченные probe workers; шифрованные секреты с сохранением удалений; отказ вложений; HTTP/TLS byte golden и сравнение CI artifacts; Defer; задержка и хвост standard, явный запрет хвоста strict/paranoid с L3; обязательная PT-песочница Linux/macOS, Windows PT fail-closed; локальный obfs4 pcap, macOS worker и байты трёх ОС подтверждены зелёной CI-приёмкой M3H; частичная автоматическая гигиена/Pass/6; UTC-окна легенды | Недоступные источники/наблюдения остаются неизвестными; bootstrap Snowflake/WebTunnel; изоляция Windows PT и шифрованное состояние транспорта macOS; WSL2 агентов; хвост strict/paranoid до L1/L2 и одобренной очереди |
| M6 | Закрепления/deny/CSP/mlock; Linux seccomp TSYNC/bwrap, реальные проверки в QEMU/Alpine под UID 1000; Windows LPAC импортера и native модели; отрицательные TCP/UDP/FS/spawn/read-handle проверки; source SBOM для трёх targets; coverage/ASan smoke импортёров, IPC/core RPC и Shield с отчётами | Изоляция остальных Windows-процессов, полные Linux-демоны и macOS, MicroVM, vet, подписи, воспроизводимость бинарников на двух машинах, 24h fuzz и проверка инструментации C/ASM |
| M7 | Экспериментальные флаги, проверены upstream pin/deployment/dependency gates (ADR 0024) | Nym требует обновлений SDK и транзитивных зависимостей; указанная zkAPI-ветка не развёрнута и не имеет production proving keys; адаптеры не завершены |

## Подтверждённые локальные проверки

- Настоящие Windows named pipes: OpenAI HTTP, IPC frame/lane и cover stdio relay.
- Сквозной tests/e2e/local.mjs: настоящий OS key store, worker, CPU модель,
  OpenAI HTTP, продолжение разговора после перезапуска core, native host,
  отсутствие синтетического открытого текста на диске, очистка fixture.
- Настоящая сеть Tor: два изолированных клиента получили разные идентификаторы
  цепочек. Состояние и кэш созданы с EFS-шифрованием. Это не тест всех свойств M2.
- Полный Route через Tor/HTTPS: терминальная ошибка синтетического запроса
  учитывается один раз. После kill core netd завершается, резерв остаётся без replay.
- Async HTTP через настоящие core/CPU: обязательный просмотр, усиление min-trust,
  отмена ожидающего задания без расходов, чувствительный ввод остаётся L0.
- Замороженный human review: канарейки, точный transcript, один вызов canonicalize,
  TTL, отмена, подмена hash/провайдера и повторное одобрение. Настоящий CPU-тест
  проходит NER по фиксированной грамматике; сквозная отмена не тратит бюджет.
- Windows LPAC: импорт Takeout проходит в настоящем сквозном сценарии; отдельный
  probe проверяет FS/TEMP/spawn и отсутствие доставки TCP/UDP. Профиль удаляется.
- Настоящее ядро Linux 6.18.60-0-virt в QEMU TCG/Alpine 3.24.4, без WSL или
  администратора Windows: musl-сборка platform/sandbox, mlock, seccomp и bwrap
  прошли под UID 1000. Положительный контроль TCP/UDP работает до фильтра;
  существующий и новый потоки после TSYNC получают EPERM, Unix IPC работает.
  Агент видит только рабочий каталог и API socket; приватный файл Linux-гостя,
  core socket и TCP/UDP недоступны. Исправлен тип ioctl для glibc/musl. Команда,
  пределы и пины — ADR 0039. Это не прогон всех Linux-демонов или production MicroVM.
- Windows native модель: настоящий бинарник проходит CPU/NER/embeddings через
  приватный IPC; read handle работает при запрете записи и открытия GGUF по пути.
  Worker mode вне AppContainer отвергается. Инференс завершается вместе с job.
- Предварительная подготовка приманок: канарейка не передаётся генератору,
  инъекция блокируется после модели, устаревший epoch не отправляется. Настоящий
  Tor SendOnce завершился без сохранения записи разговора.
- Уязвимые транзитивные RSA/SQLite в Arti заменены локальными патчами; исходный
  RSA-вектор Tor проходит, cargo-deny сетевой сборки не исключает advisories.
- HTTP serializer nw-netd: перехват настоящих Hyper-байтов в памяти проверяет все
  пять корзин, Content-Length, полный allowlist заголовков и канарейки; отдельно
  проверяются redirect/gzip/HTML/tool_calls/oversize отказы. Это граница до TLS,
  а не измерение пакетов или ритма на выходе ОС.
- SQLCipher: поиск синтетического открытого текста в файлах, reopen/wrong password,
  domain shred, запрет старого root после ротации, уничтожение store.
- Настоящий Windows Credential Manager: синтетическое пространство под target
  создано, открыто повторно и уничтожено тестом.
- Настоящий CPU inference через приватный IPC: Qwen2.5-0.5B отвечает на проверочный
  вопрос, nomic выдаёт 768-мерные векторы и различает связанные и разные темы.
  Модели получены из официальных репозиториев по закреплённым ревизиям и SHA-256.
- Синтетическая оценка privacy-v1 на настоящем worker: 16 кейсов, 10 валидных
  ответов NER и 6 отвергнутых; ошибок транспорта нет. Маленькая Qwen 0.5B не
  проходит строгий критерий качества. После усиления детерминированной политики
  unsafe_remote_cases в этом корпусе равен нулю, включая вложенную инструкцию
  пропустить имя. Это ограниченный тест minimize/NER/policy, без canonicalize и
  отправки; общее качество и полнота распознавания не подтверждены (ADR 0038).
- Официальная Qwen2.5-7B-Instruct Q4_K_M получена по immutable revision и двум
  LFS SHA-256, объединена ограниченным Node-парсером без изменения тензоров
  (ADR 0040). Свежий KV cache ограничен размером фактического запроса. Release E2E
  с этой моделью прошёл через настоящий core/HTTP/LPAC, ответы L0, отмену review,
  перезапуск и зашифрованную историю; это проверка работоспособности, не анонимности.
- Корпус privacy-v2 содержит 62 вымышленных EN/RU/HY кейса и 12 попыток связывания
  одиночного/двухходового текста с восемью досье. Он уже выявил медицинскую
  инъекцию и пропуск неизвестного составного имени в кандидате на выход 7B.
  Внешней отправки не было. Добавлены независимые ограничения тем и составных
  имён, включая частичную NER-маску; canaries проверяют пустую NER и стирающий
  rewrite. Агрегатор требует полные прогоны с одинаковым происхождением,
  отделяет L0/отказы/качество задачи от утечек и калибрует атакующего. Вероятность
  распознавания реального человека из такого корпуса не выводится (ADR 0042).
- В окне desktop: создание пространства, импорт синтетического Takeout, буквальный
  XSS-текст, построение персоны настоящей моделью, блокировка/разблокировка с
  восстановлением сводки и персоны.
- В пересобранном desktop: линии Mirror/фильтр/точки с Tab, просмотр ожидающего
  задания, отмена и восстановление исходного текста без повторной отправки.
  Синтетическое пространство и OS-ключи удалены, резерв сети остался нулевым.
- Тесты расширения проверяют CAPTCHA/login, URL allowlist, строгую схему cover,
  отклонение shadow-полей, корреляцию ответов и отсутствие повторов при disconnect.
- Исполнение popup.js в тестовом DOM проверяет, что CAPTCHA остаётся локальной
  до явного safety report; передаются только id/reason, Drift переходит на паузу.
  Миграция counters, дедупликация и rates проходят reopen зашифрованного workspace.
- Настоящий Chromium/MV3: popup и service worker выполняют Google/YouTube поиск с реальными
  scripting/InputEvent и задержками, фиксированную навигацию и чтение; alarm
  снимает синтетическую YouTube-ленту. CAPTCHA останавливает ввод/поиск; потеря
  результата scripting после фактического ввода не повторяет символ. Проверены
  XSS-текст, отсутствие body-канарейки в core и содержимого в extension storage.
  Страницы — loopback HTTPS, native host — общий тестовый обработчик. Профиль
  временный; пользовательский браузер и аккаунты не использовались (ADR 0037).
- Штатный Firefox 160.0.1/MV3: Google/YouTube поиск, alarm, остановка на CAPTCHA
  и входе, XSS-текст и отсутствие содержимого в extension storage прошли на
  loopback HTTPS с временным профилем и синтетическим native host. Исправлена
  гонка навигации about:blank. Chromium также повторно прошёл сценарии (ADR 0041).
- Живой публичный DOM в отдельном Firefox: поля Google/YouTube распознаны;
  незалогиненная YouTube-лента пуста. MyAdCenter перенаправил на анонимные
  настройки, его неподтверждённый селектор удалён. ChatGPT/Gemini открыли
  публичные страницы с элементами ввода, Claude показал вход/challenge.
  Поисков, сообщений, видео и обхода проверок не было; сохранялись только
  состояния и количества. Аккаунтные адаптеры и персонализированные ленты
  этим не проверены, рекламные темы Mirror добавляются вручную.
- Настоящий Firefox Native Messaging связался с release nw-drift-host/core через
  временный HKCU alias. Кнопки паузы/возобновления изменили состояние настоящего
  синтетического пространства; отдельный вызов подтвердил оба состояния.
  Сетевых резервов нет. Регистрация, профиль, пространство и OS-ключи удалены;
  происхождение компонентов записано в firefox-native.json (ADR 0041).
- Настоящий native desktop пересобран и запущен в пустом тестовом каталоге:
  отрисовались «Обзор» и актуальные пять показателей Mirror. Пространство не
  создавалось; окно и дочерние процессы завершились после проверки.
- Актуальный release-комплект из восьми exe собран в app/src-tauri/target/release;
  семь соседних компонентов сверены с build outputs по SHA-256. E2E --release
  --with-tor прошёл на этом комплекте: LPAC/CPU/HTTP, Tor, hard-kill/recovery,
  native host, safety stop и encrypted at-rest scan. Release-окно отдельно
  открыто в пустом тестовом каталоге. Это локальная неподписанная сборка.
- Windows coverage/ASan smoke по 30 секунд для import, IPC/core RPC и Shield.
  Падений не было. Все три цели повторно проверены после HTTP receipt, Purge
  result, search execution и personal-disclosure policy; хеш исходников совпадает
  у трёх отчётов. Это короткие прогоны; 24-часовая кампания и native C/ASM отдельно не
  подтверждены. Команды и пределы — в fuzz/README.md, решение — ADR 0032.
- Отдельная Windows-проба подтвердила, что текущий LPAC не может читать или
  записывать даже синтетический Credential Manager item. Поэтому перенос core
  в существующий профиль импортера без изменения архитектуры не реализован;
  запуск брокера без изоляции не засчитан как выполнение M6.
- cargo-deny проверяет advisories, licenses, bans и sources. Исключения лицензий
  закреплены отдельными пакетами и версиями в deny.toml и объяснены в ADR.

Полные команды: scripts/check.ps1 и scripts/check.sh. Текущие журналы проверок
находятся только в игнорируемом target. Эти локальные проверки не заменяют CI,
захват реального трафика, многосуточный fuzz или подтверждение анонимности.
