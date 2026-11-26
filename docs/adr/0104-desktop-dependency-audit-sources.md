# Источники cargo-vet и ограниченное доверие для desktop

Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только для
`app/src-tauri/Cargo.toml` и `supply-chain/desktop/`. Продуктовый критерий остаётся
`safe-to-deploy`: он включает безопасность при недоверенном вводе и безопасность
кода, создаваемого build dependencies/макросами. Политика fuzz `safe-to-run` из
[ADR 0088](0088-fuzz-dependency-audit-sources.md) сюда не переносится. Версии,
Cargo.lock, код приложения и stores остальных графов не меняются; exemptions нет.

## Закреплённые внешние проверки

Mozilla и Google сохраняют commits из ADR 0073. Прямо доверяем опубликованным
атрибутированным проверкам ещё четырёх команд, рассмотренных в ADR 0088:

- **Bytecode Alliance**, команда production runtime Wasmtime:
  [1499ce8728f5f1b7fae0db88e1417991b01cfc13](https://github.com/bytecodealliance/wasmtime/blob/1499ce8728f5f1b7fae0db88e1417991b01cfc13/supply-chain/audits.toml).
- **ISRG / Divvi Up**, разработчики privacy aggregation libprio-rs:
  [7549f3c7dffe96d3a6e6fb214007911cdec3e8e6](https://github.com/divviup/libprio-rs/blob/7549f3c7dffe96d3a6e6fb214007911cdec3e8e6/supply-chain/audits.toml).
- **Zcash**, агрегат проверок команд librustzcash, wallet и zcash:
  [ce132d7abdd52f2b3b0d55ed5dc9f152331535c2](https://github.com/zcash/rust-ecosystem/blob/ce132d7abdd52f2b3b0d55ed5dc9f152331535c2/supply-chain/audits.toml).
- **Embark Studios**, разработчики cargo-deny и Rust-приложений:
  [732513edfd9172f4eda358b2d0cefc6cad1585ee](https://github.com/EmbarkStudios/rust-ecosystem/blob/732513edfd9172f4eda358b2d0cefc6cad1585ee/audits.toml).

Сохраняются исходные criteria, авторство и ограничения. Чужие imports,
exemptions и локальные решения `trusted` не наследуются; слабые criteria не
отображаются на `safe-to-deploy`. SHA-256 исходных наборов сохранены в
[JSON-отчёте](../../supply-chain/desktop/review-2026-11-26.json).

У **Tauri** найден публичный
[store на c868ce68f78d1a471bc1810b0ac7d13e956099b3](https://github.com/tauri-apps/tauri/blob/c868ce68f78d1a471bc1810b0ac7d13e956099b3/supply-chain/audits.toml).
Он содержит пустой `[audits]` и локальные `trusted`, без full/delta или wildcard
аудитов. Import не добавлен: локальное доверие команды не является переносимой
проверкой исходников. В полных деревьях wry, tao и **CrabNebula cargo-packager**
на закреплённых в отчёте commits store не найден. Это результат проверки этих
репозиториев, а не заявление об отсутствии аудитов во всей организации.

## Доверие к публикаторам для продукта

Повторно рассмотрен список ADR 0088. Доверие — отдельное решение о конкретных
пакетах и публикаторах для `safe-to-deploy`, согласно
[механизму cargo-vet](https://mozilla.github.io/cargo-vet/trusting-publishers.html).
Это эвристика доверия разработке и выпуску, а не собственный аудит кода и не
гарантия отсутствия ошибок. Обоснования для каждого identity и каждого пакета
записаны в `audits.toml` и отчёте:

| Публикатор (crates.io id) | Основание для `safe-to-deploy` в выбранных пакетах |
|---|---|
| dtolnay (3618) | Сериализация, обработка ошибок и генерация Rust-кода для production; учитывается безопасность созданного кода |
| alexcrichton (1) | Rust/Cargo/Wasmtime, native build и системные утилиты; доверие намеренной работе с выбранным toolchain |
| tarcieri (267) | Руководитель RustCrypto; доверие реализации production crypto/KDF/secret-memory, включая unsafe и constant-time контракты |
| newpavlov (5059) | Руководитель RustCrypto; production hash/crypto support и обработка входных данных |
| taiki-e (33035) | Production async/atomic/pinning utilities, включая soundness созданного unsafe-кода |
| seanmonstar (359) | Hyper/HTTP и обработка враждебного протокольного ввода |
| Darksonn (6741) | Tokio, bytes и slab; конкурентность, длины буферов и unsafe-контракты |
| BurntSushi (189) | Production regex/search/byte utilities и документированные ресурсные ограничения |
| cuviper (539) | Rust/rayon/rust-num; численные операции, коллекции и build probing |
| kennykerr (64539) | Официальные Windows bindings/import libraries; unsafe-вызовы и права ОС остаются обязанностью вызывающего кода |
| epage (6743) | Cargo/clap/TOML; разбор недоверенной конфигурации и поведение генерируемого кода |
| Amanieu (2915) | Production locking/collections; unsafe storage, lifetimes и синхронизация |
| sunfishcode (6825) | Production rustix/WASI и kernel bindings; FFI soundness при отдельной политике capabilities |
| Thomasdezeeuw (6025) | Production Mio/socket2; unsafe OS I/O и readiness, без передачи права на сетевой выход |

Также отдельно рассмотрены семь официальных GitHub Trusted Publishing identities
из ADR 0088: `rust-lang/cc-rs`, `rust-lang/flate2-rs`, `rust-lang/libc`,
`rust-lang/log`, `RustCrypto/hashes`, `RustCrypto/utils`,
`taiki-e/pin-project-lite`. Основание для production trust соответственно:
native toolchain/build helpers; разбор сжатых данных; FFI bindings; logging facade;
hash implementations; zeroization/derive; soundness pin-projection macros.
Их точные `repository`, `sha`, `run_id`, даты и обоснования сохранены в отчёте.
Не заявляется отдельная проверка workflows или криптографический аудит.
Остальные identities исходного списка не добавлялись без подходящих доказательств.

Каждая итоговая запись охватывает **один UTC-день публикации** `[start, end)`:
`end` — следующий день. Для старой и новой версий одного пакета записываются
разные окна; многолетних промежутков и доверия к будущим версиям нет.

Живой API crates.io отвечал HTTP 429. Повторно использованы только исходные JSON
ответы из продолжения ADR 0088, чей SHA-256 совпал с уже закоммиченным отчётом.
Для точных desktop-версий проверены `published_by.id/login` либо
`trustpub_data.repository`, дата, отсутствие yank и checksum. Архивы `.crate`
заново сверены с этим ответом, sparse registry index и desktop Cargo.lock.
Неподтверждённым версиям доверие не добавлялось; свежесть проверки API не заявляется.

## Проверки агента и промежуточный результат

Baseline на `4691e27`: **514** пробелов. Четыре imports последовательно дают
**482, 480, 472, 463**. Доверие 14 user-id и 7 workflow identities рассмотрено
для 120 точных версий и закрывает **118** пробелов: остаток **345**.
`digest 0.10.7` и `hashbrown 0.12.3` остаются в выдаче locked gate;
наличие записи доверия не было выдано за прохождение проверки.

Затем записаны две полные проверки агентом с критерием `safe-to-deploy`:

- `version_check 0.9.5` — 61 транзитивный потребитель; просмотрены все четыре
  модуля, manifests и inventory, рассмотрены compiler subprocess, env и парсеры.
  Пройдено 10 unit tests и 26 doctests; отсутствующие upstream static fixtures
  тестом пропускаются и не объявляются проверенными.
- `stable_deref_trait 1.2.1` — 36 транзитивных потребителей; рассмотрены unsafe
  marker contracts и каждый unsafe impl, стабильность адреса, guards и aliasing.
  Пройдено 6 doctests; скомпилированы no-default, alloc и std варианты.

В обеих записях явно сказано **«проверено агентом, не человеком»** и указан SHA-256
архива. Просмотренные файлы сверены с членами архива. Это новые production
проверки, а не повышение критерия прежних fuzz-аудитов. Более крупные узлы с
большим fanout отложены с причинами; inventory и поиск API не заменяют аудит.

Итог — **343 пробела**, закрыт 171. После каждого шага сохранены число пробелов,
команда, код выхода и хеши входов. Полный остаток упорядочен по числу зависимых
в JSON-отчёте. Финальный `node scripts/vet-dependencies.mjs desktop` выполнен
без обновления imports, с неизменными входами и красным результатом. M6 и
dependency-audits desktop остаются открытыми.

`cargo-deny 0.22.0` для desktop прошёл; tests расширения — 24/24, tests
vet-wrapper — 3/3. Workspace tests, clippy и leak tests запускались, но сборка
vendored OpenSSL остановилась до проверок из-за отсутствующего `perl`.
Все Cargo.lock сохранены. Эти локальные результаты не заменяют CI.

## Продолжение от 9e07392 — 2026-11-26

Исходное состояние **343 пробела** воспроизведено repository-wrapper с locked
imports. Дополнительные зарегистрированные stores Actix, Fermyon и Ariel OS
рассмотрены на immutable commits, их SHA и решения записаны в
[отдельном отчёте продолжения](../../supply-chain/desktop/review-2026-11-26-continuation.json).
Actix не пересекается с нужным desktop-графом; старый набор Fermyon не даёт
нового покрытия. У Ariel OS найден подходящий конечный delta для futures-lite,
но не подтверждён полный новый путь от доверенной базы; у других записей
заметки оставляют открытыми вопросы Send/Sync safety. Одного присутствия
в реестре недостаточно. Новых imports и переноса чужого local trust нет.
Шесть прежних источников заново сверены по тем же закреплённым URL.

В отличие от первого прохода, API crates.io для **точной версии** отвечает
успешно. Для каждой выбранной публикации сохранены URL, SHA-256 ответа,
полный version record, `published_by` либо `trustpub_data`, дата и checksum;
архив проверен одновременно против API, sparse index и desktop Cargo.lock,
yanked-релизы исключены. Не используется одно лишь текущее владение пакетом.
Это свежая registry-проверка конкретной публикации, а не повторное использование
старого ответа ADR 0088. Все новые окна снова равны одному UTC-дню `[start,end)`.

Продолжено package-specific доверие к 11 user-id и двум workflow identities,
уже рассмотренным выше; область каждого нового пакета записана в notes.
Отдельно добавлены два решения:

- **KodrAus (3204), только bitflags 1.3.2 и 2.13.2.** Registry подтверждает
  публикатора обеих версий; закреплённый changelog текущего релиза подтверждает
  его работу над генерацией макросов и сопровождением библиотеки. Доверие
  относится к production-коду макросов, парсингу и interop-контрактам.
  Документированное сохранение неизвестных битов не считается проверкой
  разрешений или валидатором входа. На uuid и другие пакеты аккаунта это
  решение не распространяется.
- **github:RustCrypto/traits, только crypto-common 0.2.2 и digest 0.11.3.**
  Официальный набор production crypto traits команды RustCrypto; manifests
  указывают этот repository и RustCrypto Developers, VCS commits архивов
  совпадают с `trustpub_data.sha`. В scope входят размеры буферов, секретные
  значения и hash/MAC API. Это отдельное решение о maintainer/release trust,
  без заявления независимого криптографического аудита или полного аудита
  workflows. Реализации алгоритмов и зависимости проверяются отдельно.

Всего добавлено **50 точных версий** в 15 группах доверия: 12 user-id и три
workflow identities. Locked-остаток после этих шагов — **293**. Для smallvec
identity официального workflow и VCS commit тоже подтверждены, но новое
доверие или сертификат исходников из этого факта не выводились.

Объяснено ограничение cargo-vet 0.10.4: `resolve_package_required_entries`
вычисляет необходимые imports/publisher records сразу для **всех версий одного
имени**. Непокрытая версия мешает сохранению свежего покрытия других версий
того же пакета. Неуспешный unlocked `check` при этом может вычислить меньше
пробелов, но `cmd_check` не сохраняет imports на ошибке. Поэтому диагностические
288 пробелов одного unlocked запуска **не засчитаны**; каждый заявленный замер
повторён через locked repository-wrapper. Версии инструмента, критерии и
политика не менялись; imports.lock вручную не дополнялся ради меньшего числа.

Затем полностью просмотрены оба manifests и все пять production-модулей
**once_cell 1.21.4**, узла с 45 транзитивными потребителями. Рассмотрены
single-assignment/reentrancy, публикация Release/Acquire, tagged очередь
стековых waiters, panic cleanup, bounds Send/Sync, владение OnceBox/OnceRef
и опциональные parking_lot/critical-section backends. В записи явно написано
**«проверено агентом, не человеком»**, указан SHA-256 архива и границы проверки.
Прямые pinned rustc/rustdoc проверки дали 5 unit tests и 42 doctests без ошибок,
один doctest пропущен upstream; std+alloc+race, no-default и alloc+race варианты
собраны. Runtime-проверки опциональных зависимостей, Miri, sanitizers и
межплатформенная матрица не заявляются.

Крупнейшие незавершённые узлы явно отложены. Для недостающего перехода
hashbrown 0.14.0 → 0.14.2 проверены оба архива и inventory полного diff:
4694 вставки и 599 удалений, включая новый table API и существенный unsafe-код.
Этот просмотр не завершён и не сертифицирован. Неполные просмотры
target-lexicon и version-compare также не выданы за аудиты; конкретные причины
и полный оставшийся список отсортированы по fanout в отчёте.

Итог продолжения — **292 пробела**, закрыт ещё **51**. Финальный
`node scripts/vet-dependencies.mjs desktop` остаётся красным, без обновления
imports и с неизменными входами; `cargo-deny 0.22.0` desktop зелёный.
Изменены только desktop store, этот ADR и desktop-раздел IMPLEMENTATION.md.
Все Cargo.lock и config.toml сохранены, новых exemptions нет. Полные сборочные
и extension-тесты в этом продолжении не запускались согласно ограниченной
проверке supply-chain/docs из задачи. M6 и CI gate остаются открытыми.
