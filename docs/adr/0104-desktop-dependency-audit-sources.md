# Источники cargo-vet и ограниченное доверие для desktop

Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только для
`app/src-tauri/Cargo.toml` и `supply-chain/desktop/`. Продуктовый критерий остаётся
`safe-to-deploy`: он включает безопасность при недоверенном вводе и безопасность
кода, создаваемого build dependencies/макросами. Политика fuzz `safe-to-run` из
[ADR 0088](0088-fuzz-dependency-audit-sources.md) сюда не переносится. Версии,
Cargo.lock, код приложения и stores остальных графов не меняются. Первые три
прохода выполнены без exemptions; единственное исключение четвёртого прохода
для недостижимого дефекта `dirs-sys` разобрано ниже, без ослабления CI gate.

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

## Третий проход от a1cb2f1 — 2026-11-26

Исходные **292 пробела** воспроизведены locked repository-wrapper. Все 292
точные версии сначала сгруппированы по публикатору и типу поверхности проверки
в [отчёте третьего прохода](../../supply-chain/desktop/review-2026-11-26-desktop-3.json).
Идентификаторы и даты получены из exact-version API crates.io, архивы сверены
одновременно с API, sparse index и неизменным desktop Cargo.lock; yank исключён.
Полные ответы кешированы в target/, в отчёте — URL, SHA ответа и проверенные поля.
Новые запросы начинаются с интервалом 1100 мс, максимум три в полёте; реализованы
паузы/retry-after и exponential backoff при 429/5xx.

Проверен последний commit, менявший audit-файл каждого из шести imports: все
совпали с уже закреплёнными commits. Immutable-файлы скачаны и хешированы заново;
новых imports, criteria mappings и заимствования чужого local trust нет.
GitHub commit API затем ограничил запросы HTTP 403; недоступные lookup не
объявляются выполненными. Immutable raw README/manifests оставались доступны.

### Решения о product publisher trust

Рассмотрены 192 точные версии. Две записи уже существовали (getrandom 0.2.17
и hashbrown 0.12.3), добавлено **190 записей**, 55 identities в 39 группах.
Каждая запись — один исторический UTC-день [start,end), один пакет и конкретный
user-id либо trusted-publisher. Это доверие разработке и выпуску для
**safe-to-deploy**, включая hostile input и generated code, а не независимый
аудит исходников. Нельзя вывести отсутствие ошибок из имени команды или OIDC.

Registry published_by/trustpub_data подтверждает именно публикацию. Current
owners/team membership — отдельное дополнительное свидетельство; список owners
не выдаётся за доказательство персонального членства в команде в прошлом.
Сверены canonical repositories, archive manifests/VCS metadata и project README
excerpts; полного чтения кода доверенных семейств не заявляется. Во всех 24
новых workflow-записях VCS commit архива совпал с registry trustpub_data.sha.
Для Google zerocopy immutable README не найден (404): основание явно ограничено
официальной registry-attested identity, manifest и совпавшим VCS SHA. У двух
libappindicator manifests нет repository; canonical Tauri fork README проверен
на том же archive commit, отдельно подтверждены tauri-bot и registry ownership.

| Семейство (новых записей) | Точные identities | Основание safe-to-deploy и граница доверия |
|---|---|---|
| dropbox-brotli (4) | danielrh (4185) | Официальные Dropbox Rust Brotli/allocator packages и их maintainer: malformed streams и unsafe storage; лимиты распаковки задаёт потребитель. |
| smol (6) | zeenix (6423), fogti (2340), notgull (69526) | Сопровождающие smol-rs: atomic queues, wakeups, cancellation, pinning и блокирующие операции; sandbox по-прежнему ограничивает способности вызывающего кода. |
| gtk (24) | sdroege (3623), GuillaumeGomez (111), bilelmoussaoui (54339) | Официальные GTK/GNOME bindings: генерация ABI, refcount, потоки и недоверенный GUI/protocol input; native библиотеки и capabilities проверяются отдельно. |
| base64 (3) | marshallpierce (5563) | Автор rust-base64: hostile lengths/alphabet/padding и optimized buffer contracts; encoding не является шифрованием. |
| bytemuck (1) | Lokathor (7211) | Автор bytemuck: hostile byte slices/alignment и unsafe Pod/Zeroable contracts; downstream unsafe impl остаются обязанностью потребителя. |
| rust-project (4) | rust-lang-owner (55123), Noratrieb (130181) | Rust/Cargo и сопровождающие коллекций: platform/glob parsing, unsafe storage/drop и compiler hashing; HashDoS требует подходящего hasher у потребителя. |
| chrono (1) | djc (4556) | Release maintainer Chrono: production calendar/time parsing, ranges и OS integration; приватность TZ остаётся политикой приложения. |
| rustcrypto (2) | github:RustCrypto/formats, github:RustCrypto/hybrid-array | Официальные RustCrypto formats/hybrid-array: OID/buffer bounds и array/trait contracts; независимый криптоаудит не заявляется. |
| servo (20) | jrmuizel (5946), jdm (2396), Manishearth (1139), SimonSapin (7), mrobinson (2844), Loirooriol (437040) | Команда браузерного движка/rust-url: hostile HTML/CSS/URL, atoms/refcounts и platform FFI; quotas/URL policy остаются у потребителя. |
| crc32fast (1) | github:srijs/rust-crc32fast | Официальный workflow: checksum SIMD dispatch и unsafe slices; CRC не является аутентификацией. |
| darling (3) | TedDriggs (6324) | Автор Darling: Rust attribute parsing и production generated code во всех трёх crates; не только запуск build tool. |
| time (4) | github:jhpratt/deranged, jhpratt (15682), github:time-rs/time | Сопровождающий time: диапазоны, overflow, parsing/formatting и generated date macros, включая вспомогательные deranged/powerfmt. |
| derive-more (2) | JelteF (3797) | Release maintainer derive_more: token parsing и production-generated conversions/operators/error impls; invariants типов отдельно. |
| objc2 (11) | madsmtm (36629) | Сопровождающий objc2: ABI, retain/release, exceptions, lifetime и thread contracts; наличие location API не разрешает его использование. |
| enumflags (2) | meithecatte (38769) | Автор enumflags2: generated bit/discriminant validity и unsafe conversions; флаги не являются проверкой permissions. |
| generic-array (1) | novacrazy (5704) | Release maintainer generic-array: production unsafe layout, initialization/drop и type-level lengths, используемые RustCrypto; не автоматическое наследование RustCrypto trust. |
| rust-random (3) | josephlr (39279), github:rust-random/getrandom, github:rust-random/rand | Команда rust-random: OS entropy failures, initialization и FFI backends; custom RNG и криптопротокол потребителя остаются отдельными обязательствами. |
| icu4x (18) | robertbastian (166196), sffc (128408) | Команда Unicode ICU4X: недоверенный Unicode/locale input, zero-copy lifetimes, generated tables и derive; не заменяет политику IDNA. |
| tauri (20) | tauri-bot (95389) | Команда production UI/IPC boundary: runtime, webview, build/macros, menu/tray и поддерживаемые GTK forks; доверие включает генерируемый код и FFI, но не разрешает обход CSP/IPC/sandbox. |
| jiff (4) | github:BurntSushi/jiff | Официальный workflow BurntSushi: production date/time parsing, generated timezone data и bounds; системное время не получает разрешение на выход. |
| jni (3) | rib (68864) | Сопровождающий jni-rs: raw JNI ABI и version-selection macros; JVM validity и unsafe caller contracts обязательны. |
| wasm-bindgen (7) | github:wasm-bindgen/wasm-bindgen | Официальный release workflow: Wasm/JS ABI, lifetimes и generated glue; права браузера и приложение проверяются отдельно. |
| rusqlite (2) | gwenn (5062) | Сопровождающий rusqlite: statements/blobs/backups, hostile DB input и native build/link helpers; SQLCipher/OpenSSL dependencies и forks проверяются отдельно. |
| rust-mobile (2) | MarijnS95 (110371) | Официальные NDK bindings: native ABI/ownership/thread contracts; Android capabilities остаются отдельной политикой. |
| nix (2) | SteveLauC (146703), asomers (6094) | Команда Nix: Unix ABI, descriptors, errors и lifetimes; доверие не разрешает системные вызовы в обход sandbox. |
| num-enum (2) | illicitonion (14455) | Автор num_enum: discriminant/range/default handling и generated unchecked APIs с явными caller preconditions. |
| openssl (2) | alex (163) | Alex Gaynor, registry account alex: официальный rust-openssl, FFI/build/link и hostile crypto inputs; native OpenSSL и TLS policy отдельно. |
| phf (10) | JohnTitor (51017) | JohnTitor подтверждён автором официального release commit: production lookup tables, escaping и macro/codegen contracts; PHF не является crypto hash. |
| proc-macro-crate (3) | bkchr (6134) | Автор проекта: Cargo manifest/renamed-dependency lookup и generated crate paths в доверенной build environment. |
| schemars (4) | GREsau (55662) | Автор Schemars: schema/derive generation, recursion и escaping; JSON Schema generation не является runtime validation. |
| apple-security (3) | kornelski (988) | Сопровождающий rust-security-framework: certificate/keychain FFI, ownership, lengths и errors; права Keychain не расширяются. |
| serde-with (2) | github:jonasbb/serde_with | Официальный workflow: hostile serialized values/ranges и derive-generated adapters; сериализация секретов этим не разрешается. |
| smallvec (1) | github:smallvec/smallvec | Официальный workflow smallvec: production inline/heap storage, capacity, initialization, panic/drop и aliasing; это отдельное release trust, не аудит soundness. |
| synstructure (1) | mystor (1947) | Автор проекта: Rust type/token parsing и generated impl/trait/lifetime bindings для production derive consumers. |
| target-lexicon (1) | fitzgen (696) | Сопровождающий Bytecode Alliance/Wasmtime: target parsing/layout и build-time generation; отдельное publisher trust, не импортированный аудит. |
| typenum (1) | paholg (243) | Автор typenum: production type-level arithmetic/length relations и generated operator tables; независимое математическое доказательство не заявляется. |
| winapi (1) | retep998 (63) | retep998: исторические raw Windows ABI bindings; отдельный third-party проект, не Microsoft/kennykerr. |
| zbus (7) | zeenix (6423) | Руководитель zbus: hostile D-Bus serialization/names/messages и generated macros; IPC authorization и запрет D-Bus в sandbox сохраняются. |
| google-zerocopy (2) | github:google/zerocopy | Официальный Google publishing repository: hostile byte-layout/alignment/validity и derive contracts; не наследование Google imports или чужого local trust. |

Microsoft windows/windows-sys/windows-targets уже покрыты предыдущими решениями
и в baseline не присутствуют. Сторонние winapi и wravery/WebView2 не объявлены
Microsoft-публикациями. Старые GNU winapi import-library packages без registry
publisher identity остались открыты: 27 строк Rust не равны проверке native
архивов. Для portable-atomic workflow SHA отличается от archive VCS SHA;
расхождение записано, новая запись доверия не добавлялась. После product trust
locked-остаток — **100**, закрыты 192 пробела (включая две ранее несохранявшиеся
записи при других непокрытых версиях того же имени).

### Собственные проверки и итог

Добавлено **11 полных production source audits**, все с явным
**«проверено агентом, не человеком»**, SHA-256 архива, перечнем прочитанных файлов
и ограничениями: android_system_properties 0.1.6, cesu8 1.1.0, dirs 7.0.0,
dtoa-short 0.3.5, endi 1.1.1, idna_adapter 1.2.2, new_debug_unreachable 1.0.6,
secrecy 0.10.3, static_vcruntime 3.0.0, tower-layer 0.3.3, tower-service 0.3.3.
Прочитанные файлы побайтно сверены с членами проверенных архивов. Рассмотрены
все production-модули, manifests, unsafe/FFI контракты и optional source code;
непроверенные platform/feature executions не заявляются.

15 upstream unit/integration tests прошли; дополнительно проверены I/O errors
и короткие buffers, secret redaction/zeroize/Drop, округление/carry/ошибки writer,
100000 generated f32/f64 bit patterns, roundtrip каждого Unicode scalar и все
65536 двухбайтовых входов CESU-8. dtoa-short отдельно пересобран в release без
debug assertions. Safe вызов debug_unreachable! в release отвергнут rustc E0133;
сам unreachable_unchecked не исполнялся. Synthetic probes сохранены рядом с
отчётом, команды нормализованы без реальных пользовательских путей. Нулевые
unit suites не считаются runtime coverage; Miri/sanitizers/полная OS матрица
и выполнение optional serde/Android backend не заявляются.

Ограничения важны для потребителей: CESU-8 decoder fast path допускает валидный
UTF-8/NUL и не является strict canonical validator; secrecy не гарантирует
очистку compiler/caller copies, swap или abort; static_vcruntime намеренно меняет
CRT linker arguments; unsafe macro требует доказательства недостижимости.
Для dirs-sys audit не выдан: просмотр обнаружил возможные slice panics на
коротких XDG key/value; это source finding без Unix runtime repro на Windows.
Чтение ordered-stream не завершено и аудитом не названо.

Итог — **292 → 100 → 89 пробелов**, закрыто **203**. Финальный
node scripts/vet-dependencies.mjs desktop выполнен с locked imports, входы
неизменны, результат честно красный. cargo-deny 0.22.0 desktop зелёный.
Полный остаток с fanout, объёмом и причиной отложения — в JSON. Среди
приоритетов siphasher, version-compare, system-deps, GNU winapi import libraries
и errno. Native SQLCipher/libtomcrypt distribution не сертифицирован по одним
652 строкам Rust helper.

Workspace tests, clippy и leak tests запускались, но остановились до тестов на
отсутствующем perl для vendored OpenSSL; extension npm test остановился на
отсутствующем локальном tsc. Зелёных результатов для этих запусков нет.
Все девять tracked Cargo.lock, desktop config.toml и stores остальных графов
неизменны. Exemptions не добавлены, safe-to-deploy не ослаблен, M6/CI gate
остаются открытыми.

## Четвёртый проход от 2791eb5 — 2026-11-26

Ветка `agent/vet-desktop-4`, только desktop. Исходные **89 пробелов**
воспроизведены repository wrapper с locked imports. Добавлены **77 решений
доверия 60 identities**, **два собственных аудита** и **одно поштучное
deployment exemption**: **89 → 10 → 9**. Все новые записи помечены
**«Проверено агентом, не человеком»**, содержат SHA-256 архива, прочитанный
материал и границы проверки. Это промежуточный результат, не закрытие M6.

[Отчёт четвёртого прохода](../../supply-chain/desktop/review-2026-11-26-desktop-4.json)
сохраняет registry fields/SHA предыдущих exact-version ответов, проверку
архивов против неизменного desktop lockfile и cached sparse index, upstream
URL/SHA, решения для каждой версии, checkpoints/receipts и полный остаток.
89 исходных ответов crates.io заново не скачивались; их свежесть не заявляется.
`regenerate imports` независимо обновил publisher snapshots: identity и UTC-день
каждой из 77 записей сверены с новым `imports.lock`. Изменились только эти
snapshots; все шесть source pins и импортированные audit sections сохранены.
Новые запросы кешировались в `target/desktop4/`; последовательные обращения,
Retry-After/exponential backoff для 429/5xx, предел паузы 45 секунд.

### Доверие публикаторам и собственные аудиты

Каждая запись доверия ограничена именем пакета и историческим UTC-днём
`[start,end)`, с точной версией текущего lockfile в notes. Это отдельное
product-maintainer trust для `safe-to-deploy`, включая unsafe, недоверенный ввод,
FFI и генерируемый production-код, **не построчный аудит этих 77 пакетов**.
Сверены original manifest с immutable upstream (у widestring и dlopen2 различаются
только LF/CRLF), авторы/repository и начальный README excerpt до 160 символов,
где README упакован. Отсутствующий README не объявляется прочитанным.
Для неоднозначных identities получены official release commits: например,
Manishearth/displaydoc, hds/tracing, dralley/quick-xml, folkertdev/zlib-rs,
pczarn/bit-vec, jplatte/axum-core, 197g/png, madsmtm/rust-windowing,
adamreichold/rust-scraper. Author, committer, message, URL и SHA ответа — в отчёте.
Имя crates.io account не заменялось догадкой из названия репозитория.

Собственные аудиты выданы только после чтения production-кода:

- `version-compare 0.2.1`: оба manifests, все шесть production-модулей;
  повторяющиеся rustdoc/test bodies прочитаны выборочно, не выданы за полный
  независимый аудит fixtures. Проверены UTF-8 boundaries, checked integer parsing,
  GNU ordering, iterator exhaustion и bounds. Это best-effort comparison,
  не SemVer и не валидатор минимальной безопасной версии. `set_manifest` не
  перепарсивает parts; длинные численные строки могут требовать сверхлинейного
  CPU из-за повторного `nth`. В desktop потребитель — build-time `system-deps`
  с доверенными native-library metadata; произвольный удалённый ввод требует
  отдельного ограничения длины. Прошли **30 upstream tests** и synthetic
  probe с BMP Unicode scalars, overflow и bounds.
- `foreign-types-macros 0.2.4`: оба manifests и все три полных source modules.
  Рассмотрены generated ownership/NonNull/Drop/Clone/ToOwned/deref, явные
  unsafe Send/Sync assertions и оба варианта `std`. Безопасность конкретной
  foreign declaration зависит от её unsafe CType/drop/clone/lifetime contracts.
  Synthetic integration test с `foreign-types 0.5.0` проверяет разные allocations
  clone, mutable borrow, borrowed ToOwned и ровно один Drop каждой allocation.

Исходники этих аудитов сверены с проверенными архивами. Стенд
[review-tests-2026-11-26-desktop-4.mjs](../../supply-chain/desktop/review-tests-2026-11-26-desktop-4.mjs)
воспроизводит проверки из cached sources; его файлы, executables и отдельный
synthetic Cargo.lock создаются только в ignored `target/desktop4/`.
Miri, sanitizers, timing и полная OS/feature matrix не заявляются.

### portable-atomic 1.15.0: объяснение двух SHA

Архив SHA-256
`05c8b63e8d9609db387f0324918f81d68fe27748f084ef092fb35954d0539a85`.
Тег `v1.15.0` разрешается в
[`e4595528211f1d53b7f4d93e528ef84b491fc871`](https://github.com/taiki-e/portable-atomic/commit/e4595528211f1d53b7f4d93e528ef84b491fc871),
то есть ровно archive `.cargo_vcs_info.json.git.sha1`. Его непосредственный
родитель — registry trusted-publishing SHA
`cb58081f88cd02681dbb32482acec7ae198850d5`. Diff — только `Cargo.toml`
(`1.14.0` → `1.15.0`) и `CHANGELOG.md`; production-код между ними неизменен.

Причина подтверждается прочитанным `.github/workflows/release.yml` и его
[закреплённым reusable workflow](https://github.com/taiki-e/github-actions/blob/e6a1170cbd07eb898017958967912976fce18f2d/.github/workflows/rust-release.yml):
он запускается на родителе, затем создаёт release commit/tag и выполняет
`cargo publish` из нового commit. OIDC SHA описывает запуск workflow, а VCS SHA —
упакованный release commit; совпадение этих двух SHA здесь не требуется.

Все **66 опубликованных негenerated-файлов** побайтно совпали с git tree тега,
включая `Cargo.toml.orig` против upstream `Cargo.toml`. Отдельно перечислены
три Cargo-generated файла: normalized `Cargo.toml`, packaged `Cargo.lock`
и `.cargo_vcs_info.json`; они не выдаются за побайтовые файлы git tree.
Файл за файлом SHA и исключения сохранены в отчёте. После объяснения provenance
добавлено однодневное доверие официальному `github:taiki-e/portable-atomic`
для production atomic/assembly/memory-ordering scope. Независимый полный
аудит atomics или доказательство soundness этим не заявляется.

### Native-архивы

`webview2-com-sys 0.39.1` опубликован **wravery (131438)**, а не Microsoft.
Все **девять** DLL/LIB для arm64/x64/x86 совпали побайтно с official
`wravery/webview2-rs` на archive commit
`edc2caf886175ccaebe86078c9cfe1ae2a187328`, а затем — с
**Microsoft.Web.WebView2 1.0.3800.47** из official NuGet feed.
На [странице NuGet](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.3800.47)
проверены reserved prefix и owner Microsoft; прочитан nuspec с author Microsoft.
SHA-256 `.nupkg`:
`56c9f26bdd07916a2d1949fb58a5c7e434dfa1173577dca879206050c4e718db`.
Пути, размеры и SHA всех binaries — в отчёте.
**Инструкции бинарей построчно не проверены**, воспроизводимая сборка и
криптографическая проверка NuGet signature chain не выполнялись; наличие
`.signature.p7s` само по себе не объявляется проверенной подписью.

Две DLL test fixtures `libloading` также совпали с immutable upstream;
`system-deps/src/tests/lib/libteststatic.a` — пустой test fixture, не настоящая
библиотека. Они не исполнялись и не линкуются в production. Уже покрытые до
baseline official Microsoft windows/windows-targets решения не расширялись;
новый построчный аудит их native binaries не заявляется.
Оба исторических GNU winapi packages по-прежнему открыты: registry identity
отсутствует, **1387 + 1416** import archives не привязаны этим проходом к
подтверждённой official distribution. Они не объявлены публикациями Microsoft.

### dirs-sys 0.5.0: достижимость и исключение

Архив SHA-256
`e01a3366d27ee9890022452ee61b2b63a67e6f13f58900b651ff5665f0bb1fab`.
Прочитаны оба manifests, полный `src/lib.rs` и `src/xdg_user_dirs.rs`.
Две синтетические строки воспроизводят slice panic в опубликованном parser:

```text
XDG_DIR="/safe"
XDG_DOWNLOAD_DIR="
```

У первого key prefix/suffix перекрываются: `key[4..key.len()-4]` получает
`4..3`. Во втором value состоит из одного double quote: `value[1..len-1]`
получает `1..0`. Это deterministic DoS/panic, не утверждение о memory corruption.
Оба `catch_unwind` probes прошли именно воспроизведением ожидаемой паники.
На Windows заменён **только** Unix `OsStringExt` import на ASCII-only shim;
parser/slices сохранены. Native Unix runtime, реальный HOME и конфигурация
пользователя не использовались.

Проверено полное обратное дерево `dirs-sys` для `--target all`:
`dirs 7.0.0` → Tauri, tauri-build и Wry. Дефект **недостижим в текущем
проверенном deployment**, а не признан безопасным:

1. В `app/` и `crates/` нет прямых вызовов dirs/dirs-sys или Tauri PathResolver.
   Конфигурация ресурсов/окон не содержит `$DOWNLOAD` и подобных user-dir paths.
   Build и обычная инициализация используют home/base directories без XDG parser.
2. Tauri path plugin имеет `resolve_directory`, но единственная capability
   `main` содержит `permissions: []`: разрешение
   `core:path:allow-resolve-directory` не выдано.
3. Обнаружен дополнительный Linux-путь Wry download callback. В Tauri
   `from_config` поле `download_handler=None`, NymWrap не устанавливает
   `on_download`; `tauri-runtime-wry` передаёт callbacks только для `Some`,
   а Wry регистрирует обработчик только при наличии callback. Поэтому до
   `dirs::download_dir()` этот путь сейчас не доходит.
4. На Windows используется Known Folder API, на macOS этот XDG parser
   не компилируется. Это дополнительное разделение платформ, не замена Linux-анализу.

Hashes исходников и точные просмотренные участки Tauri/Wry, application config
и main сохранены в отчёте. Добавлено **одно exemption только для 0.5.0** с этим
обоснованием и ссылкой сюда. Safe-to-deploy audit не выдан. Решение обязательно
пересмотреть до изменения capabilities, native path calls, download hooks,
resource/window config или указанных версий зависимостей.

### Требуют обновления

По завершённому анализу этого прохода обязательная доступная версия для
обновления **не установлена**. Проверен новый
[`dirs-sys` registry response](https://crates.io/api/v1/crates/dirs-sys):
latest/max остаётся **0.5.0**, исправленной опубликованной версии нет.
Нельзя предлагать выдуманную `0.5.1`. При появлении исправления либо достижимости
parser требуется отдельная задача на обновление/исправление с length checks
до обоих slices; Cargo.lock здесь сохранён. Для девяти незавершённых проверок
вопрос обязательных обновлений остаётся открытым.

### Остаток и проверки

Осталось **9 пробелов safe-to-deploy**: `dbus-secret-service 4.1.0`,
`ordered-stream 0.2.0`, `recvmsg 1.0.0`, оба `serialize-to-javascript* 0.1.2`,
`sqlcipher-src 420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2`,
`vswhom 0.1.0` и оба `winapi-*-pc-windows-gnu 0.4.0`.
В JSON у каждой версии сохранены точная причина и оставшаяся работа.
Неполные чтения, отсутствие repository/publisher и нерешённые template/native
вопросы не выданы за аудиты. Историческая source-проблема `ordered-stream`
из root-прохода здесь независимо не воспроизведена и не сертифицирована.

Финальный `node scripts/vet-dependencies.mjs desktop` с locked imports:
**failed, 9 gaps**, входы неизменны. Дополнительно unchanged repository policy
`successfulVet` отвергает **любое exemption**, включая новое dirs-sys: даже
закрытие оставшихся девяти само по себе не сделает gate зелёным. Этот отказ
не обходится изменением wrapper, criteria или импортов.
Desktop `cargo-deny 0.22.0` — **exit 0**, advisories/bans/licenses/sources ok,
при существующих duplicate/unmatched-exception warnings. Проверки стенда:
30 upstream + 1 version probe + 2 panic reproductions + 1 macro integration.
Workspace tests/clippy/leak tests и extension tests в этом проходе **не
запускались**: пользователь ограничил проверку metadata/docs задачи vet и deny.
Прошлые неудачные запуски не объявляются новыми зелёными результатами.
Все tracked Cargo.lock, версии, production-код и stores других графов сохранены.
CI не запускался; итог неполный, M6/gate открыты.
