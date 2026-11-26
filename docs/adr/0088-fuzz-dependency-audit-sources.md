# Источники аудитов и критерий для отдельного fuzz-графа

Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только для
`fuzz/Cargo.toml` и `supply-chain/fuzz/`. Root, netd и desktop не меняются.
Версии зависимостей, Cargo.lock и закреплённый cargo-vet 0.10.4 сохраняются.
`imports.lock` обновляется намеренно для новых источников, как предусмотрено
ADR 0073; это не обновление зависимостей.

## Прямое доверие к опубликованным проверкам

Прежние Mozilla и Google остаются на прежних immutable commits. Добавляем:

- **Bytecode Alliance**, набор команды Wasmtime, commit
  `1499ce8728f5f1b7fae0db88e1417991b01cfc13`.
  [Исходный набор](https://github.com/bytecodealliance/wasmtime/blob/1499ce8728f5f1b7fae0db88e1417991b01cfc13/supply-chain/audits.toml).
  Команда разрабатывает Rust/WebAssembly runtime и публикует именованные
  проверки его зависимостей, включая инфраструктуру fuzz. Доверяем этим
  конкретным проверкам с их исходными criteria и замечаниями.
- **ISRG / Divvi Up**, набор команды libprio-rs, commit
  `7549f3c7dffe96d3a6e6fb214007911cdec3e8e6`.
  [Исходный набор](https://github.com/divviup/libprio-rs/blob/7549f3c7dffe96d3a6e6fb214007911cdec3e8e6/supply-chain/audits.toml).
  Разработчики криптографической агрегации для приватности публикуют
  персонально атрибутированные проверки криптографии и Rust-инфраструктуры.
  Это релевантный опыт для данного графа; доверие ограничено записями набора.
- **Zcash**, агрегированный набор Rust ecosystem, commit
  `ce132d7abdd52f2b3b0d55ed5dc9f152331535c2`.
  [Исходный набор](https://github.com/zcash/rust-ecosystem/blob/ce132d7abdd52f2b3b0d55ed5dc9f152331535c2/supply-chain/audits.toml).
  Проверены sources.txt и workflow агрегации той же ревизии: источники —
  `zcash/librustzcash`, `zcash/wallet` и `zcash/zcash`. Явно доверяем
  опубликованным проверкам этих трёх команд, работающих над криптографическим
  кошельком и протоколом, с сохранением авторства исходных записей.

Наборы Bytecode Alliance и ISRG найдены в официальном
[реестре cargo-vet](https://github.com/mozilla/cargo-vet/blob/main/registry.toml).
Ссылка Zcash в реестре устарела: фактический путь подтверждён в официальном
репозитории, затем закреплён commit. Чужие imports и exemptions не наследуются,
custom criteria не отображаются на более сильные локальные. В первой партии
локальных wildcard/trusted-publisher записей не добавлялось. Это ограниченное
доверие к внешним аудитам, а не гарантия отсутствия ошибок.

## Область safe-to-run

Отдельный fuzz workspace — локальный тестовый инструмент с синтетическими
данными, не поставляемый пользователю продукт. Для его first-party crates
требуется `safe-to-run`: отсутствие неожиданных действий при сборке и
контролируемом запуске (чужие файлы, установка ПО, внешние подключения,
злоупотребление ресурсами). Семантика соответствует официальным
[criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html) и
[policies](https://mozilla.github.io/cargo-vet/specifying-policies.html).
Этот критерий не заявляет безопасность production-парсеров на произвольных
враждебных данных. Отдельные stores продуктов продолжают требовать прежний
критерий. Локальные аудиты агента здесь записываются только с `safe-to-run`,
явным авторством, точной версией либо delta, хешами и описанием просмотренного.
Непросмотренные зависимости остаются пробелами; массовых exemptions нет.

## Результат первой партии

Замер на baseline `94e6bf9`: 248 пробелов. Три imports при прежнем критерии
оставляют 219; явная политика fuzz `safe-to-run` — 206. После 16 новых аудитов
агента (10 полных, 6 delta) осталось **193**. У thiserror/thiserror-impl
проверена только delta `2.0.18 -> 2.0.21`; базовое покрытие отсутствует,
поэтому эти два крейта остаются в списке. Обе delta crossbeam-utils вместе
с импортами закрывают один пробел. Новых exemptions нет.

Это намеренно промежуточная поставка по пункту 6 задачи 9: непроверенный код
не объявляется безопасным ради зелёного gate. Полный список остатка, критерии,
четыре набора хешей входов и локальное происхождение измерений сохранены в
[отчёте](../../supply-chain/fuzz/review-2026-11-26.json).
Финальная команда первой партии из dependency-audits запускалась без обновления
imports, `node scripts/vet-dependencies.mjs fuzz`; результат был красным с
193 пробелами. CI и M6 не закрывались. Проверки и ограничения перечислены в
[IMPLEMENTATION](../IMPLEMENTATION.md).

## Доверенные публикаторы

Продолжение от `a120a5f`, 2026-11-26. Доверие ограничено `safe-to-run`,
конкретными пакетами fuzz и историческими периодами публикации `[start, end)`.
Последний день публикации включён через `end` следующего дня; будущие релизы
не охвачены. Это механизм
[trusted entries](https://mozilla.github.io/cargo-vet/trusting-publishers.html),
а не собственный аудит исходников и не `safe-to-deploy` для продуктов.

Перед каждой записью проверены `published_by.id`, login, `created_at`,
отсутствие yank и checksum **точной locked-версии** в
`https://crates.io/api/v1/crates/<crate>`. SHA-256 каждого локального `.crate`
сверен одновременно с API и sparse registry index. Полный список версий,
публикаторов, дат, URL и хешей ответов реестра находится в
[отдельном отчёте продолжения](../../supply-chain/fuzz/review-2026-11-26-continuation.json).
Имя нынешнего owner не используется как доказательство прежней публикации.

Список ниже предназначен для повторного рассмотрения другими графами; доверие
в их stores этим решением **не добавляется**. Число закрытых пробелов измерено
последовательными прогонами fuzz; это число пар crate/version, не число записей.

| Публикатор (crates.io user-id) | Основание ограниченного доверия | Закрыто |
|---|---|---:|
| [dtolnay](https://github.com/dtolnay) (3618) | Serde, syn, proc-macro2, quote, thiserror; широко используемые макросы и сериализация | 13 |
| [alexcrichton](https://github.com/alexcrichton) (1) | Многолетняя работа над Rust/Cargo, Wasmtime, native build и WASI | 2 |
| [tarcieri](https://github.com/RustCrypto#project-leads) (267) | Руководитель RustCrypto; семейства AEAD, шифров, password hashing и кодировок | 9 |
| [newpavlov](https://github.com/RustCrypto#project-leads) (5059) | Руководитель RustCrypto; семейства хешей, шифров и KDF | 3 |
| [taiki-e](https://github.com/taiki-e) (33035) | pin-project, portable-atomic, futures/smol и Rust tooling | 8 |
| [seanmonstar](https://github.com/seanmonstar) (359) | Hyper, HTTP/body, Tokio/Tower | 8 |
| [Darksonn](https://github.com/Darksonn) (6741) | Alice Ryhl, Tokio; релизы Tokio, bytes, slab и axum | 5 |
| [BurntSushi](https://github.com/BurntSushi) (189) | regex, regex-automata, memchr, aho-corasick и ripgrep | 5 |
| [cuviper](https://github.com/cuviper) (539) | Команды Rust compiler/library/release; rayon, rust-num, indexmap, autocfg | 6 |
| [kennykerr](https://github.com/microsoft/windows-rs) (64539) | Microsoft windows-rs; семейства Windows bindings и target libraries | 22 |
| [epage](https://github.com/epage) (6743) | Cargo/clap, TOML, winnow; инфраструктура CLI и конфигурации | 5 |
| [Amanieu](https://github.com/Amanieu) (2915) | parking_lot, lock_api, hashbrown и синхронизация | 3 |
| [sunfishcode](https://github.com/sunfishcode) (6825) | rustix, linux-raw-sys, cap-std и WASI | 2 |
| [fitzgen](https://github.com/fitzgen) (696) | Wasmtime, arbitrary, libfuzzer-sys и bumpalo | 2 |
| [rust-lang-owner](https://github.com/rust-lang/jobserver-rs) (55123) | Общая учётная запись Rust для релизов инфраструктуры; здесь только подтверждённый jobserver | 1 |
| [Thomasdezeeuw](https://github.com/tokio-rs/mio) (6025) | Мейнтейнер Tokio Mio; широко используемые Mio/socket2 | 2 |

Эти 16 учётных записей закрыли **96**, остаток **97**.

Отдельно обработаны публикации, у которых API возвращает `published_by = null`
и `trustpub_data.provider = "github"`. Им не приписывался вымышленный user-id.
Использован `trusted-publisher = "github:<repository>"`, поддерживаемый
закреплённым [cargo-vet 0.10.4](https://github.com/mozilla/cargo-vet/blob/a9bde85910409be3d2d61e6f6ff6ba7a521f0412/src/format.rs).
Проверены точные repository, run_id, SHA и дата из реестра; run_id/SHA сохранены
как метаданные публикации, без заявления об отдельном аудите workflow.
Здесь доверяем выпуску официальных репозиториев уже выбранных Rust/RustCrypto
мейнтейнеров и taiki-e, только для перечисленных пакетов и исторических дат.

| Trusted Publishing identity | Пакеты | Закрыто |
|---|---|---:|
| [github:rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) | cc, find-msvc-tools | 2 |
| [github:rust-lang/flate2-rs](https://github.com/rust-lang/flate2-rs) | flate2 | 1 |
| [github:rust-lang/hashbrown](https://github.com/rust-lang/hashbrown) | hashbrown | 1 |
| [github:rust-lang/libc](https://github.com/rust-lang/libc) | libc | 1 |
| [github:rust-lang/log](https://github.com/rust-lang/log) | log | 1 |
| [github:RustCrypto/hashes](https://github.com/RustCrypto/hashes) | sha1 | 1 |
| [github:RustCrypto/utils](https://github.com/RustCrypto/utils) | zeroize, zeroize_derive | 2 |
| [github:taiki-e/pin-project-lite](https://github.com/taiki-e/pin-project-lite) | pin-project-lite | 1 |

Эти восемь identities закрыли ещё **10**, остаток **87**. В сумме доверие к
публикаторам закрыло **106**. Без подтверждённого uploader/официального workflow
нового доверия нет; прочие учётные записи и организации не разрешаются целиком.

## Дополнительный import и вторая партия исходных проверок

Добавлен **Embark Studios**, команда cargo-deny и Rust tooling, из официального
реестра cargo-vet. Прямо доверяем атрибутированным проверкам этого набора с их
исходными criteria. Закреплён commit `732513edfd9172f4eda358b2d0cefc6cad1585ee`:
[audits.toml](https://github.com/EmbarkStudios/rust-ecosystem/blob/732513edfd9172f4eda358b2d0cefc6cad1585ee/audits.toml).
SHA-256 источника записан в отчёте. Чужие imports/exemptions не наследуются,
criteria не усиливаются. Непосредственный результат — **87 → 87**: набор
содержит исторические проверки, но не закрывает оставшиеся locked-версии.
Actix и Fermyon также просмотрены: в первом только отсутствующие здесь Actix
семейства, во втором небольшой исторический Wasmtime/plotting набор; не добавлены.

Далее выполнены восемь полных `safe-to-run` проверок агентом: `version_check`,
`bitflags`, `wasm-bindgen-shared`, `errno`, `phf_shared`, `phf_generator`,
`proc-macro-crate`, `memoffset`. Каждая содержит SHA архива и честное авторство.
Начали с широко используемых узлов: `version_check` имеет 36 транзитивных
потребителей, bitflags — 32, wasm-bindgen-shared — 28, errno — 25.
Инвентаризация typenum (36) не закончена; он не сертифицирован. Остальные
крупные библиотеки, генераторы и встроенные native исходники также не получили
аудит по одному лишь поиску подозрительных API. Объём остатка требует отдельной
партии содержательного просмотра; неизвестное покрытие не заменялось доверием
к менее знакомым авторам или exemptions.

Результат исходных проверок — **87 → 79**. Новых exemptions нет. Финальный
locked gate остаётся красным с **79 пробелами**; полный остаток и все промежуточные
замеры сохранены в отчёте продолжения. M6 и CI dependency-audits fuzz не закрыты.

## Завершение fuzz-графа от 4691e27

2026-11-26: **79 → 0 пробелов**; накопительно **248 → 0**. Изменены только
`supply-chain/fuzz/audits.toml`, publisher-метаданные его `imports.lock`, новый
отчёт завершения, этот ADR и существующий раздел fuzz в IMPLEMENTATION. Шесть imports остаются
на тех же immutable commits; `config.toml`, критерии, версии и все Cargo.lock
не менялись. Новых imports, wildcard audits или exemptions нет.

Сначала повторно проверены точные locked-публикации: `published_by` либо
`trustpub_data`, UTC-дата, отсутствие yank, SHA-256 архива одновременно по API
crates.io и sparse index. Просматриваемые Rust-файлы и manifests из Cargo cache
побайтно сопоставлены с архивами. Для каждого из 64 доверяемых релизов исходный
Cargo.toml дополнительно загружен из официального репозитория по VCS commit
архива и совпал с Cargo.toml.orig (у widestring различается только CRLF/LF).
У всех 11 workflow-публикаций repository/SHA из реестра также совпали с
официальным репозиторием и VCS commit архива; run_id сохранён как свидетельство
публикации. Это проверка происхождения, не независимый аудит workflow или всего
кода опубликованного архива на совпадение с Git.

Ниже — **новое прямое доверие** для fuzz: 29 пользовательских учётных записей
(53 locked-публикации) и семь GitHub identities (11 публикаций). Каждая запись
ограничена одним пакетом, `safe-to-run` и одним историческим днём `[start, end)`.
Даже разные годы релизов security-framework не объединены в широкое окно.
Доверие не выводится автоматически из текущего ownership, подписи workflow,
хеша или присутствия пакета в реестре: основание принятия ответственности
публикатора приведено отдельно; это эвристика с остаточным риском компрометации
мейнтейнера. Пользовательские и workflow identities не взаимозаменяются.

| Публикатор / identity | Locked-публикаций | Основание ограниченного доверия |
|---|---:|---|
| [paholg](https://github.com/paholg) (243) | 1 | Paho Lurie-Gregg maintains typenum, the type-level arithmetic library used by generic-array. Accept the verified release from its upstream maintainer; this is publisher trust, not completion of the earlier deferred source review. |
| [github:wasm-bindgen/wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) | 4 | Official wasm-bindgen repository release identity for its Rust/JavaScript bindings and procedural generators. Trust this project release rather than attributing the workflow to historical human uploader alexcrichton. |
| [dvdhrm](https://github.com/dvdhrm) (12177) | 1 | David Rheinsberg maintains r-efi, the Rust definitions of the UEFI reference specification. Trust his verified release of this platform binding package. |
| [github:smallvec/smallvec](https://github.com/smallvec/smallvec) | 1 | Official smallvec repository release identity for the small-vector implementation used by Rust/Servo infrastructure. Accept project release responsibility for its unsafe storage implementation; no local source certification is claimed. |
| [jedisct1](https://github.com/jedisct1) (468) | 1 | Frank Denis maintains the SipHash implementation in jedisct1/rust-siphash. Trust this verified release from the cryptographic-library maintainer; this is not a local cryptographic review. |
| [zeenix](https://github.com/zeenix) (6423) | 8 | Zeeshan Ali Khan maintains zbus and zvariant and publishes smol synchronization/channel packages. Trust the verified releases of these specific D-Bus and async infrastructure packages. |
| [notgull](https://github.com/notgull) (69526) | 3 | John Nunley maintains smol async infrastructure. Trust his verified concurrent-queue, futures-lite and piper releases from the smol-rs repositories. |
| [dralley](https://github.com/dralley) (129150) | 1 | Daniel Alley maintains the quick-xml parser in tafia/quick-xml. Accept responsibility of the verified upstream release publisher for this local fuzz dependency, without claiming production XML parser security. |
| [github:google/zerocopy](https://github.com/google/zerocopy) | 2 | Official Google zerocopy repository release identity for the layout/conversion library and its derive macros. Trust project release responsibility; unsafe correctness is not locally audited. |
| [mkroening](https://github.com/mkroening) (91569) | 1 | Martin Kroening publishes the Hermit Rust platform ABI from hermit-os/hermit-rs. Trust this verified release of the platform interface maintained with the Hermit project. |
| [alex](https://github.com/alex) (163) | 2 | Alex Gaynor publishes the rust-openssl bindings from rust-openssl/rust-openssl. Trust these verified releases of OpenSSL binding/build infrastructure; system/native OpenSSL remains part of the trusted toolchain. |
| [JohnTitor](https://github.com/JohnTitor) (51017) | 3 | Yuki Okushi publishes Rust PHF lookup tables and generators. The existing pinned Mozilla audit set also explicitly trusts user-id 51017 for these same packages; accept direct, narrower local trust after checking the actual locked publications. |
| [github:rust-random/rand](https://github.com/rust-random/rand) | 1 | Official Rust Random rand repository release identity. Trust this project release for local test random generation, without claiming an independent RNG or cryptographic audit. |
| [hds](https://github.com/hds) (172786) | 2 | Hayden Stainsby publishes tracing and tracing-attributes from the Tokio tracing project. Trust these verified instrumentation and procedural-macro releases. |
| [jplatte](https://github.com/jplatte) (6913) | 1 | Jonas Platte publishes axum-core from the Tokio axum repository. Trust this verified release of its HTTP request/response abstraction layer. |
| [diwic](https://github.com/diwic) (429) | 1 | The diwic account maintains dbus-rs and publishes libdbus-sys. Trust this verified release of the native D-Bus binding/build package; native libdbus/toolchain is not independently audited here. |
| [SteveLauC](https://github.com/SteveLauC) (146703) | 1 | SteveLauC published the exact nix 0.29.0 release from nix-rust/nix. Trust this historical release of the project Unix API bindings; current ownership is not used as publication evidence. |
| [kornelski](https://github.com/kornelski) (988) | 3 | Kornel maintains rust-security-framework and publishes the Apple Security framework wrappers and bindings. Trust only the verified historical releases of these named packages. |
| [github:LucaCappelletti94/sqlcipher-src](https://github.com/LucaCappelletti94/sqlcipher-src) | 1 | Official sqlcipher-src repository release identity. Explicitly accept this maintainer's release responsibility for the SQLCipher/libtomcrypt source bundle described by its pinned README and manifest. This is new, package-specific trust in the bundler, not an independent review of bundled C, cryptography or release workflow. |
| [SimonSapin](https://github.com/SimonSapin) (7) | 3 | Simon Sapin publishes Servo string interning/code generation and html5ever. Trust these verified releases from their Servo repositories; this does not certify production HTML parser behavior. |
| [VoidStarKat](https://github.com/VoidStarKat) (3416) | 1 | Kathryn Long maintains widestring-rs and publishes the UTF-16/UTF-32 FFI string library. Trust this verified project release, including its unsafe string representation code. |
| [jrmuizel](https://github.com/jrmuizel) (5946) | 1 | Jeff Muizelaar published the exact core-foundation 0.9.4 release from the Servo platform-bindings repository. Trust this historical Apple Core Foundation wrapper release. |
| [jdm](https://github.com/jdm) (2396) | 3 | Josh Bowman-Matthews publishes Servo platform bindings and html5ever support crates. Trust the verified core-foundation, web_atoms and markup5ever releases from the listed repositories. |
| [JelteF](https://github.com/JelteF) (3797) | 2 | Jelte Fennema-Nio maintains derive_more and derive_more-impl. The existing pinned Mozilla set explicitly trusts the same user-id for these packages and describes his PR security review; accept narrower historical local trust. |
| [kotauskas](https://github.com/kotauskas) (72501) | 1 | The kotauskas account maintains interprocess, whose pinned manifest, README and published source commit describe the local IPC toolkit. Explicitly trust this verified project release for its Unix/Windows IPC implementation; no local unsafe/ACL correctness certification is claimed. |
| [Spxg](https://github.com/Spxg) (89675) | 2 | Nico Goh maintains sqlite-wasm-rs and its rsqlite-vfs package. Explicitly trust these verified project releases and their SQLite/Wasm host-binding build integration; bundled C and VFS isolation are not independently audited. |
| [mrobinson](https://github.com/mrobinson) (2844) | 1 | Martin Robinson publishes the Servo tendril string container from servo/html5ever. Trust this verified project release of the parser support library. |
| [brotskydotcom](https://github.com/brotskydotcom) (103233) | 2 | Daniel Brotsky publishes keyring and dbus-secret-service; the project README documents the synchronous Secret Service backend and keyring integration. Trust these verified project releases, including their documented access to the OS credential store when called. |
| [gwenn](https://github.com/gwenn) (5062) | 2 | The gwenn account publishes rusqlite and libsqlite3-sys from rusqlite/rusqlite. Trust these verified project releases of SQLite wrappers and native build integration; this does not independently certify SQLite or SQLCipher C. |
| [Noratrieb](https://github.com/Noratrieb) (130181) | 1 | The Noratrieb account publishes rustc-hash from the official rust-lang repository. Trust this verified release of the compiler hash implementation; it is explicitly non-cryptographic. |
| [Loirooriol](https://github.com/Loirooriol) (437040) | 2 | Oriol Brufau publishes selectors and servo_arc from the Servo Stylo repository. Trust these verified project releases of browser CSS and shared-allocation infrastructure; the recently created registry account is verified by exact historical publication, not an old account assumption. |
| [folkertdev](https://github.com/folkertdev) (256011) | 1 | Folkert de Vries publishes zlib-rs from the Trifecta Tech Foundation repository. Trust this verified project release of the Rust compression implementation; no local decompressor robustness audit is claimed. |
| [github:srijs/rust-crc32fast](https://github.com/srijs/rust-crc32fast) | 1 | Official rust-crc32fast repository release identity for CRC32 dispatch/implementation. Trust this verified project release for local test execution. |
| [asomers](https://github.com/asomers) (6094) | 1 | Alan Somers publishes nix from nix-rust/nix. Trust the verified nix 0.32.0 project release of Unix platform API wrappers. |
| [chipsenkbeil](https://github.com/chipsenkbeil) (67779) | 1 | Chip Senkbeil maintains typed-path, a lexical Unix/Windows path library. Trust this verified upstream release; no security claim about callers using paths for filesystem authorization is made. |
| [github:zip-rs/zip2](https://github.com/zip-rs/zip2) | 1 | Official zip-rs/zip2 repository release identity for the ZIP reader/writer. Trust this verified project release for local synthetic fuzz inputs; this does not independently certify archive extraction on hostile production input. |

У sqlcipher-src, sqlite-wasm-rs/rsqlite-vfs, libsqlite3-sys, openssl-sys и
interprocess это явное принятие релиза конкретного упаковщика/мейнтейнера,
включая native C, FFI, build integration или IPC. Встроенный C/ASM, криптография,
изоляция VFS/ACL и unsafe-контракты не объявляются проверенными агентом.
Предшествующий незаконченный просмотр typenum также не превращён в исходный
аудит: теперь пакет покрыт отдельным доверием к подтверждённой публикации paholg.
У PHF и derive_more дополнительно учтены прямые trusted entries тех же user-id
в уже закреплённом наборе Mozilla; чужие окна доверия не копировались.

Из нового источника официального реестра просмотрен Ariel OS:
commit `f868e4c7262753a38f94f5c64db83a61862d6b4e`,
[audits.toml](https://github.com/ariel-os/ariel-os/blob/f868e4c7262753a38f94f5c64db83a61862d6b4e/supply-chain/audits.toml),
SHA-256 `6f701ac53c40cece09a77790386087e61520d323c817fc73ccd8df1da42b3690`.
Историческая delta-цепочка futures-lite дублирует выбранное покрытие точной
публикации notgull; источник не добавлен. Предыдущие imports не обновлялись.
В imports.lock добавлены только publisher-метаданные; внешний набор audits
побайтно сохранён. Результат доверия измерен отдельно: **79 → 15**.

Затем выполнены 15 собственных проверок точных версий с `safe-to-run`:
`enumflags2_derive 0.7.12`, `redox_syscall 0.5.18`, `enumflags2 0.7.12`, `blocking 1.7.0`, `async-recursion 1.2.0`, `doctest-file 1.1.1`, `matchit 0.8.4`, `ordered-stream 0.2.0`, `recvmsg 1.0.0`, `uds_windows 1.2.1`, `dtoa-short 0.3.5`, `secret-service 4.0.0`, `constant_time_eq 0.6.1`, `ego-tree 0.11.1`, `scraper 0.29.0`.
Порядок записи и последовательных locked-проверок соответствует убыванию числа
транзитивных потребителей: enumflags2_derive/redox_syscall — по 10, enumflags2 — 9,
blocking — 8, далее узлы с 7, 6, 5, 4 и 3 потребителями. Все записи явно помечены
Codex agent и содержат SHA-256 архива, прочитанные пути, ожидаемые обращения к ОС
и границы проверки. Для больших обёрток это целевой просмотр путей полномочий,
а не заявление о построчном доказательстве всего unsafe. Тесты самих crates
не запускались. Последовательный результат: **15 → 0**.

Ограничения записаны прямо: Redox raw syscalls/MMIO/PIO и Scheme требуют
предусмотренных платформы и доверенных kernel pointers; отмечены непроверенные
byte views/padding, временный bits()-view, некорректные directory records и
атомики. recvmsg требует доверенных receiver/buffer contracts и квот от caller;
blocking — ограниченной вызывающим нагрузки. Secret Service обращается к
session D-Bus/credential store только по вызову; его upstream integration tests
на реальном хранилище не запускались. CLI scraper читает указанные файлы/stdin,
а запись man page допускает только явный флаг; этот режим не исполнялся.
Эти ограничения не заменяют production-аудит: новый safe-to-deploy не добавлен.

Финальный `node scripts/vet-dependencies.mjs fuzz` **без** обновления imports:
exit 0, conclusion success, **273 fully vetted**, 0 partially vetted,
0 exemptions, хеши четырёх входов неизменны. cargo-deny fuzz 0.22.0: exit 0,
advisories/bans/licenses/sources ok; остались только предупреждения о дубликатах.
Это локальная проверка Windows x86_64, не CI и не закрытие M6/других графов.
Все свидетельства и ограничения — в
[отчёте завершения](../../supply-chain/fuzz/review-2026-11-26-completion.json).
