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
