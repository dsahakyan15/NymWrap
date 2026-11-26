# Аудиты зависимостей продуктового графа root

Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только для
`Cargo.toml` в корне и `supply-chain/root/`. Исходная ревизия —
`4691e27f15b7ea109c2a01116387f450454b7054`, дата — 2026-11-26.
Продуктовый критерий **safe-to-deploy сохранён**: root использует стандартную
политику cargo-vet; локальных policy overrides на safe-to-run нет.
Версии, все Cargo.lock и правило audit-as-crates-io для llama-cpp-2 не меняются.

Метод взят из [ADR 0088](0088-fuzz-dependency-audit-sources.md), но доверие для
fuzz не перенесено автоматически. safe-to-deploy требует рассмотреть unsafe,
ambient capabilities и генерируемый deployed-код при недоверенном вводе,
а не только отсутствие неожиданных действий при сборке/локальном запуске:
[семантика cargo-vet](https://mozilla.github.io/cargo-vet/built-in-criteria.html).

## Закреплённые внешние аудиты

Прямо доверяем опубликованным именованным проверкам следующих официальных
команд с их исходными критериями. Mozilla/Google сохранены на commits ADR 0073.
Дополнительно взяты те же immutable источники, что рассмотрены в ADR 0088:

- Bytecode Alliance / Wasmtime: `1499ce8728f5f1b7fae0db88e1417991b01cfc13`.
  Команда развивает runtime и проверяет production Rust/FFI и его зависимости.
- ISRG / Divvi Up libprio-rs: `7549f3c7dffe96d3a6e6fb214007911cdec3e8e6`.
  Релевантна работа с криптографией и агрегацией данных для приватности.
- Zcash Rust ecosystem: `ce132d7abdd52f2b3b0d55ed5dc9f152331535c2`.
  Принимаются атрибутированные проверки команд librustzcash/wallet/zcash,
  описанных в ADR 0088, для криптографического production ПО.
- Embark Studios: `732513edfd9172f4eda358b2d0cefc6cad1585ee`.
  Команда cargo-deny и Rust tooling публикует проверки production-зависимостей.

Точные URL и SHA-256 загруженных наборов записаны в
[JSON-отчёте](../../supply-chain/root/review-2026-11-26.json). Наборы не передают
собственные imports/exemptions; custom criteria не отображаются на более
сильные локальные. Собственные safe-to-run проверки fuzz не повышались и
не копировались. Внешние аудиты дали **268 → 245 → 242 → 235 → 233** пробела.

## Доверие к публикаторам именно для safe-to-deploy

[Trusted entries](https://mozilla.github.io/cargo-vet/trusting-publishers.html) —
явное доверие качеству production-релизов определённого сопровождающего,
а не доказательство авторства каждого изменения и не собственный source audit.
Выбраны 15 crates.io user-id и 7 официальных repository identities из списка
ADR 0088. Для каждого ниже заново принято ограниченное продуктовое доверие.
Полное обоснование повторено в notes каждой записи и в JSON вместе с
проверенными первичными upstream-источниками и их SHA-256.

| Публикатор | Основание safe-to-deploy в ограниченном семействе | Закрыто |
|---|---|---:|
| dtolnay (3618) | Сериализация недоверенных данных и безопасность сгенерированного Rust в Serde/syn и связанных макросах. | 17 |
| alexcrichton (1) | Только wasi: сопровождение Rust/Cargo/Wasmtime и production WASI ABI; openssl-src отложен. | 1 |
| tarcieri (267) | Руководитель RustCrypto: аутентификация, ключи, constant-time ограничения шифров/MAC и CPU dispatch. | 10 |
| newpavlov (5059) | Руководитель RustCrypto: production хеши/KDF, CBC, padding и размерные интерфейсы; getrandom исключён из итогового доверия. | 5 |
| taiki-e (33035) | Инварианты pinning, атомиков, cancellation/wakeup и владения в futures/smol/Crossbeam. | 11 |
| seanmonstar (359) | Сетевые HTTP-парсеры, framing, буферы и композиция сервисов Hyper/Tower; опубликована security policy. | 8 |
| Darksonn (6741) | Production Tokio: конкурентность, владение bytes/slab, генерация entry points, axum и tokio-util. | 6 |
| BurntSushi (189) | Недоверенные текст/шаблоны и ограничения сложности regex; для walkdir/same-file/winapi-util — заявленные файловые/symlink контракты. | 8 |
| cuviper (539) | Production арифметика rust-num, инварианты контейнеров indexmap/either и build capability detection. | 8 |
| kennykerr (64539) | Microsoft windows-rs: сгенерированные Windows ABI и упакованные target import libraries; unsafe предусловия вызывающего кода сохраняются. | 22 |
| epage (6743) | Парсинг/сериализация недоверенной TOML-конфигурации и parser combinators winnow. | 5 |
| Amanieu (2915) | Владение блокировками, атомарные состояния, RAII/unwind и Drop в parking_lot/lock_api/scopeguard. | 4 |
| sunfishcode (6825) | Безопасные syscall-обёртки rustix и согласованные ABI linux-raw-sys. | 2 |
| rust-lang-owner (55123) | Только jobserver, cmake, glob и hashbrown: официальная Rust toolchain/collection инфраструктура; общий аккаунт не разрешён целиком. | 4 |
| Thomasdezeeuw (6025) | Production Mio/socket2: владение сокетами, readiness, FFI длины и платформенные I/O контракты. | 2 |
| github:rust-lang/cc-rs | Официальный release cc/find-msvc-tools: native build arguments и compiler discovery; чужой компилируемый C/C++ не получает аудит. | 2 |
| github:rust-lang/flate2-rs | Production decompression wrapper на недоверенных байтах; backends и лимиты распаковки проверяются отдельно. | 1 |
| github:rust-lang/libc | Сопровождение production OS ABI/layout Rust-проектом; безопасность unsafe-вызовов требует проверки клиентов. | 1 |
| github:rust-lang/log | Синхронизация глобального logger и formatting dispatch; политика содержания журналов остаётся у приложения. | 1 |
| github:RustCrypto/hashes | Реализация sha1 и её dispatch на недоверенных байтах; стойкость SHA-1 к коллизиям не заявляется. | 1 |
| github:RustCrypto/utils | zeroize/derive: устойчивое к оптимизации очищение памяти и soundness сгенерированного cleanup. | 2 |
| github:taiki-e/pin-project-lite | Soundness структурной pin projection и ограничений Drop/Unpin в deployed async-коде. | 1 |

Итого **122 записи / 122 закрытых пары crate/version**, **233 → 111**.
Разрешены только перечисленные в JSON пакеты, с отдельным однодневным окном
`[день публикации, следующий день)`. Будущих релизов и широких периодов нет.
Это не утверждение о новом независимом криптографическом или native-аудите;
полагаемся на указанную компетенцию и сопровождение ровно этих upstream.

Для каждой точной locked-версии заново получен crates.io API response:
проверены published_by.id/login либо trustpub_data.repository/provider,
created_at, отсутствие yank; SHA-256 локального .crate совпал с checksum API,
Cargo.lock и sparse index. Текущий owner не подменяет uploader публикации.
При published_by=null не придуман человеческий user-id: используются
`github:<repository>`, а run_id/SHA сохранены как registry metadata. Отдельного
аудита этих workflows не заявляем. У path fork llama-cpp-2 нет registry checksum
в Cargo.lock: он не получил нового доверия или source audit; опубликованная
база и локальная/native разница остаются открытыми согласно ADR 0073.

Дополнительная запись getrandom 0.2.17 по newpavlov не дала измеримого покрытия
в locked resolver и удалена: **107 → 107** после исходных аудитов. Её проверенные
метаданные и история оставлены в deferred_publisher_trust; imports.lock вручную
не дополнялся. Доверие к alexcrichton не распространили на openssl-src: для
bundled OpenSSL C и обвязки общего опыта Rust toolchain недостаточно.

## Исходные проверки агента и честный остаток

Добавлены четыре полных записи safe-to-deploy: bitflags 2.13.2, version_check
0.9.5, wasm-bindgen-shared 0.2.130, endi 1.1.1. Каждая явно помечена
**«Проверено агентом, не человеком»**, имеет SHA архива, перечень рассмотренных
опасных операций/макросов и ограничения. По JSON можно сверить SHA каждого
просмотренного файла с опубликованным архивом. Исходные записи root сохранены.

Сначала рассматривались узлы с наибольшим числом транзитивных потребителей:
bitflags — 46, typenum/version_check — по 39. Для typenum просмотрены manifest,
структура и sealed marker traits, но арифметика/генерируемые таблицы не проверены
полностью — сертификата нет. generic-array (38) и errno (34) также оставлены
открытыми. У errno просмотрены все платформенные реализации, но требуется
завершить проверку ABI и NUL-терминации для strlen после strerror_r/ERANGE.
Это не заявление о подтверждённой уязвимости. Частичное чтение phf_shared
и native C/ASM тоже не объявлено аудитом.

Четыре аудита дали **111 → 110 → 109 → 108 → 107**. Новых exemptions нет.
Оставшиеся **107** пар с критериями и приоритетами перечислены в JSON.
Root dependency gate и M6 остаются **открытыми**; конечное состояние —
промежуточная партия, не зелёная приёмка.

## Локальная проверка

- Закреплённый cargo-vet 0.10.4: финальный
  `node scripts/vet-dependencies.mjs root`, без обновления imports, —
  failed, 107 gaps; все четыре хеша входов неизменны в финальном прогоне.
- cargo-deny 0.22.0: `cargo deny check --hide-inclusion-graph` — exit 0,
  advisories/bans/licenses/sources ok; предупреждения о дубликатах.
- Прямые проверки pinned rustc: version_check — 10 unit tests (исторический
  static corpus отсутствует и соответствующий тест возвращается без проверки);
  bitflags — 2 review tests, включая все 256 масок u8; wasm-bindgen-shared —
  schema hash approval test; endi — 11 unit tests и no_std compilation.
  Это не полный upstream feature matrix и не cross-platform CI.
- Тесты vet wrapper — 3/3; расширение `npm ci; npm test` — 24/24.
- `cargo test --workspace --locked`, `cargo clippy -- -D warnings` и
  `cargo test -p nw-leak-tests --locked` завершились exit 101 до окончания
  проверки проекта: сборке OpenSSL не хватило Perl; имеющийся Git Perl
  при process-local PATH не содержит `Locale::Maketext::Simple`.
  Инструменты не устанавливались, зелёного результата этих проверок нет.
- cargo vet fmt для root и git diff --check. Другие stores не менялись,
  пользовательское поведение не менялось; CI не запускался.

## Продолжение от a05f078: 107 → 88

2026-11-26, локальная ветка `agent/vet-root-2`. Продуктовый критерий
**safe-to-deploy** и все прежние immutable imports сохранены. Версии и
Cargo.lock не менялись, новых зависимостей, imports и exemptions нет.
Все промежуточные результаты и первичные evidence находятся в
[отчёте продолжения](../../supply-chain/root/review-2026-11-26-continuation.json).
Предыдущие числа и ограничения выше относятся к первой партии.

### Собственные крейты

Для всех 21 `nw-*` из `cargo metadata --locked --offline` явно записано
`policy.<name>.audit-as-crates-io=false`. Это собственный код workspace,
проверяемый в репозитории; одноимённые crates.io пакеты не являются его
источником. Аудиты собственных крейтов не добавлялись. **107 → 107**.
Third-party policy для llama-cpp-2 остаётся `true`: его опубликованная база,
локальная разница и native-код всё ещё требуют отдельных проверок.

### Дополнительные продуктовые доверия

Это решения доверять сопровождению конкретных production-инвариантов,
а не новые независимые source audits. У каждой записи ровно свой пакет,
верифицированный uploader/workflow и историческое окно публикации
`[день, следующий день)`. Иные публикации/семейства и будущие релизы не
разрешаются. SHA архива совпал с точной версией API, sparse index и Cargo.lock;
API также подтвердил отсутствие yank, дату и числовой id или repository identity.
Для workflow `published_by=null` человеческий id не придумывался.

| Identity | Пакеты и основание safe-to-deploy | Остаток |
|---|---|---:|
| matklad (2699) | once_cell: single assignment, публикация значения между потоками, reentrancy/panic и владение; автор и документация проекта. | 106 |
| github:wasm-bindgen/wasm-bindgen | wasm-bindgen, macro, macro-support, js-sys: согласованность Rust/JS ABI, владение памятью и сгенерированные интерфейсы; официальный Rust/Wasm проект и описанный процесс выпуска. | 102 |
| github:google/zerocopy | zerocopy и derive: alignment/layout, validity/aliasing и soundness сгенерированных trait impls; явная soundness policy, Miri/Kani и работа Google-команды в этом домене. | 100 |
| github:smallvec/smallvec | smallvec: inline/heap layout, инициализированная длина, перемещение, Drop/unwind и безопасные collection API; официальный upstream контейнера. | 99 |
| Stebalien (280) | tempfile: безопасное создание/права/владение временными файлами и ограничения path-based cleanup; документация безопасности авторского проекта. | 98 |
| github:rust-random/rand | rand: unbiased sampling, состояние RNG и границы crypto/noncrypto; официальный Rand и его security premises. | 97 |
| tony-iqlusion (19631) | secrecy: явное раскрытие, редактированный Debug, clone/serialization ограничения и zeroization; авторство Tony Arcieri подтверждено отдельным iqlusion-аккаунтом. | 96 |
| jplatte (6913) | axum-core: production request/response/body/extractor контракты над недоверенным HTTP; автор официального релиза Axum. | 95 |
| notgull (69526) | concurrent-queue, futures-lite, piper: thread ownership, initialized storage, atomic/wakeup/cancellation контракты; авторство и сопровождение соответствующих smol-примитивов. | 92 |

Итого **15 записей / 15 закрытых пар**, пять числовых user-id и четыре
repository identities. Точные URL/SHA primary sources, версии и даты — в JSON;
для wasm-bindgen, zerocopy, smallvec и Rand первичные документы взяты из
конкретного registry-reported commit. SHA/run_id реестра сохранены как metadata;
отдельного аудита workflows не заявляем. Для текущих веток других проектов
сохранён хеш прочитанного текста; он подтверждает основание доверия, не
подменяет проверку исторического uploader.

Ограничения явно повторены в notes: публичные fixed-key хеши и не-CSPRNG не
становятся аутентификацией; пользовательские unsafe impls, JS, closures и
инициализаторы остаются кодом вызывающего; tempfile не заменяет шифрование
диска или выбор безопасного каталога; секреты вне контейнеров не очищаются
автоматически. Зависимости рассматриваются отдельно.

Доверие `github:rust-random/getrandom` для 0.4.3 было проверено по тем же
первичным источникам и реестру, но дало **98 → 98**: resolver не выбрал
publisher evidence в imports.lock. Неиспользованная запись удалена после партии:
**92 → 92**. Обоснование, metadata и история оставлены в deferred_publisher_trust.
Период не расширяли, imports.lock вручную не заполняли. getrandom остаётся
пробелом; причина выбора resolver не установлена.

### Четыре исходных аудита агента

Каждая запись — полный source audit точной опубликованной версии для
`safe-to-deploy`, явно **«Проверено агентом, не человеком»**. SHA архивов и
просмотренных файлов сохранены; файлы Cargo cache побайтно сверены с архивами.
Последовательность: phf_shared 0.14.0 (**91**), tower-service 0.3.3 (**90**),
tower-layer 0.3.3 (**89**), proc-macro-crate 3.5.0 (**88**).

- phf_shared: весь runtime, hasher, optional ptrhash и макросы. Единственный
  unsafe cast разделяет байты u8/i8/bool с сохранением длины/lifetime, без
  изменения и padding. Проверены wrapping arithmetic, checked indexing,
  portable integer hashing и Rust-literal escaping. Некорректные/пустые
  generated tables могут паниковать; key equality и валидация генератора —
  ответственность потребителя. FmtConst для одноэлементного tuple выдаёт
  `(value)` без запятой: ограничение явно записано, точный round-trip не обещан.
  Пользовательский FmtConst способен выдавать произвольный код и требует
  доверенного вызывающего; эта проверка не сертифицирует consuming generators.
- tower-service: весь trait и адаптеры &mut/Box. Вызовы передаются тому же
  service без clone, обработки запроса или независимого владения ресурсами.
  Readiness, cancellation и authorization должны обеспечивать реализации.
- tower-layer: все пять модулей, Identity/LayerFn/Stack и tuple арностей 0–16.
  Проверены порядок композиции и сокращение рекурсии, без unsafe и скрытого I/O.
  Пользовательские closures/Debug/Layer остаются кодом вызывающего.
- proc-macro-crate: весь helper, manifests, unit tests и packaged integration
  test. Cargo TOML остаётся данными; библиотека возвращает имя, не исполняет
  токены. CARGO вызывается без shell с фиксированными отдельными locate-project
  аргументами; stdout используется только как путь к manifest. Env, Cargo и
  local build files — доверенные входы сборки, не sandbox для чужих manifests.
  Нормализация только заменяет дефисы; downstream macro обязан строить
  проверенный identifier. Cache/mtime/duplicate-name ошибки могут испортить
  сборку, и не должны использоваться как граница runtime-авторизации.

Приоритеты вновь рассмотрены от наибольшего числа транзитивных потребителей:
getrandom 0.2.17 — 40, typenum — 39, generic-array — 38, errno — 34.
Для typenum сверены inventory/manifests/lib.rs/sealed marker structure, но
объёмная арифметика и generated tables не проверены полностью. У generic-array
сверены archive/source inventory, но unsafe layout/инициализация/Drop ещё не
сертифицированы. У errno заново прочитаны все платформенные реализации и
проверены GNU/Microsoft документы; переносимая гарантия NUL после ERANGE для
всех Unix/WASI ABI не установлена. Его сертификата нет, подтверждённая
уязвимость не заявляется. signal-hook-registry только инвентаризирован;
signal-safety и конкурентное освобождение требуют отдельного чтения.
Далее проверены меньшие узлы с 16/13/12/12 потребителями. Неизвестное
не заменено exemptions; общий объём оставшихся 88 крейтов требует новой партии.

### Проверка продолжения и остаток

Финальный locked `node scripts/vet-dependencies.mjs root` — **failed, 88 gaps**;
четыре входа неизменны. Каждое добавление и удаление измерено той же командой.
Root `cargo deny check --hide-inclusion-graph`, cargo-deny 0.22.0 — exit 0:
advisories/bans/licenses/sources ok, только предупреждения о duplicate versions
и неиспользованных license exceptions. `cargo vet fmt`, rustfmt стенда и
`git diff --check` выполнены.

Прямой pinned rustc на Windows: 5 upstream-тестов phf_shared со std+ptrhash,
1 unit test tower-layer и 5 проверок сохранённого
[стенда](../../supply-chain/root/review-tests-2026-11-26.rs) прошли. Это тесты
байтов/escaping/границ metadata, service forwarding и порядка Layer/tuple,
не Miri и не cross-platform matrix. Optional uncased/unicase не тестировались.
Тесты proc-macro-crate не запускались: опубликованный integration test требует
не вошедший в архив nested workspace; исходный аудит не объявлен тестированием.
Первую ошибку компиляции стенда (создание non_exhaustive Hashes) исправили,
использовав публичный hash API, затем проверки прошли.

Полные workspace tests, clippy, leak tests и расширение в этой партии не
запускались согласно границам задачи для supply-chain/docs. Cargo test/clippy
не вызывались, Perl не использовался. CI не запускался. **88 пробелов**, включая
все три getrandom, typenum/generic-array/errno и native C/ASM/fork, перечислены
в JSON с критериями и приоритетами. Root dependency gate и M6 остаются открытыми.

## Третья партия от 61c17b5: 88 → 67

2026-11-26, ветка `agent/vet-root-3`. Добавлен **21 source audit агента**
для неизменного **safe-to-deploy**; новых trust/imports/exemptions и изменений
policy нет. Все девять Cargo.lock и версии сохранены. Другие графы не менялись.
Подробности, SHA архивов/просмотренных файлов, режим чтения и полный остаток —
в [третьем отчёте](../../supply-chain/root/review-2026-11-26-batch-3.json).

Сначала проинвентаризированы все 88 пакетов: размер Rust-исходников, unsafe,
build scripts, proc-macro, native/FFI и признаки файлов/сети/процессов.
Группы: 36 native/FFI, 26 unsafe/контракты, 6 proc-macro, 5 build scripts,
4 с признаками ambient capabilities, 5 небольших и 6 больших safe-Rust.
Это эвристическая сортировка, а не доказательство отсутствия опасных операций;
в отчёте указаны также перекрывающиеся признаки каждого пакета.
Использован локальный Cargo cache, SHA архивов сверен с Cargo.lock и sparse
index; просматривались байты архивов, имеющиеся распакованные файлы сверены.
crates.io API не вызывался; новой проверки uploader/свежести yank не заявляем.

Проверены new_debug_unreachable, stable_deref_trait, dtoa-short, find_cuda_helper,
async-recursion, enumflags2 и derive, zvariant_utils, doctest-file, rustc-hash,
string_cache_codegen, phf_codegen, phf_macros, phf, markup5ever, memoffset,
derive_more, constant_time_eq, xdg-home, ordered-stream и web_atoms. У каждой
записи есть явное **«Проверено агентом, не человеком»**, SHA и конкретные
ограничения. Для небольших крейтов прочитаны manifests и весь production-код;
у ordered-stream прочитан весь исполняемый код и контракты, без полного чтения
больших rustdoc-примеров. У web_atoms прочитана вся логика, а таблица 2231 entities
и 1108 local names целиком разобраны строгой грамматикой как данные; точность
каждого соответствия стандарту HTML не объявлена проверенной. **88 → 72 → 67**.

Рассмотрены также небезопасные контракты и генерация deployed-кода: mask/enum
transmute, float scratch/UTF-8, SIMD/DIT, UTF-8 границы tendril, escaping Rust
литералов и доверенные текстовые fragments в codegen, файловые пути и rustfmt.
Дискреционные ограничения safe-to-deploy явно записаны в notes: memoffset
опирается на уже закреплённый Rust 1.100, а старые unsound fallback не признаны
универсально безопасными; xdg-home может терять OS allocation на error/UTF-16
ветвях и доверяет локальному HOME/NSS; у ordered-stream воспроизведён завышенный
position_hint в B-ветви Join, поэтому hint не принят как граница авторизации
или anti-replay. Это не новые более слабые критерии и не аудиты зависимостей
этих библиотек. Constant-time свойства не объявлены измеренными на всех CPU.

Без сертификата оставлены полностью прочитанные кандидаты:

- **async-broadcast 0.7.2:** set_capacity(0) + overflow=true позволяет расти
  очереди сверх ёмкости; воспроизведено на 32 синтетических сообщениях.
- **zvariant_derive 4.2.0:** сгенерированный TryFrom<Value> паникует на короткой
  Structure из-за remove(0); воспроизведено в debug и release.
- **blocking 1.7.0:** persistent spawn failure повторяется под mutex в grow_pool;
  failure injection не запускался, требуется анализ ограничений ресурсов.
- **phf_generator 0.14.0:** неограниченный поиск/дубликаты/несогласованный hash
  могут зависать; контракт недоверенного ввода не объявлен закрытым.

Для первых двух подтверждён путь в самой библиотеке, а не remote exploit
NymWrap. siphasher 1.0.4 прочитан частично (common/64-bit и manifests), но
128-bit/serde state invariants ещё требуют анализа; UB не заявлен. Остальные
пакеты, включая getrandom всех трёх версий, typenum/generic-array/errno,
native C/ASM, llama-cpp-2 base/fork, остаются явно перечисленными пробелами.

Финальный `node scripts/vet-dependencies.mjs root` без обновления imports —
**failed, 67 gaps**, входы неизменны. cargo-deny 0.22.0 — exit 0;
advisories/bans/licenses/sources ok, прежние предупреждения. Сохранённый
[стенд](../../supply-chain/root/review-tests-2026-11-26-batch-3.mjs):
**11/11** в debug, release и ptrhash debug (33 результата), включая
воспроизведения двух причин отказа в аудите. Это не полные upstream suites,
не Miri, не ARM/timing matrix и не CI. Wrapper — 3/3, расширение — 24/24.
Workspace tests, clippy и leak tests вызваны, но все остановились (exit 1)
на сборке OpenSSL: executable perl не найден. Инструменты не устанавливались.
Root gate и M6 остаются открытыми; зелёная приёмка не заявляется.

## Четвёртая партия от df9dcc3: 67 → 50

2026-11-26, ветка `agent/vet-root-4`. Неизменный продуктовый критерий —
**safe-to-deploy**. Добавлены **14 точных доверий публикаторам**, **один исходный
аудит libloading 0.8.9** и **два поштучных exemptions** с анализом ниже.
Все девять Cargo.lock, версии, исходные policy и шесть закреплённых импортов
сохранены; другие графы и код приложения не менялись. Полные SHA архивов,
просмотренных файлов, registry metadata, проверки и остаток — в
[четвёртом отчёте](../../supply-chain/root/review-2026-11-26-batch-4.json).
Записи явно помечены **«Проверено агентом, не человеком»**.

### Проверенные публикации и импорты

У всех 17 затронутых пар архив сверен с Cargo.lock и фактической записью
локального sparse index; имеющиеся распакованные файлы побайтно совпали с
архивом. Для доверий заново проверены exact-version crates.io API:
checksum, дата, отсутствие yank и именно uploader id либо repository identity.
Основные серии exact-version запросов последовательные, с паузами 1,3 с,
кэшем в `target/root-review-4/` и ограниченным Retry-After/exponential backoff;
дополнительные сверки latest также кэшировались. HTTP 429 в этой партии не было.

| Identity | Точные версии и продуктовое основание доверия |
|---|---|
| newpavlov (5059), josephlr (39279), github:rust-random/getrandom | getrandom 0.2.17 / 0.3.4 / 0.4.3 соответственно: OS entropy, инициализация буфера, FFI и ошибки без небезопасного fallback. Прочитаны разделы README о платформах/ошибках и SECURITY; custom entropy source не получает доверия. |
| dvdhrm (12177) | r-efi 5.3.0 и 6.0.0: автор/сопровождающий reference UEFI bindings, ABI/layout и явные unsafe-интерфейсы; прочитаны официальный README и AUTHORS. Качество firmware и вызовы клиентов не проверены. |
| hds (172786) | tracing 0.1.44 и tracing-attributes 0.1.31: Tokio span/event dispatch, владение и generated instrumentation. Прочитаны README/CONTRIBUTING и metadata официального release-preparation commit с автором hds. Захват аргументов намеренный: отбор полей и отсутствие содержания в журналах остаются обязанностью приложения. |
| kornelski (988) | security-framework 2.11.1 / 3.7.0 и security-framework-sys 2.17.0: сопровождающий Apple TLS/Keychain bindings, CF ownership и ABI. Прочитаны README, исходные manifests и release metadata. Badge looking-for-maintainer сохранён как ограничение: будущая поддержка не обещана. |
| jrmuizel (5946), jdm (2396) | core-foundation 0.9.4 / 0.10.1: Mozilla/Servo publisher identities, явно названные в историческом аудите Bobby Holley; ownership/retain/release и native wrappers. Прочитаны README/manifests и metadata релиза 0.10.1. Это отдельное доверие точным публикациям, не продление старого wildcard. |
| folkertdev (256011) | zlib-rs 0.6.8: автор официального release commit, сопровождение bounds/CPU dispatch и compression/decompression в Trifecta Tech Foundation. Прочитаны README/manifest, metadata релиза и описание проекта фонда; прежний аудит проекта не объявлен аудитом этой версии. Лимиты распаковки остаются у приложения. |
| github:srijs/rust-crc32fast | crc32fast 1.5.5: официальный release identity, IEEE CRC, SIMD bounds/dispatch и описанный процесс fuzz/ASan. Прочитаны README и manifest. CRC не становится аутентификацией; независимого source/workflow audit нет. |

Основания подтверждаются первичными
[Tokio tracing](https://github.com/tokio-rs/tracing),
[getrandom SECURITY](https://github.com/rust-random/getrandom/blob/master/SECURITY.md),
[r-efi](https://github.com/r-efi/r-efi),
[rust-security-framework](https://github.com/kornelski/rust-security-framework),
[Servo Core Foundation](https://github.com/servo/core-foundation-rs),
[Trifecta zlib-rs](https://trifectatech.org/projects/zlib-rs/) и
[crc32fast](https://github.com/srijs/rust-crc32fast).
Хеши прочитанных snapshots и точные API responses атрибутированы в JSON.
У каждой записи только один пакет и исторические UTC-сутки `[день, следующий
день)`; будущих релизов и широких периодов нет. Это решения доверия
сопровождению production-инвариантов, а не заявление о прочтении всего кода
этих 14 пакетов или о независимом человеческом аудите.

`node scripts/vet-dependencies.mjs root --update-imports` штатно добавил
publisher evidence в imports.lock. Ручного дописывания publisher evidence нет.
Это устранило препятствие прошлых партий для getrandom. Замеры: **67 → 62 → 53**.
Проверены также актуальные heads прежних шести команд и прямые Mozilla
Cargo-vet/Firefox stores; дополнительные pins/imports не дали полезного
покрытия и не оставлены. При очистке эксперимента после автоматической
перестановки секций временно пострадали старые policy/import sections;
config целиком восстановлен из HEAD и повторно проверен. Тот промежуточный
результат не включён в итоговое уменьшение пробелов.

### Исходный аудит libloading 0.8.9

Прочитаны оба manifests, README и весь исполняемый production Rust, включая
обе платформы, constants, symbol/type/error helpers. Changelog проверен
полной построчной грамматикой: rustdoc и пустые modules, без исполняемого кода.
SHA архива — `d7c4b02199fee7c5d21a5ae7d8cfa79a6ef5bb2fc834d6e9058e89c825efdc55`.

Рассмотрены lifetime borrow Library → Symbol, Clone/Send/Sync, размерные
проверки перед pointer casts, NUL-проверки имён символов, владение handles,
однократное закрытие, dlerror и Windows system ABI/UTF-16/error-mode guard.
Загрузка native initializers/finalizers намеренно требует unsafe-доказательства
вызывающего. DLL search path, environment, сами DLL и клиенты не получают
сертификата. Windows filename API допускает усечение по embedded NUL;
проверка полного разрешённого пути остаётся у вызывающего. Сохранены
документированные ограничения dlerror на старых платформах без TLS error state.
Это исходный аудит реализации API, не аудит произвольного загружаемого кода.

<a id="root-4-unreachable"></a>

### Две воспроизведённые ошибки: достижимость и отдельные exemptions

Для **async-broadcast 0.7.2** повторно воспроизведён рост очереди до 32 сообщений
при capacity=0 и overflow=true. `set_capacity` разрешает ноль, `try_broadcast`
сравнивает len с capacity на равенство, а pop из пустой очереди не удаляет
сообщения. [crates.io API](https://crates.io/api/v1/crates/async-broadcast)
показывает latest 0.7.2; текущий upstream src/lib.rs на
`124e9a78a44f7e1fec07e106027cd78a54eb2860` побайтно совпадает с locked-исходником.
Опубликованного исправления не подтверждено. **Safe-to-deploy audit не дан.**

Для **zvariant_derive 4.2.0** повторно воспроизведена паника сгенерированного
TryFrom<Value> для структуры из двух полей при входной Structure из одного.
Проверен и [latest 5.15.1](https://crates.io/api/v1/crates/zvariant_derive/5.15.1):
скачанный архив сверён с checksum API, src/lib.rs делегирует генерацию в
zvariant_utils 4.2.0. Его опубликованный `src/derive/value.rs` всё ещё выдаёт
`fields.remove(0)` без проверки арности; файл прочитан целиком.
SHA helper-файла — `dcba0a356401d1f99d87dca1b1370d995f862754e59d5ae3dac07fe69404ab1a`.
Новая версия не объявлена исправлением. **Safe-to-deploy audit не дан.**

В root обе пары присутствуют через metadata-цепочку
`keyring 3.6.3 → optional secret-service 4.0.0 → zbus 4.4.0`.
Но workspace отключает default features keyring, а nw-vault/nw-cred включают
на Linux **sync-secret-service → dbus-secret-service**, не async-secret-service.
В keyring `src/secret_service.rs:92–98` эти импорты разделены cfg.
На Windows/macOS используются native backends.

Для каждой пары `cargo tree --locked --offline --target all -i <crate>
-e normal,build,dev` не показывает активного пути, также с `--all-features`
workspace. Из кода NymWrap в **текущем графе root ни один процесс** не достигает
ошибок. Потенциальными потребителями при смене backend были бы credential
операции nw-vault/nw-cred в `nymwrap`/`nymwrapd`; проверены их manifests и
вызовы keyring. Вывод не распространяется на desktop/netd stores.

По явному разрешению задачи добавлены ровно два отдельных exemptions,
каждый для своей версии, с SHA архива, причиной, ссылкой на этот анализ и
условиями пересмотра. Включение async backend, прямого пути или изменение
features отменяет основание: новый saved harness отвергает непустое inverse
tree. Эти исключения не сертифицируют остальной код пакетов. Вместе с
аудитом libloading они дают **53 → 50**.

### Требуют обновления

Для двух воспроизведённых ошибок **обязательное обновление сейчас не
установлено**: в root нет активного пути, а исправленная опубликованная версия
не подтверждена. `zvariant_derive 5.15.1` сохраняет проблему и не предлагается
как исправление. При включении async backend потребуется upstream repair
либо согласованная владельцем замена/обновление цепочки. Cargo.lock не менялся.
Непроверенный остаток не объявлен безопасным или не требующим обновлений.

### Проверка и незавершённый остаток

- Финальный `node scripts/vet-dependencies.mjs root`: **failed, 50 gaps**,
  locked imports, четыре входа неизменны. Без exemptions покрыты 15 новых пар
  (14 publisher decisions + один source audit), ещё две пары покрыты exemptions.
  Wrapper требует ноль `vetted_with_exemptions` для полного pass; это условие
  не менялось. Root gate и M6 остаются открытыми.
- `cargo deny check --hide-inclusion-graph`: exit 0,
  advisories/bans/licenses/sources ok; прежние предупреждения о дубликатах и
  неиспользованных license exceptions.
- [Стенд](../../supply-chain/root/review-tests-2026-11-26-batch-4.mjs):
  четыре проверки отсутствия активного пути и **3/3** Rust tests в debug и
  release (**6 результатов**). Включает оба воспроизведения и обращение к
  уже загруженному kernel32: правильный ABI/PID, Symbol clone/borrow, отказ
  внутреннему NUL имени символа. Unix, Miri и upstream feature matrix не запускались.
- `cargo vet fmt` для root, rustfmt стенда, JSON/integrity checks и
  `git diff --check`. Workspace tests, clippy, leak suite и расширение в этой
  партии **не запускались** согласно разрешённому объёму supply-chain/docs;
  Perl bootstrap не потребовался. CI и push не запускались.

Все **50** оставшихся пар с группами и дальнейшей работой перечислены в JSON.
Открыты typenum/generic-array/errno, signal-hook-registry, blocking,
phf_generator, siphasher, interprocess, парсеры, unsafe-контейнеры,
OpenSSL/SQLite/SQLCipher/native payload и llama-cpp-2 base/fork.
У siphasher дочитаны обе реализации, но optional serde state contract ещё не
закрыт. У zbus_names прочитана часть validators/conversions без полного
чтения остальных modules; сертификата нет. Неизвестное не заменено
массовыми exemptions или более слабым критерием.

## Продолжение от 41fc8a3: 50 → 10 → 9

2026-11-26, локальная ветка `agent/vet-root-5`. Изменён только store root,
этот ADR и раздел root в IMPLEMENTATION. Критерий **safe-to-deploy** сохранён;
версии, манифесты, все девять Cargo.lock, исходные policy и шесть immutable
imports не менялись. Новых import sources нет. Полные решения, ограничения,
SHA архивов и прочитанных файлов, команды и остаток находятся в
[пятом отчёте](../../supply-chain/root/review-2026-11-26-batch-5.json).

### Точные доверия публикаторам

Добавлены **27 записей для 22 identities**, каждая только для своего пакета
и исторических UTC-суток `[день публикации, следующий день)`. Это явные решения
доверять сопровождению production-инвариантов, **не независимые исходные аудиты**.
В notes каждой записи есть «Проверено агентом, не человеком», SHA архива,
что прочитано, конкретная область доверия и ограничения.

| Публикатор | Пакеты и область продуктового доверия |
|---|---|
| madsmtm | clang-sys: libclang ABI, version gates, владение динамической библиотекой; внешний LLVM проверяется отдельно. |
| brotskydotcom | dbus-secret-service, keyring: выбор backend, сессии/шифрование Secret Service, поиск/передача секретов, handles и ошибки; клиентская политика и зависимости отдельно. |
| JelteF | derive_more-impl: корректность и hygiene **сгенерированных deployed** conversions/operators/formatters. |
| adamreichold | ego-tree, scraper: владение DOM/узлами, стабильные IDs, интеграция HTML и selectors на недоверенном тексте. |
| novacrazy | generic-array: layout/length, инициализация, владение, Drop/unwind; unsafe пользовательские ArrayLength и typenum отдельно. |
| SimonSapin | html5ever, string_cache: browser HTML parsing и string interning, владение и статические таблицы. |
| kotauskas | interprocess, recvmsg: IPC handles, lifetimes, cancellation, инициализация message buffers и обработка усечения. |
| jswrenn | itertools: iterator ownership и unsafe-оптимизации; автор release commit — Philippe Cholet, не публикатор. |
| ibraheemdev | matchit: radix-trie, параметры/lifetimes и границы UTF-8 на входных URL. |
| Alexhuszagh | minimal-lexical: арифметика/округление float conversion; грамматика и подготовка digit iterators остаются клиенту. |
| asomers | nix 0.32.0: безопасные syscall wrappers, ABI, descriptors и pointer/length contracts. |
| kazcw | ppv-lite86: SIMD storage/операции, CPU dispatch и Machine safety design; не новый криптографический аудит. |
| dralley | quick-xml: XML events/encoding/namespaces и borrowing; schema, лимиты и политика entities отдельно. |
| 4lDO2 | redox_syscall: Redox ABI/layout и syscall assembly contracts; компетенция подтверждена официальным описанием kernel/ABI работы. |
| gwenn | rusqlite: Rust handles/statements/rows, binding lengths и callbacks; libsqlite3-sys и native engines остаются открытыми. |
| Loirooriol | selectors, servo_arc: browser CSS matching и refcount/layout/ownership unsafe-контейнера Stylo. |
| vorner | signal-hook-registry: синхронизация и lifetime registry, chaining/removal; callbacks должны оставаться async-signal-safe. |
| mrobinson | tendril: inline/shared/COW strings, refcounts и UTF validity; предупреждение README об unsafe сохранено и не подменено аудитом. |
| chipsenkbeil | typed-path: Windows/Unix parsing, UTF/byte boundaries и checked joins; это не symlink confinement. |
| paholg | typenum: type-level арифметика и генерируемые размерные константы, используемые unsafe-потребителями. |
| VoidStarKat | widestring: UTF-16/32, C NUL/length и владение; unsafe foreign pointers остаются обязанностью вызывающего. |
| github:zip-rs/zip2 | zip: hostile archive parsing/offsets и extraction paths; в 9.x header consistency opt-in, размера по умолчанию нет, бюджеты задаёт клиент. |

Для всех 50 исходных пробелов заново получен exact-version crates.io API:
проверены uploader/workflow, дата, checksum и отсутствие yank. Запросы шли
последовательно через curl с описательным User-Agent, паузой 1,35 с, кэшем
в target/ и поддержкой bounded backoff/Retry-After. HTTP 429 не было.
Начальная попытка Node завершилась TLS-ошибкой, curl без описательного
User-Agent получил 403; эти ответы не использованы как подтверждения.
Серия из 50 успешных API responses выполнена после этого, без отключения TLS.

У всех **41 затронутых архивов** SHA совпал с Cargo.lock и фактическим sparse
index; **1749** присутствующих распакованных файлов совпали с архивами.
Для identities рассмотрены официальные pinned README/release metadata,
авторские repositories/patches и документы проектов. Точные URL/SHA в JSON.
Поздние GitHub API commit lookups вернули 403 — они явно помечены unavailable,
а не выданы за проверенное авторство. Для Servo отдельно прочитан официальный
maintainers list; для Redox — разделы kernel/ABI официального release report.
Эти два mutable снимка имеют хеши и используются только как свидетельства роли.
У recvmsg repository в manifest отсутствует, но pinned README официального
`kotauskas/recvmsg` побайтно совпал с опубликованным. Старый URL DBus возвращает
404, canonical `open-source-cooperative/dbus-secret-service` на точном commit —
200. Publisher metadata добавлена штатным `regenerate imports`; ручных правок
evidence в imports.lock нет. Отдельного аудита workflows не заявляем.

### Тринадцать отдельных исключений по недостижимости

Для **каждой из всех 50 пар** выполнены две команды:

```text
cargo tree --locked --offline --target all -e normal,build,dev -i <crate>@<version>
cargo tree --locked --offline --target all -e normal,build,dev -i <crate>@<version> --all-features
```

Все 100 команд завершились exit 0. У следующих 13 пар обе stdout пусты;
добавлены отдельные exemptions с собственными версиями, SHA, причиной,
двумя точными командами и условием потери применимости. Исходных аудитов этим
пакетам не дано, на остальные графы вывод не перенесён.

| Пара | Почему путь неактивен в текущем root |
|---|---|
| blocking 1.7.0 | Unselected async zbus backend; dependency dev metadata не создаёт workspace execution path. |
| event-listener 5.4.2 | Только невыбранная async Secret Service цепочка. |
| hermit-abi 0.5.3 | polling/Hermit находится в невыбранном async stack, пути нет также при `--target all`. |
| nix 0.29.0 | Старая версия нужна невыбранному zbus; активная 0.32.0 отдельно получила trust. |
| openssl 0.10.82 | Rust wrapper optional; synchronous Secret Service использует crypto-rust. Активные openssl-src/openssl-sys **не исключены**. |
| rsqlite-vfs 0.2.0 | Приходит только из невыбранного sqlite-wasm-rs. |
| secret-service 4.0.0 | keyring выбирает sync-secret-service → dbus-secret-service. |
| sqlite-wasm-rs 0.6.3 | Workspace отключает default features rusqlite и не включает ffi-sqlite-wasm-rs. |
| uds_windows 1.2.1 | Только невыбранный zbus на Windows; активный IPC использует interprocess. |
| zbus 4.4.0 | Async backend keyring не выбран. |
| zbus_macros 4.4.0 | Генерирует код только для невыбранного zbus. |
| zbus_names 3.0.0 | Нужен невыбранной zbus/secret-service цепочке. |
| zvariant 4.2.0 | Сериализация только невыбранного zbus/zbus_names. |

`--all-features` включает features workspace, а не все optional features
каждой зависимости. Включение async/OpenSSL/wasm backend, прямой зависимости,
изменение dependency features или lockfile отменяет соответствующее основание.
[Стенд партии](../../supply-chain/root/review-tests-2026-11-26-batch-5.mjs)
повторяет все **26** пустых inverse-tree проверок и отвергает появление пути.
Вместе 27 trust records и 13 отдельных exemptions дали **50 → 10**.

### Исходный аудит phf_generator 0.14.0

Полностью прочитаны оба manifests, README, `src/lib.rs`, `src/ptrhash.rs`
и packaged binary `src/bin/gen_hash_test.rs`. SHA архива:
`aeb62e0959d5a1bebc965f4d15d9e2b7cea002b6b0f5ba8cde6cc26738467100`.
Рассмотрены индексирование/срезы, bucket/displacement и pilot/remap алгоритмы,
seed, integer widths, принадлежность результатов исходным ключам и соответствие
генерируемых таблиц deployed lookup. Unsafe, FFI, сети, ФС и subprocess в самом
генераторе нет; packaged binary создаёт синтетические строки в памяти.

Открытый ранее вопрос о бесконечном seed search разрешён **для root callers**:
генерация получает небольшие неизменные наборы distinct build-time keys,
а не runtime-ввод из импортов. Прочитаны `phf_macros::Map::from_parsed` и
`check_duplicates`, guards `phf_codegen::Map/OrderedMap::build`,
`string_cache_codegen::AtomType` с `BTreeSet` и фильтрацией перед генерацией.
Внешние генераторы проверяют или устраняют дубликаты до вызова. Их полный
исходный аудит здесь не заявляется; прочитанные sections и file hashes в JSON.

Дубликаты или постоянно коллидирующий custom hash всё ещё могут зациклить
прямой вызов; универсальная termination guarantee не заявляется. Наборы больше
u32 и генерация по недоверенным runtime keys не входят в рассмотренное root
использование и требуют пересмотра. Это ограничение записано в самом аудите.
Ptrhash прочитан и проверен дополнительно, хотя root его feature не включает.
Четыре синтетических теста в debug и release проверяют пустые/разноразмерные
наборы, полные перестановки, настоящий lookup через phf_shared, детерминизм
и отказ codegen на дубликатах. **8/8 результатов**, **10 → 9**.

### Требуют обновления

В этой партии **новых воспроизведённых проблем на активном root-пути нет**.
Недостаток Perl — ошибка окружения сборки OpenSSL, не доказательство
уязвимости или необходимости смены версии. Вопросы errno/ERANGE и optional
serde-state siphasher остаются непроверенными контрактами; они не объявлены
подтверждёнными уязвимостями, и trust/source audits им не даны.
У siphasher активны только default/std, но сам crate достижим — exemption ему
не дан. Предыдущие две ошибки async-broadcast/zvariant_derive остаются
недостижимыми; их исходные exemptions и условия пересмотра сохранены.
Ни одной версии как подтверждённого исправления не предложено.

### Проверка и точный остаток

- Финальный `node scripts/vet-dependencies.mjs root`: **failed, 9 gaps**,
  locked imports, четыре входа неизменны. Сохранены initial/final receipts.
- `cargo deny check --hide-inclusion-graph`: **exit 0**, advisories/bans/
  licenses/sources ok; прежние duplicate/unmatched-exception warnings.
- Стенд: **26/26** проверок недостижимости и **4/4 debug + 4/4 release**;
  vet wrapper tests **3/3**, расширение после offline npm ci — **24/24**.
- `cargo test --workspace --locked --offline`,
  `cargo clippy --locked --offline -- -D warnings`,
  `cargo test -p nw-leak-tests --locked --offline`: **exit 101** при Configure
  OpenSSL, `Command 'perl' not found`. Зелёного workspace/clippy/leak результата
  нет; инструменты не устанавливались. CI и push не запускались.
- Root cargo-vet fmt, rustfmt стенда, JSON/integrity checks и git diff --check.

Остались **ровно девять пар safe-to-deploy**:

- errno **0.3.15** — закончить ABI/NUL-termination анализ ERANGE перед strlen;
- siphasher **1.0.4** — завершить feature/state/serde и endian/streaming contracts;
- libdbus-sys **0.2.7**, libsqlite3-sys **0.40.0**, openssl-sys **0.9.118** —
  ABI/build и соответствующий native code;
- openssl-src **300.6.1+3.6.3**;
- sqlcipher-src **420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2**;
- llama-cpp-2 **0.1.161**, llama-cpp-sys-2 **0.1.161** — опубликованная база,
  local fork delta, FFI и llama.cpp/GGML/native model parsing.

Остаток с next actions сохранён в JSON. Все 50 закрыть не удалось: native
payload и нерешённые контракты не заменены общим доверием или exemptions.
Всего root теперь содержит **15 exemptions** с двумя исходными; даже ноль
failures сам по себе не сделал бы wrapper зелёным, поскольку он отдельно
требует пустой `vetted_with_exemptions`. Это правило не менялось.
**Root gate и M6 остаются открытыми.**

## Шестая партия от 902745c: 9 → 6

2026-11-26, ветка `agent/vet-root-6`, implementation sub-agent, без делегирования
и push. Добавлены ровно **три доверия публикаторам**, каждое для одного пакета
и исторических UTC-суток. **safe-to-deploy сохранён**, новых exemptions нет.
Версии, все Cargo.lock, manifests, прежние policy и шесть import sources не
менялись. Прежние разделы этого ADR описывают историю, не новый результат.
Полные registry evidence, SHA, область чтения и остаток — в
[шестом отчёте](../../supply-chain/root/review-2026-11-26-batch-6.json).

### Три ограниченных доверия

| Пара | Проверенный uploader и окно [start,end) | Основание |
|---|---|---|
| errno 0.3.15 | Chris Wong / lambda-fairy, id 684; 2026-11-12–13 | Автор и автор точного release commit; сопровождение OS ABI, TLS errno, форматирования и преобразования UTF. Прочитаны все production Rust файлы и manifests. |
| siphasher 1.0.4 | Frank Denis / jedisct1, id 468; 2026-09-25–26 | Автор и автор точного release commit; SipHash 1-3/2-4, 64/128 бит, tail/chunk bounds и deployed hashing. Прочитан весь production Rust. |
| openssl-src 300.6.1+3.6.3 | Alex Crichton / alexcrichton, id 1; 2026-06-09–10 | Прочитан весь production Rust build helper; отдельно подтверждено происхождение native payload OpenSSL 3.6.3 ниже. |

Для девяти исходных кандидатов свежие exact-version API запросы дали HTTP 200:
uploader, дата, отсутствие yank, checksum сверены с архивом и фактической записью
sparse index; registry-зависимости — также с Cargo.lock. У path fork llama-cpp-2
проверена опубликованная база, собственного checksum в Cargo.lock нет.
Все распакованные файлы совпали с .crate. Запросы последовательные, с
описательным User-Agent и паузой 1,4 с; TLS не отключался. Release patches и
README закреплены на точных commits и записаны с SHA. Publisher evidence
добавлена штатным regenerate imports, вручную imports.lock не дополнялся.
Каждая запись явно помечена **«Проверено агентом, не человеком»**; это решения
доверия, не заявление о полном независимом человеческом исходном аудите.

У errno прежний вопрос ERANGE проверен по GNU libc 2.42 `string/xpg-strerror.c`
и musl 1.2.5 `src/string/strerror_r.c`: обе реализации завершают непустой
буфер NUL и при ERANGE. Это не универсальное доказательство для всех libc,
локалей и ОС: их контракты остаются частью явного доверия сопровождающему.
Windows get/set и форматирование неизвестных кодов проверены локально.

У siphasher конструкторы и запись сохраняют `ntail < 8`; root выбирает только
default/std, также при workspace --all-features. Serde восстанавливает private
state без валидации: `ntail=8` принимается и даёт debug panic при write_u8.
Это воспроизведено, не объявлено исправленным; внешнее недоверенное состояние
десериализовать нельзя. В текущем root serde этой зависимости не включён.
Нулевые default keys не дают защиты от намеренных коллизий; криптографическая
аутентификация и универсальная constant-time гарантия не заявляются.

### Сверка native payload с upstream

[Воспроизводимая сверка](../../supply-chain/root/review-native-2026-11-26-batch-6.mjs)
проверяет SHA артефактов и побайтное совпадение упакованных поддеревьев.
По умолчанию использует cache в target/; `--fetch-upstream` загружает только
точные записанные HTTPS-артефакты. Сравнение упакованного подмножества не
объявляется равенством полных деревьев: исключённые upstream-файлы перечислены
числом, добавленный crate glue рассматривается отдельно.

| Крейты / upstream | Результат |
|---|---|
| openssl-src / OpenSSL 3.6.3 | Все 2425 общих упакованных файлов совпали с официальным release tar.gz. Три оставшихся dot-файла инструментов совпали с официальным тегом openssl-3.6.3. SHA архива совпал с upstream SHA256 asset. |
| libdbus-sys / libdbus 1.14.4 | Все 304 упакованных файла vendor/dbus совпали с официальным GitLab тегом dbus-1.14.4. Сертификата нет из-за build fallback ниже. |
| libsqlite3-sys / SQLite 3.54.1 | sqlite3.c, sqlite3.h и sqlite3ext.h совпали с официальным sqlite-amalgamation-3540100.zip. Два Rust binding-файла и wasm32-wasi-vfs.c — отдельный crate glue; его полная проверка не завершена. |
| sqlcipher-src / SQLCipher 4.20.0, SQLite 3.54.1 | Release source archive получен, но готовой амальгамации в нём нет. Генерация configure/make/Tcl не воспроизведена; совпадение sqlcipher.c и generated headers **не доказано**. Требует человеческого решения. |
| sqlcipher-src / libtomcrypt 1.18.2 | Все 425 файлов src/ совпали с официальным crypt-1.18.2.zip. В git-tag tarball отличались только ref-комментарии; он не выдан за побайтное совпадение. Это не закрывает непроверенную амальгамацию SQLCipher. |
| llama-cpp-sys-2 / llama.cpp d81235049384534c167caea52b85a694f6103d14 | Все 1908 упакованных файлов совпали с официальным commit; gitlink подтверждён HTML дерева wrapper на точном release commit. Соответствующего release tag среди свежих upstream refs не найдено. Это совпадение с commit, **не подтверждение официального релиза**; доверие не дано. |

OpenSSL archive SHA-256:
`243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1`.
**Вендоренный C/C++ совпадает с upstream OpenSSL 3.6.3; построчно агентом не
аудирован; доверие к upstream-проекту.** То же ограничение относится к ASM.
Происхождение подтверждено по официальному
[релизу OpenSSL](https://github.com/openssl/openssl/releases/tag/openssl-3.6.3),
а не по одному номеру версии внутри крейта. Подпись GPG независимо не проверялась.

У openssl-src default build/install/remove paths находятся внутри
OUT_DIR/openssl-build; Configure запускается в копии исходников, --prefix
направлен в OUT_DIR. openssldir — runtime metadata, не destination сборки.
Скачивания в Rust helper нет. Toolchain/environment и явный caller out_dir
остаются доверенной конфигурацией сборки. Legacy provider включён через
openssl-sys; безопасность всех legacy algorithms не заявляется. Доверие этому
пакету не сертифицирует openssl-sys, SQLCipher или вызывающий код приложения.

GitHub API git-tree вернул 403, поэтому для gitlink использован закреплённый
HTML. Неудачные 404 запросы и ошибка распаковки .xz без xz не выданы за evidence:
libdbus проверен по официальному GitLab tar.gz, libtomcrypt — по release ZIP.
Сырые URL, коды и SHA сохранены в JSON, включая эти ограничения.

### Открытые решения и точный остаток

Остались **6 safe-to-deploy gaps**, без новых exemptions:

- **libdbus-sys 0.2.7:** C совпал с 1.14.4, Rust/build прочитаны. При отсутствии
  vendor/dbus/dbus build_vendored.rs запускает git submodule update --init.
  В проверенном .crate каталог есть, но абсолютное требование «build не качает»
  этим fallback не обеспечено. Требует человеческого решения, доверие не дано.
- **libsqlite3-sys 0.40.0:** build.rs и runtime helpers прочитаны, SQLite сверена;
  завершить полную проверку generated Rust ABI и отдельного WASI VFS C glue.
  Неполное чтение не повышено до сертификата.
- **openssl-sys 0.9.118:** из фактического src/err.rs воспроизведено
  ERR_GET_REASON(ERR_SYSTEM_FLAG | 13) == 2. Проверенный OpenSSL 3.6.3
  include/openssl/err.h.in возвращает 13 через ERR_SYSTEM_MASK. Доверие и
  exemption не даны; исправление/обновление требует отдельного решения.
  Собственного Rust caller этого helper в root не найдено; crate остаётся
  активным для линковки SQLCipher. Это не remote exploit и не причина
  самовольно менять версии.
- **sqlcipher-src 420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2:**
  Rust lib/source list прочитаны, libtomcrypt совпал; официальную амальгамацию
  ещё нужно воспроизвести. Требует человеческого решения, доверие не дано.
- **llama-cpp-sys-2 0.1.161:** native subset совпал с commit, release qualification
  не подтверждена. При dynamic-link build.rs делает hard links DLL в
  target/profile, examples и deps вне OUT_DIR. Прочитана часть build/Rust,
  полный feature/ABI аудит не завершён. Требует человеческого решения.
- **llama-cpp-2 0.1.161:** опубликованная база и локальная разница открыты.
  Прочитан локальный build.rs и Win32 FILE bridge на C/Rust, сверена область
  delta; полный аудит Rust ownership/FFI базы не завершён. Сертификат не дан.

### Проверки шестой партии

- Финальный `node scripts/vet-dependencies.mjs root`: **failed, 6 gaps**,
  locked imports, все четыре входа неизменны. Критерий и wrapper не менялись.
- `cargo deny check --hide-inclusion-graph`: **exit 0**, advisories/bans/
  licenses/sources ok; прежние duplicate/unmatched-exception warnings.
- [Стенд](../../supply-chain/root/review-tests-2026-11-26-batch-6.mjs):
  **13 upstream + 6 synthetic tests** в debug и release, **38 результатов**.
  Включает полные split/tail проверки 64/128-bit SipHash, errno, serde-state
  ограничение и расхождение OpenSSL error helper; воспроизведения не исправления.
- Native recheck: OpenSSL 2425 + три dot-файла, libdbus 304, SQLite 3,
  llama.cpp 1908, libtomcrypt 425 файлов; SHA manifests сохранены в JSON.
- Все 15 прежних exemptions повторно дали пустое inverse tree с --target all,
  --all-features, normal/build/dev. Новых исключений нет. Wrapper tests **3/3**,
  расширение после offline npm ci — **24/24**.
- Workspace tests, clippy и leak suite запущены; каждый **exit 101**, Configure
  OpenSSL не находит Perl. Зелёного результата нет. Первый запуск isolated
  harness также столкнулся с rustup auto-sync/rename ошибкой rust-src;
  повтор с явными installed rustc/rustdoc прошёл. Toolchain/config не менялись.
- Root vet fmt, проверка неизменности lockfiles/других sections и git diff --check.
  CI и push не запускались. Native runtime, Miri и cross-platform matrix не
  запускались.

Все **15 прежних exemptions** сохранены и отдельно перечислены в JSON:
async-broadcast 0.7.2, blocking 1.7.0, event-listener 5.4.2, hermit-abi 0.5.3,
nix 0.29.0, openssl 0.10.82, rsqlite-vfs 0.2.0, secret-service 4.0.0,
sqlite-wasm-rs 0.6.3, uds_windows 1.2.1, zbus 4.4.0, zbus_macros 4.4.0,
zbus_names 3.0.0, zvariant 4.2.0, zvariant_derive 4.2.0. Даже ноль gaps не
сделал бы wrapper зелёным при этих exemptions. **Root gate и M6 открыты.**
