# cargo-vet: источники и промежуточный аудит графа netd

2026-11-26. Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только
для `daemons/nw-netd/Cargo.toml` и `supply-chain/netd/`. Исходный commit —
`4691e27f15b7ea109c2a01116387f450454b7054`. Манифесты, версии, все Cargo.lock,
остальные stores и cargo-vet 0.10.4 сохранены. Новых exemptions нет.

Результат этой партии: **499 → 312 пробелов**. Это промежуточная работа:
`node scripts/vet-dependencies.mjs netd` по-прежнему завершается провалом
аудитного покрытия. M6 и CI dependency-audits не закрыты.

## Критерий продукта

netd — поставляемый сетевой демон, обрабатывающий недоверенные ответы и байты
Tor/HTTP/TLS. Его требования остаются прежними: production-путь требует
`safe-to-deploy`, включая безопасность unsafe-кода, сильных возможностей и
генерируемого для продукта кода на враждебных данных. Существующая dev-политика
cargo-vet также не меняется. Не добавлены переопределения policies, ослабление
criteria или отображение `safe-to-run` на `safe-to-deploy`.

Послабление отдельного fuzz из [ADR 0088](0088-fuzz-dependency-audit-sources.md)
сюда не переносится. Его список авторов — только исходные кандидаты для нового
решения о доверии. Семантика взята из документации cargo-vet:
[criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html),
[publisher trust](https://mozilla.github.io/cargo-vet/trusting-publishers.html).

## Закреплённые внешние проверки

Mozilla и Google остаются на commits ADR 0073. Добавлены четыре прямых импорта,
ранее рассмотренные в ADR 0088; их содержимое заново получено и SHA-256 записан
в [JSON-отчёт](../../supply-chain/netd/review-2026-11-26.json):

| Источник | Immutable commit | Пробелов после шага |
|---|---|---:|
| Bytecode Alliance / Wasmtime | `1499ce8728f5f1b7fae0db88e1417991b01cfc13` | 475 |
| ISRG / Divvi Up / libprio-rs | `7549f3c7dffe96d3a6e6fb214007911cdec3e8e6` | 470 |
| Zcash / rust-ecosystem | `ce132d7abdd52f2b3b0d55ed5dc9f152331535c2` | 464 |
| Embark Studios / rust-ecosystem | `732513edfd9172f4eda358b2d0cefc6cad1585ee` | 461 |

Эти команды публикуют атрибутированные проверки зависимостей runtime,
криптографических продуктов и Rust tooling. Доверяем опубликованным записям с
их исходными criteria; custom criteria не усиливаются, чужие imports и
exemptions не наследуются. Агрегированный Zcash имеет те же три источника,
которые описаны в ADR 0088. Ссылки на точные audits.toml находятся в конфиге
netd; доверие к продукту не выводится из одного лишь имени организации.

### Tor Project / Arti

Официальный GitLab API подтвердил проект `tpo/core/arti`, id 647. Проверено
полное публичное дерево — **2486 записей, 25 страниц** — на commit
[`12432ae63b529bccbb68c52073576b19fd6f8552`](https://gitlab.torproject.org/tpo/core/arti/-/tree/12432ae63b529bccbb68c52073576b19fd6f8552).
В этом дереве нет cargo-vet `audits.toml`/store; найден `maint/cargo-audit`,
который не является набором cargo-vet. Tor также отсутствует в просмотренном
[реестре cargo-vet](https://github.com/mozilla/cargo-vet/blob/main/registry.toml).
Raw GitLab дал HTTP 403, поэтому вывод основан на успешном полном обходе API,
а не на ошибке загрузки одного предполагаемого пути. URL и хеши ответов API
сохранены в отчёте. Это ограниченный вывод об этой ревизии и просмотренном
реестре, а не утверждение об отсутствии у Tor других security audits.
Импорт Tor и доверие всем `tor-*` не добавлены; **36 Arti/Tor пакетов** остаются
пробелами.

## Доверие публикаторам для safe-to-deploy

Добавлены **145 отдельных записей для 145 пар crate/version**, сгруппированных
по **15 user-id и восьми GitHub identities**. Каждая запись ограничена именем
пакета и одним UTC-днём `[дата публикации, следующий день)`. Это разрешает
публикации того же автора/пакета в этот день; точный используемый релиз задаёт
неизменённый Cargo.lock. Долгих окон и разрешения будущих релизов нет.

До решения проверены exact-version uploader/дата/yank/checksum в crates.io API,
SHA локального `.crate` и sparse index; перед записью publisher lock также
проверен checksum Cargo.lock. Для **19 версий** использовано уже сохранённое
подтверждение crates.io из отчёта ADR 0088 на исходном commit: текущий API после
первой части запросов вернул HTTP 429. Их архивы и индекс сверены заново;
повторная онлайн-проверка uploader не заявляется. Эти случаи явно имеют
`metadata_origin` с источником и хешем прежнего отчёта. Остальные 126 версий
имеют вновь полученный ответ API. Workflow identity не подменяется user-id;
repository/run_id/SHA из реестра — происхождение публикации, не аудит workflow.

HTTP 429 помешал `regenerate imports` получить `paste`. Поэтому publisher-блоки
`imports.lock` перенесены из проверенных API-метаданных; для одинаковых версий
из прежнего отчёта использованы соответствующие блоки fuzz imports.lock.
Внешние аудиты до этого обновлены штатным `--update-imports`. Закреплённый
`cargo vet fmt` нормализовал store; каждый содержательный шаг после этого
измерен обычным CI wrapper `check --locked`, без изменения инструмента или
проверки. Это не фиктивные исходные аудиты. Онлайн-регенерацию следует повторить,
когда реестр снова доступен, и проверить diff publisher-метаданных.

Доверие — явно принятая эвристика к сопровождению конкретного семейства для
production, а не независимая проверка исходников. Краткие основания ниже;
каждая запись audits.toml и отчёт содержат подробное обоснование для
`safe-to-deploy`, область и ограничения. Прецеденты доверия в закреплённых
наборах не считаются аудитом более нового релиза.

| Автор / identity | Основание именно для продукта | Закрыто |
|---|---|---:|
| dtolnay (3618) | Serde/syn и собственные макросы: недоверенный синтаксис, сериализация, bounds/lifetimes генерируемого кода; прецедент safe-to-deploy в ISRG/Wasmtime | 23 |
| alexcrichton (1) | Только filetime/WASI: сопровождение Rust/Cargo/Wasmtime, файловые операции и корректность ABI; то же продуктовое доверие в pinned наборах | 2 |
| tarcieri (267) | Руководитель RustCrypto; доверие обработке враждебных ключей, подписей, шифротекста и unsafe ускорению в своих криптографических семействах | 24 |
| newpavlov (5059) | Руководитель RustCrypto; буферы, hash/cipher/KDF, источники энтропии и код literal-макроса, включая границы platform/unsafe | 8 |
| taiki-e (33035) | futures/crossbeam/fastrand: pin/waker, атомарность и конкурентное исполнение; fastrand не считается криптографическим RNG | 5 |
| seanmonstar (359) | HTTP/Hyper/body/Tower/mime: framing, длины и буферы при враждебных HTTP-данных; опыт production-протоколов | 8 |
| Darksonn (6741) | Tokio/bytes/slab/axum: владение буферами, async pinning и adversarial scheduling | 6 |
| BurntSushi (189) | Поиск/regex/bstr: недоверенные шаблоны и текст, SIMD bounds; отдельно ожидаемые операции file identity/tzdb | 8 |
| cuviper (539) | rust-num/indexmap/autocfg/either: инварианты чисел/контейнеров и корректность compiler probes, опыт Rust compiler/library/release | 7 |
| kennykerr (64539) | Microsoft windows-rs: generated ABI/layout/linkage и target import libraries; не безопасность произвольных вызовов Win32 | 12 |
| epage (6743) | TOML/winnow: границы парсеров и emitted syntax на недоверенной конфигурации, сопровождение Cargo/TOML | 12 |
| Amanieu (2915) | atomic/hashbrown/parking_lot: unsafe владение памятью, синхронизация и конкурентные нагрузки | 7 |
| sunfishcode (6825) | rustix/linux-raw-sys: указатели/длины, ABI и ошибки системных вызовов, опыт capability runtime | 2 |
| rust-lang-owner (55123) | Только jobserver: владение наследуемыми FD/handles и build coordination; hashbrown/libm/lazy_static этого user-id здесь не разрешены | 1 |
| Thomasdezeeuw (6025) | Mio/socket2: socket ABI, ownership/readiness и размеры буферов на враждебной сети | 2 |
| github:rust-lang/cc-rs | cc/find-msvc-tools: native toolchain и linker output; не аудит компилируемых ими C/ASM | 2 |
| github:rust-lang/flate2-rs | flate2: bounds/state на враждебном сжатом вводе; caller обязан ограничить объём распаковки | 1 |
| github:rust-lang/hashbrown | Unsafe bucket ownership/probing в официальной реализации таблиц Rust; выбор DoS-resistant hasher остаётся за caller | 1 |
| github:rust-lang/libc | ABI/signatures/layout системных bindings; не аудит их callers или native ОС | 1 |
| github:rust-lang/log | Global logger lifetime/init и конкурентный dispatch; content-free logging остаётся обязанностью NymWrap | 1 |
| github:RustCrypto/hashes | Hash padding/compression и accelerated unsafe при враждебных длинах; SHA-1 не объявляется collision-resistant | 3 |
| github:RustCrypto/utils | Буферы, constant-time helpers, zeroize и emitted derive-код; без отдельного crypto-reviewed утверждения | 8 |
| github:taiki-e/pin-project-lite | Soundness проекций и Drop генерируемого pin-кода при произвольном polling | 1 |

После каждого автора выполнен отдельный locked check: **461 → 316**.
Полная последовательность, версии, даты, URL и SHA ответов реестра — в JSON.

## Исходные аудиты агента

Приоритет задан числом транзитивных потребителей полного all-platform графа
`cargo metadata --locked`, без фильтрации платформ или features. Это приоритет
человеческого/агентского просмотра, не мера числа автоматически проверенных
зависимостей.

| Крейт | Потребителей | Просмотр и результат | Пробелов |
|---|---:|---|---:|
| wasm-bindgen-shared 0.2.130 | 131 | Все Rust-модули, build.rs, schema macro, manifests; ограниченные операции build git/read, безопасные строки и predicates | 315 |
| wasm-bindgen-macro 0.2.130 | 129 | Весь wrapper и diagnostic glue; macro-support остаётся отдельным пробелом | 314 |
| version_check 0.9.5 | 57 | Все четыре модуля и manifests; проверено управление индексами и ограниченный compiler subprocess без shell | 313 |
| crypto-common 0.2.2 | 54 | Все три модуля и macro families; проверки длины ключей/IV, сериализация, fallible entropy и ограничения peek/unwind | 312 |

Каждый аудит содержит точный SHA-256 `.crate`, `safe-to-deploy`, описание
просмотренного и честное авторство: **«проверено агентом, не человеком»**.
Архивы заново сверены с Cargo.lock и sparse index, исходники читались из этих
архивов; SHA отдельных просмотренных файлов также сохранены. Старые fuzz
`safe-to-run` аудиты не переименовывались.

В изолированных копиях исходников version_check прошёл 10 unit tests и
26 doctests, shared — один schema-hash test. crypto-common собран offline с
all-features и версиями разрешения netd: unit tests отсутствуют, четыре
doctests ignored, поэтому это только свидетельство компиляции. Копии для
тестов получили пустой `[workspace]`, файлы продукта не менялись.

## Остаток и проверки

**312 пробелов** перечислены полностью в отчёте с missing criteria. Среди
наиболее общих непросмотренных узлов — wasm-bindgen-macro-support/bindgen/js-sys,
typenum, r-efi/getrandom 0.4, hybrid-array, libm, bitflags, smallvec и zerocopy.
У typenum просмотрены только manifests/changelog/инвентарь; исходный аудит не
завершён. Большие платформенные/криптографические/генерирующие библиотеки и
native-код не сертифицированы по одному поиску подозрительных API.

Опубликованная база path forks по-прежнему проверяется через прежнее
`audit-as-crates-io`; локальные TLS/PT/compatibility изменения и C/ASM остаются
отдельной работой M6. Канареечные тесты здесь не изменялись: runtime-код и
сетевая граница не меняются.

JSON содержит checkpoints с receipt закреплённого инструмента, хешами входов,
локальным происхождением результатов, полным остатком и фактическими статусами
проверок. Зелёный `cargo-deny` не заменяет красный cargo-vet.

## Продолжение от 265e336: публикаторы Tor и наиболее общие узлы

2026-11-26, ветка `agent/vet-netd-2`. Новая партия: **312 → 253 пробела**,
суммарно от начала ADR — **499 → 253**. Меняются только store netd, этот ADR
и раздел netd в IMPLEMENTATION. Требования продукта остаются `safe-to-deploy`;
нет новых imports, exemptions, версий, зависимостей или изменений Cargo.lock.
Каждый шаг измерен прежним CI wrapper и записан с receipt и хешами входов в
[отчёте продолжения](../../supply-chain/netd/review-2026-11-26-continuation.json).
Прежний JSON сохранён как историческое свидетельство.

### Доверие Gabi: связь личности, релиза и реестра

Для каждого из **36** оставшихся `arti-*`/`tor-*` получен собственный ответ
exact-version crates.io API: все версии 0.48.0 опубликованы **4 ноября 2026**
аккаунтом **gabi-250, user-id 31201**, без yank. SHA-256 локального `.crate`
совпадает с checksum API и sparse index, а для registry-зависимостей — также
Cargo.lock. У трёх существующих path forks сверена именно опубликованная база;
их локальные изменения этим не сертифицируются.

Основания связи аккаунта с Tor Project проверялись совместно:

- [Официальная команда Tor](https://www.torproject.org/about/people/) указывает
  Gabi как участницу Network Team, работающую над Arti. Отпечаток её ключа
  `8F56AA5800BA4E2325EFFCC83946E0ADE72BAC99` совпадает с отпечатком в профиле
  GitHub `gabi-250`, на который ссылается crates.io. Это подтверждает вывод о
  связи identities; одна строка authors или совпадение имени не служили основанием.
- Официальный GitLab API связывает `gabi-250` (id 2470) с публичным адресом
  `gabi@torproject.org`; тот же аккаунт/адрес указан в релизном commit.
- [Тег arti-v2.8.0](https://gitlab.torproject.org/tpo/core/arti/-/tags/arti-v2.8.0)
  перечисляет каждую точную пару crate/version и ссылается на commit
  `7c038125baef924a4bf287429c192c5af606f79c`; именно он записан в VCS-метаданных
  всех рассмотренных архивов. Сохраняется различие annotated tag object и commit.
- [README этой ревизии](https://gitlab.torproject.org/tpo/core/arti/-/blob/7c038125baef924a4bf287429c192c5af606f79c/README.md)
  описывает пригодность клиента для обычного использования, а
  [релизное объявление](https://blog.torproject.org/arti_2_8_0_released/) и
  закреплённый CHANGELOG подтверждают сопровождение безопасности.

GitLab signature API сообщил только тип PGP. Криптографическая проверка подписи
локально не выполнялась и не заявляется. URL, хеши ответов и извлечённые поля
сохранены в отчёте; неуспешный запрос `/users/2470` не считается свидетельством.

Принято явное доверие релизному сопровождению Tor для production-клиента:
обработка враждебных cells, сертификатов и directory documents, криптографические
и unsafe-инварианты, circuit isolation, keystore и конкурентное исполнение.
Это сильнее разрешения просто собрать код, но остаётся эвристикой сопровождения,
а не независимой проверкой всей реализации, доказательством анонимности или
одобрением экспериментального relay/authority режима.

Каждый пакет получает собственную запись `trusted`, **только user-id 31201**,
`[2026-11-04, 2026-11-05)`. Политики по префиксу, длительного окна и разрешения
будущих публикаций нет. Получено **312 → 276**.

Ещё **девять** оставшихся библиотек явно перечислены в том же теге и имеют
того же реестрового публикатора, день и VCS commit: caret, fs-mistrust,
fslock-guard, oneshot-fused-workaround, retry-error, safelog, saturating-time,
slotmap-careful, web-time-compat. Решение отдельно охватывает права/пути и
блокировки файлов, обёртки логирования, futures, арифметику времени и владение
слотами; оно не гарантирует правильную файловую политику или отсутствие секретов
в сообщениях самого NymWrap. Результат — **276 → 267**.

### Остальные ограниченные доверия

Для всех строк ниже заново сверены exact-version публикации и SHA архивов.
У GitHub Trusted Publishing сопоставлены repository, run_id и head SHA
успешного официального run с VCS commit пакетов. Прочитаны закреплённые README
или crate-level документация и метаданные workflow. Это подтверждение
происхождения; полный аудит workflow, actions и окружения не заявляется.
Доверие каждому репозиторию принято отдельно и ограничено именами пакетов и
историческими UTC-сутками. Workflow identity не подменена отсутствующим user-id.

| Identity | Пакеты и область продуктового доверия | Пробелов |
|---|---|---:|
| github:wasm-bindgen/wasm-bindgen | wasm-bindgen/macro-support и js-sys: генерируемый ABI, владение, lifetimes и JS-граница; прежнее доверие Alex Crichton не считается аудитом нового workflow | 264 |
| github:rust-random/getrandom | getrandom 0.4.3: OS entropy, FFI, инициализация буферов и ошибки; корректность системного RNG остаётся сильным предположением | 263 |
| github:RustCrypto/hybrid-array | hybrid-array: соотношения длины/типа, layout и владение криптографическими буферами | 262 |
| github:RustCrypto/formats | const-oid 0.10.3: враждебные OID, длины, арифметика дуг и кодирование | 261 |
| github:RustCrypto/traits | digest 0.11.3: буферизация, длины, defaults и serialization macros; реализации алгоритмов проверяются отдельно | 260 |
| github:smallvec/smallvec | smallvec: stack/heap переходы, drop, panic-safety и unsafe layout; это отдельное решение о repository identity | 259 |
| github:RustCrypto/sponges | keccak 0.2.2: перестановки, константы, SIMD и ускоренный dispatch; без нового crypto-reviewed утверждения | 258 |
| github:google/zerocopy | zerocopy и derive: layout/alignment/byte validity, pointer provenance и генерируемые реализации | 256 |
| rust-lang-owner (55123) | Только libm 0.2.16: численный runtime compiler-builtins; закреплённый Wasmtime содержит прецедент доверия этому user-id именно для libm | 255 |

Таким образом, добавлено **57 отдельных записей доверия**: 45 Tor и 12 прочих.
Никакое доверие не распространяется автоматически на другие пакеты аккаунта.
Все шесть прежних immutable imports заново получены и сверены; их конфигурация
и импортированные проверки сохранены, их criteria не усиливались.

### Исходные аудиты и отказы в сертификации

Сохранён приоритет по числу транзитивных потребителей прежнего all-platform
графа: манифесты и lockfiles не изменились. У typenum (88) и r-efi (83)
проверен только инвентарь: полный разбор арифметики/генерации и firmware ABI
не завершён. bitflags, once_cell, strum_macros и другие сложные узлы остаются
явными пробелами, без аудита по одному поиску unsafe или известных API.

Завершены два исходных аудита с точным SHA-256 архива и авторством
**«проверено агентом, не человеком»**:

- **strum 0.28.0**, 40 потребителей: весь lib.rs, documentation module,
  манифесты, README и инвентарь. Безопасные trait-интерфейсы, фиксированное
  форматирование ParseError и cfg-реэкспорты не дают ambient authority.
  strum_macros/phf требуют собственного покрытия. Четыре doctest прошли в
  изолированной all-feature сборке; unit tests у пакета нет. **255 → 254**.
- **displaydoc 0.2.7**, 37 потребителей: все четыре production-модуля,
  оба манифеста, std/no_std генерация и форматные placeholders. Docstrings
  остаются строковыми литералами, имена становятся типизированными tokens;
  выдаются безопасные borrowed destructuring и write! без unchecked lifetimes.
  Некорректный синтаксис может остановить компиляцию; текст не исполняется.
  Formatter намеренно показывает выбранные caller значения, поэтому политика
  журналов NymWrap остаётся обязанностью приложения. **254 → 253**.

Полный upstream offline-набор displaydoc не запустился из-за отсутствующего
`pretty_assertions`; он не объявлен зелёным. Отдельный dependency-only harness
выполнил неизменённые upstream happy/num_in_field/no_std файлы: **3 теста со std,
2 без std**, no_std target компилируется в обоих случаях. Остальные unit/UI/doc
tests не выполнялись. Копии исходников получили лишь пустой `[workspace]`;
изменения тестовых манифестов и lockfiles находятся только в target/.

**convert_case 0.10.0 не сертифицирован.** С собственным upstream-кодом и
unicode-segmentation 1.13.3 воспроизведён panic:
`split(&"a:::b", &[delim_boundary!("::")])`. После первого разделителя цикл
проверяет перекрывающийся второй; начало среза оказывается после конца.
Обычный `a::b` проходит. Минимальный probe, SHA архива/файлов и хеш лога есть
в отчёте. Это препятствие аудиту пользовательских границ, а не установленная
уязвимость NymWrap: полная достижимость через зависимости не исследована.

У errno 0.3.15 прочитаны все шесть модулей и манифесты, но ABI-контракты
платформенных указателей и NUL-termination после strerror_r/ERANGE ещё не
доказаны для всех платформ. Аудит не добавлен; это незавершённое обязательство
проверки, не подтверждённая уязвимость.

### Проверки продолжения и остаток

Осталось **253 пробела**, перечисленных целиком и по приоритету в новом JSON.
Среди них **нет `arti-*`/`tor-*`**, но остаются другие Tor-зависимости и локальные
изменения forks. M6 и dependency-audits по-прежнему не закрыты.

Запросы crates.io выполнялись последовательно с паузой не менее трёх секунд
перед каждым некэшированным запросом. Ответы сохранены в target/; 429 в этой
партии не наблюдался, повторные попытки имели backoff. Publisher-блоки
imports.lock перенесены из проверенных ответов и нормализованы закреплённым
cargo-vet 0.10.4. `regenerate imports` не запускался, чтобы не создавать
параллельные запросы API; внешние audit-блоки не менялись.

`node scripts/vet-dependencies.mjs netd` подтвердил **253**, неизменность входов
и красный locked gate. `cargo deny --manifest-path daemons/nw-netd/Cargo.toml
check --hide-inclusion-graph` — exit 0 по всем четырём категориям; предупреждения
о нескольких версиях сохранены. Все четыре Cargo.lock неизменны.

Полноценный Strawberry Perl 5.40.5 подготовлен `bootstrap-perl.ps1`, модуль
Locale::Maketext::Simple загружен; для изолированных Cargo tests использованы
build-env.ps1 и CARGO_BUILD_JOBS=4. В Windows PowerShell 5 перед bootstrap
потребовалась загрузка System.IO.Compression.FileSystem. Workspace tests,
clippy, leak tests и тесты расширения не запускались согласно явно ограниченному
объёму проверки изменений supply-chain/docs. Эти результаты локальные, не CI.

## Продолжение от 3ab65e9: полная группировка остатка netd

2026-11-26, ветка `agent/vet-netd-3`: **253 → 109 пробелов**; от начала ADR —
**499 → 312 → 253 → 109**. Добавлены **128 записей доверия и 16 исходных аудитов**.
Меняются только store netd, этот ADR и раздел netd в IMPLEMENTATION. Критерий
продукта остаётся **safe-to-deploy**; policies, источники imports, зависимости, версии,
все Cargo.lock и exemptions сохранены. Gate остаётся красным, M6 открыт.

Полное свидетельство — [третий отчёт](../../supply-chain/netd/review-2026-11-26-third.json):
исходные 253 версии сгруппированы по точному публикатору, репозиторию и типу.
По Cargo metadata: 31 proc-macro, 24 пакета с build script; у оставшихся 198
пакетов в 125 найдены текстовые упоминания unsafe, в 73 — нет. Последнее —
только грубая сортировка: комментарии/тесты тоже дают совпадения, отсутствие
строки не доказывает отсутствие FFI или риска. Автоматических аудитов по этому
признаку нет.

### Реестр и отдельные решения о доверии

Для **всех 253 версий** получены exact-version ответы crates.io: дата,
публикатор либо Trusted Publishing, yank и checksum. SHA-256 каждого локального
архива совпал с API и sparse index; у registry-зависимостей также с Cargo.lock.
У path forks это сверка опубликованной базы. Запросы последовательные, пауза
перед некэшированным запросом — 3 секунды; предусмотрен backoff. Ответы и
временные инструменты лежат в `target/netd-review-3/`. HTTP 429 в этой партии
не наблюдался. Два старых winapi import-архива не имеют сообщённого API
публикатора: доверие им не добавлено.

Каждый новый `trusted` ограничен **именем пакета, проверенным identity и
историческими UTC-сутками**. Точный используемый релиз и checksum закреплены
неизменённым lockfile. Нет доверия будущим релизам или всем пакетам аккаунта.
Таблица ниже фиксирует принятые решения именно для продукта; это доверие
сопровождению, включая unsafe и генерируемый код, а не исходный аудит.

| Семейство | Новых записей | Область safe-to-deploy |
|---|---:|---|
| RustCrypto | 21 | Враждебные ключи/подписи/шифротекст, кодировки, арифметика и accelerated backends; без нового crypto-reviewed утверждения |
| Unicode ICU4X | 18 | Unicode/locale/IDNA, таблицы данных, layout и lifetime zero-copy типов и derives |
| Microsoft windows-rs | 10 | Генерируемый Win32/COM ABI, владение строками/интерфейсами, threading bridges |
| BurntSushi: Jiff, walkdir, winapi-util | 11 | Недоверенное время/TZif, статические данные и макросы, обход ФС и target FFI |
| Rust Random | 6 | Энтропия/ошибки ОС, буферы, sampling, ChaCha и reseeding; не любой RNG становится криптографическим |
| Dalek | 4 | Враждебные точки/скаляры/подписи, constant-time и SIMD/derive dispatch |
| Hashbrown, rust-lang-owner | 2 | Только две версии hashbrown: unsafe buckets, рост/drop и probing; выбор hasher остаётся у caller |
| Darling | 6 | Три core и три facade: синтаксис атрибутов и корректность сгенерированных реализаций |
| Ian Jackson, инструменты Tor | 5 | Шаблоны/строители, passwd/group FFI и явно вызываемое раскрытие путей |
| Tokio/Tower | 3 | axum-core, tracing и attributes: HTTP input, async ownership, dispatch и instrumentation |
| Rusticata | 5 | ASN.1/DER и derive/implementation: длины, теги, ошибки и parser contracts |
| Rust URL/IDNA | 3 | URL/form/IDNA bytes и нормализация; парсинг не заменяет endpoint allowlist |
| Rust PHF | 4 | Согласованность таблиц/индексов и генерируемых literals, lookup на произвольных ключах |
| Time | 4 | Время/format strings, диапазоны целых, checked arithmetic и literal macros |
| Async Compression | 3 | Poll/pin, частичные буферы, EOF и ошибки; отдельное покрытие backend и лимиты распаковки обязательны |
| Notify | 2 | FFI событий ФС и callback lifetime; события не служат авторизацией |
| Chrono | 1 | Календарная арифметика, parsing и платформенное время |
| Bitflags | 1 | Генерируемые операции/представление и feature-gated unsafe contracts |
| Bytemuck | 1 | Layout/alignment/validity casts; чужие unsafe marker impls не проверены этим доверием |
| Serde With | 2 | Адаптеры сериализации и macro-generated bounds/представление |
| Rustls | 5 | TLS/certificate parsing, PKI, roots и Tokio adapter; локальная дельта отдельно ниже |
| Winnow | 1 | Недоверенные байты/UTF-8, streaming/backtracking и ошибки |
| SSH forks Arti | 3 | Именно публикации Gabi: SSH encodings и fork-specific RSA compatibility, не upstream-релизы RustCrypto |
| Zkcrypto ff/group | 2 | Арифметические/constant-time trait contracts и представление; реализации полей/кривых отдельно |
| Taiki E | 3 | Pin/Drop/lifetime генерации и target atomic memory ordering, включая unsafe/build probes |
| Smol event-listener | 1 | Zeeshan Ali: wakeups, cancellation, memory ordering и unsafe владение listeners |
| Trifecta zlib-rs | 1 | Deflate state/bounds и unsafe/SIMD; caller ограничивает распакованный объём/работу |

В JSON у каждой версии есть числовой user-id либо точный repository identity,
дата, SHA ответа/архива и отдельное обоснование. Источники личности и проекта:

- [Руководство Unicode](https://unicode.org/consortium/techchairs.html),
  [состав комитетов](https://www.unicode.org/consortium/techcommittees.html)
  и официальный CODEOWNERS связывают Robert Bastian, Shane Carr и Manish
  Goregaokar с ICU4X. Реестр независимо связывает их logins с публикациями.
- У RustCrypto проверен [публичный состав команды](https://github.com/orgs/RustCrypto/people),
  включая baloo и dignifiedquire. README на VCS commit архива задаёт назначение
  семейств; предупреждения о raw primitives не превращены в обещание безопасной
  композиции. SSH-форки выделены из этого решения: README прямо сообщает о
  fork от ssh-key/v0.6.7 и изменении допуска старых RSA-ключей; опубликованный
  tor-key-forge выбирает fork явно. Личность Gabi установлена предыдущей партией.
- Закреплённый README Rustls перечисляет ctz/djc/cpu; [ISRG/Prossimo](https://www.memorysafety.org/initiative/rustls/)
  подтверждает их работу над TLS. Для zlib-rs проверены официальный README и
  [история проекта Prossimo](https://www.memorysafety.org/initiative/zlib/).
- Официальная история [релизов tracing](https://github.com/tokio-rs/tracing/actions/workflows/release.yml)
  связывает hds с конкретными tracing/attributes releases. Профиль Zeeshan Ali
  указывает сопровождение Smol. Это отдельные решения о новых публикаторах,
  не автоматическое распространение прежнего доверия Darksonn/Taiki E.
- Шесть уже закреплённых audit sources заново получены без изменения импорта.
  В Zcash найден независимый safe-to-deploy прецедент str4d именно для ff;
  его окно не скопировано и не расширено автоматически.

GitHub contributor API вернул HTTP 403; он не служит свидетельством членства.
Для Trusted Publishing сопоставлены repository и SHA с VCS архива; полной
проверки workflow/actions не заявляется. У pin-project/internal и
portable-atomic сначала обнаружено отличие package VCS SHA от SHA публикации.
Оно **разрешено до добавления доверия**: официальные commit metadata дают
единственным непосредственным родителем VCS-коммита именно publication SHA;
прочитанные полные patches меняют только версии и changelog. Проверены
закреплённые release workflow и части reusable workflow, создающие release
commit перед cargo publish. Для pin-project цепочка `62963de8… → f49edb95…`,
для portable-atomic `cb58081f… → e4595528…`. URL, SHA ответов, полные commit IDs
и область просмотра workflow записаны в JSON. Криптографическая проверка
подписей и аудит всех actions/окружения не заявляются. Получено **112 → 109**.
Publisher-блоки imports.lock перенесены из проверенных ответов API и
нормализованы закреплённым cargo-vet; внешние импортированные блоки сохранены.

### Шестнадцать исходных аудитов агента

Каждый имеет `safe-to-deploy`, SHA-256 архива, перечень прочитанных файлов с
хешами и пометку **«проверено агентом, не человеком»**. Прочитаны оба манифеста
и весь Rust-код соответствующего архива; source audit не выводился из registry
identity или одного поиска unsafe.

| Пакеты | Просмотренные свойства |
|---|---|
| hostname-validator 1.1.1 | Чистый ASCII predicate, длины hostname/labels, без индексации/ОС |
| tower-service/tower-layer 0.3.3 | Service delegation, Layer/Fn/Stack и tuples 0–16; без скрытых I/O |
| derive_builder_macro_fork_arti 0.11.2 | Полный proc-macro wrapper; генератор core проверяется отдельно |
| darling_macro 0.14.4/0.21.3/0.24.1 | Все entry points, typed AST и фиксированная диагностика; core отдельно |
| derive-deftly 1.14.0 | Реэкспорты точной версии macros, документационные модули и обязательный feature; шаблонизатор отдельно |
| humantime-serde 1.1.1 | Duration/SystemTime/Option adapters, fallible parsing и явное форматирование |
| secrecy 0.10.3 | Borrow/Drop/zeroize, редактирование Debug, opt-in Serialize; копии, swap и panic temporaries не объявлены защищёнными |
| downcast-rs 2.0.2 | Все macro arms, Any/static и Send/Sync bounds, безопасные Box/Rc/Arc downcasts |
| stable_deref_trait 1.2.1 | Полные unsafe marker contracts и каждый std/alloc impl; mutable owners не получают CloneStableDeref |
| by_address 1.2.1 | Оба unsafe repr(transparent) from_ref casts и DST metadata, согласованные Eq/Ord/Hash; Debug раскрывает адрес и значение |
| universal-hash 0.5.1/0.6.1 | Порядок blocks/tail, нулевое padding, ct comparison; в старой версии отдельно unsafe GenericArray slice cast |
| lazy_static 1.5.1 | Once publication/poisoning до MaybeUninit read, T:Sync и static lifetime, hygienic macro; spin backend отдельно |

Конкретные algorithms, dependency unsafe contracts, caller expressions, лимиты
ресурсов и политика журналов не объявлены проверенными этими wrapper-аудитами.
У universal-hash нулевой размер, выбранный собственной реализацией backend,
не является размером из сетевого ввода. У lazy_static циклическая инициализация
может зависнуть, а static values не очищаются через Drop при выходе: хранение
таким способом секретов, которым нужен Drop, недопустимо для NymWrap.

В неизменённых изолированных исходниках прошли 2 unit tests hostname-validator,
1 tower-layer и 30 downcast-rs. stable_deref_trait со std+alloc компилируется,
но unit tests у него нет. У by_address **2/3**, один тест предполагает разные
vtable, тогда как компилятор выдал одинаковые metadata; документация прямо
предупреждает об этой ненадёжности, провал сохранён. lazy_static сначала не
скомпилировал upstream tests с deny(warnings) из-за новых lints Rust 1.100;
с единственным диагностическим флагом `--cap-lints=allow` те же **9 тестов прошли**.
Полные UI/doctest и все feature/target combinations этих пакетов не заявлены.

### Локальные forks и convert_case

Полное сравнение четырёх опубликованных vendored деревьев с точными архивами
после нормализации CRLF не нашло удалённых файлов или скрытых добавленных
исходников. JSON содержит SHA каждого изменённого файла, список добавлений
и границу вывода. Это отдельный просмотр дельт, а не cargo-vet audit всего fork:

- **rustls:** ровно три source changes — optional order seed, default None и
  выбор `exts.order_seed`. Криптографическая энтропия не меняется; специальные
  ограничения порядка ECH/PSK остаются в upstream serializer.
- **tor-ptmgr:** прочитаны все hunks ipc.rs/managed.rs: managed caller требует
  isolation, без retry без песочницы; фиксированный argv и экранирование macOS
  literal paths, env_clear, нормализованное окружение, direct child kill/wait,
  очищенные logs/errors. macOS runtime, низкоуровневые direct callers и общая
  crash-lifetime остаются ограничениями, не объявлены решёнными.
- **tor-llcrypto:** сверены RSA type/API migration, RNG, significant bit_width
  и trimmed big-endian n/e. Дополнительно прочитаны соответствующие методы
  RSA 0.10/crypto-bigint; sign padding и checked constructor сохранены.
- **tor-key-forge:** private RSA keystore import/export возвращает ошибку;
  public mpints требуют положительного значения и checked PublicKey::new,
  экспорт использует positive bytes. Full RSA/SSH/native audit и пределы
  ресурсов для необычно больших ключей этим просмотром не заменены.
- **rusqlite-compat 0.40.99:** прочитаны весь манифест и трёхстрочный shim.
  Это неопубликованный реэкспорт точного rusqlite 0.43.0 с отключёнными defaults
  и forwarding features, не upstream archive с фиктивным аудитом 0.40.99.

**convert_case 0.10.0 остаётся пробелом**, но достижимость найденного panic
уточнена. Полный all-platform metadata/tree даёт единственного потребителя:
`derive_more-impl 2.1.1`, target **proc-macro**. Просмотрены все места конверсии
в is_variant, unwrap, try_unwrap, Display, FromStr и RenameAll. Они преобразуют
синтаксис/rename literals во время сборки через встроенные Case variants;
custom Boundary, delim_boundary!, set_boundaries и прямого split нет. Поэтому
именно перекрывающийся `"::"` panic из предыдущего отчёта этим путём недостижим,
включая rename literal с двоеточиями; runtime Tor/HTTP bytes сюда не попадают.
Это вывод о текущем lock и конкретном panic, не общий аудит convert_case.

### Проверки и оставшаяся работа третьей партии

`node scripts/vet-dependencies.mjs netd` с прежним cargo-vet 0.10.4 и
`check --locked` подтверждает **109 пробелов**, неизменность входов и красный
gate. `cargo deny --manifest-path daemons/nw-netd/Cargo.toml check
--hide-inclusion-graph` — exit 0 по четырём категориям, duplicate warnings
сохранены. Полный остаток и missing criteria перечислены в третьем JSON;
среди него нет `arti-*`/`tor-*`. Версии и четыре lockfile не менялись.

Среди незавершённого — typenum/r-efi, generic-array/once_cell, оставшиеся
генераторы, массивные OS/FFI/native библиотеки (ring, SQLite, zstd/liblzma)
и convert_case. Дополнительно прочитаны весь код sanitize-filename и unty,
но исходные аудиты не добавлены: остаются вопросы к контракту replacement/
Windows truncation первого и proof lifetime/TypeId erasure второго; это не
утверждение об установленной уязвимости NymWrap. Массового
exemption или ослабления product criterion нет. Локальные результаты и
провалы dependency source tests не объявляются результатами CI.

Общие проверки этой партии: `cargo test --workspace --locked` — exit 0,
164 passed / 16 ignored; `cargo clippy --locked -- -D warnings` — exit 0;
`npm test` расширения — build и 24/24. Workspace включает девять leak suites:
32 passed, один тест специального окружения ignored. Отдельный запуск
`cargo test -p nw-leak-tests --locked` остановлен на повторной нативной сборке
после подтверждения этих результатов; самостоятельный результат этой команды
не заявляется, отдельное feature combination не проверено. Ранние попытки
без Perl/libclang не прошли; финальные workspace/clippy использовали штатные
bootstrap scripts и build-env.ps1. SHA логов и фактические статусы — в JSON.
