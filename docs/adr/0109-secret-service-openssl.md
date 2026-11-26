# ADR 0109 — OpenSSL для Linux Secret Service

Дата: 2026-11-26. Статус: реализовано для графов root и desktop; полный аудит
зависимостей и M6 остаются открытыми. Проверено агентом, не человеком.

## Причина

Аудит ADR 0104 обнаружил в dbus-secret-service 4.1.0 незащищённый ГПСЧ
`fastrand` при создании DH private key и IV, а также панику при неверной длине IV
в crypto-rust. Независимо прочитаны manifests и session.rs точных cached версий
4.1.0 и 4.2.0. **Одна смена feature на crypto-openssl недостаточна:** обе версии
используют общий `salt()`/`Keypair::generate()` с fastrand и собственной BigUint
арифметикой даже с OpenSSL. OpenSSL decrypt также может паниковать на коротком IV.
Ошибки подтверждены исходниками, upstream не объявлен исправленным.

## Решение

- nw-cred и nw-vault выбирают `sync-secret-service`, `crypto-openssl`, `vendored`
  на Linux. Windows/macOS сохраняют native keyring backend.
- Root и desktop явно подключают локальный patch `vendor/dbus-secret-service`,
  основанный на **4.1.0**, archive SHA-256
  `708b509edf7889e53d7efb0ffadd994cc6c2345ccb62f55cfd6b0682165e4fa6`.
  Состав изменений и лицензии сохранены в `UPSTREAM.md`. Netd lockfile,
  supply-chain/netd и его patch configuration не меняются.
- В patch разрешён только crypto-openssl. Удалены зависимости устаревшего
  crypto-rust backend, включая fastrand/num. Несовместимая конфигурация даёт
  compile_error; автоматического перехода на plain нет. Keyring по-прежнему
  явно запрашивает `EncryptionType::Dh`.
- DH выполняют OpenSSL `Dh::generate_key`/`Deriver`; IV создаётся `rand_bytes`.
  Сохраняются протокольные RFC 2409 group 2, g=2, 128-байтное дополнение общего
  секрета, HKDF-SHA256 с пустыми salt/info и AES-128-CBC/PKCS#7. Peer public key
  ограничен 128 байтами и интервалом `1 < y < p-1`, затем проверяется OpenSSL.
  Группа, KDF и формат IV сверены с [официальной спецификацией Secret Service](https://specifications.freedesktop.org/secret-service/latest/ch07s03.html).
- Закрытый DH-ключ хранится только в native OpenSSL owner: прочитанный DH_free
  точной поставки вызывает BN_clear_free для private BIGNUM. Rust-буферы общего
  секрета, промежуточного AES-ключа и частично расшифрованных данных используют
  `Zeroizing`. Session сохраняет upstream `ZeroizeOnDrop`; ключи берутся по ссылке.
  Публичные DH-значения, IV и ciphertext не являются секретами.
- IV должен иметь ровно 16 байт, ciphertext — непустую длину, кратную блоку.
  Ошибки RNG, DH, HKDF и cipher возвращаются через Result до операций keyring;
  при ошибке нет plain/system fallback. Внешний IPC/API keyring не меняется.

Это локальная реализация устранения конкретных дефектов, **не новый полный
safe-to-deploy аудит dbus-secret-service или криптографического протокола**.
В обоих графах `policy.dbus-secret-service.audit-as-crates-io = true` сохраняет
third-party base в проверке cargo-vet, хотя зависимость стала path patch.
Прежнее root publisher trust dbus-secret-service отозвано из-за подтверждённой
ошибки общего криптографического пути; README не основание скрывать её новым
типом зависимости. Патч также требует самостоятельного review. Полный review остальной D-Bus библиотеки,
native FFI и legacy 1024-bit протокола остаётся человеческой задачей.

## Сборка и отсутствие загрузок

`openssl-sys 0.9.118` vendored branch вызывает `openssl-src::Build`.
В openssl-src **300.6.1+3.6.3** источник берётся из локального `openssl/`,
копируется в OUT_DIR и собирается Perl Configure + make/nmake; downloader и
сетевой bootstrap в прочитанном Rust build helper отсутствуют. Native OpenSSL
и его toolchain остаются отдельной границей доверия. Полный Windows Perl
устанавливается явным bootstrap с закреплённым hash до сборки, затем
dot-source `scripts/build-env.ps1`. Он не заменяется Perl из Git Bash.

`libdbus-sys 0.2.7` содержит сетевой fallback: если отсутствует
`vendor/dbus/dbus`, запускается `git submodule update --init vendor/dbus`.
В проверенной registry-поставке каталог присутствует; SHA архива сверена с
crates.io, sparse index и lockfile. Именно эта ветка **не исполняется при наших
полных vendored inputs**. CI-проверка перед сборкой требует наличие каталога и
OpenSSL Configure, проверяет hashes обоих cached архивов. Наличие fallback
не исправляется и не одобряется этим ADR; решение по upstream — ADR 0110.
`--offline` ограничивает Cargo, а не сетевые возможности дочерних build scripts.
Linux-сборка под физическим запретом сети локально не выполнялась.

## Cargo-vet и закрепление

Оба Cargo.lock обновлены без обновления версий остальных пакетов. Локальный
patch закреплён исходниками репозитория; новые прямые test/build зависимости
имеют точные версии и registry checksums в lockfiles.

Из root удалено ложное non-reachability exemption для **openssl 0.10.82**.
Добавлено ограниченное доверие официальному release maintainer Alex Gaynor,
crates.io account **alex / 163**, только за UTC день публикации
`[2026-11-01, 2026-11-02)`. Это та же доказанная идентичность, которая уже
используется desktop (ADR 0104), с новой exact-version проверкой API, non-yanked
sparse index и архива SHA-256
`4de8111e94a56adca7ebfe6c365b6d42f99deb69b74b6becacd4204e2f193aa2`.
Доверие не распространяется на openssl-sys и его известную находку.
Остальные ставшие активными Rust helpers покрываются существующими аудитами;
остальные 14 root non-reachability exceptions перепроверены после смены features
для `--target all`, normal/build/dev, default и all workspace features.

Источник доказательств: [review-2026-11-26-dep-fixes.json](../../supply-chain/root/review-2026-11-26-dep-fixes.json).
Остальные пробелы и exemptions не скрываются; wrapper ADR 0073 продолжает их
отклонять. Никакой release gate не ослаблен.

## Регрессии и ограничения проверки

`node scripts/check-keyring-backend.mjs [root|desktop]` проверяет Linux feature
resolution с любого host, в default/all-features: local patch, crypto-openssl,
vendored и отсутствие crypto-rust. Проверка сначала воспроизведённо падала на
исходной конфигурации; добавлена в CI dependency-audits для двух графов.

`tests/leak/tests/keyring_crypto.rs` подключает **тот же файл crypto backend**,
поэтому работает на Windows без настоящего Secret Service. Проверяются обмен
DH, roundtrip синтетической канарейки, неверные IV/peer/ciphertext и фиксированный
DH/HKDF vector с ведущими нулями. Это не статистическое доказательство качества
ГПСЧ; источник энтропии задаётся вызовами OpenSSL, а ошибки передаются вызывающему.
Не запускались настоящий Linux keyring, D-Bus integration или тесты враждебного
провайдера Secret Service. Локальные результаты перечислены в IMPLEMENTATION.

Сетевые правила NymWrap, разделение полос, зашифрованное хранение, согласия,
честная автоматизация и журналы без содержания сохраняются. Новых пользовательских
операций и миграции данных нет; USER_GUIDE не требует изменения.
