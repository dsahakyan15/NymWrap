# ADR 0111 — поштучные exemptions cargo-vet как принятый риск

Дата: 2026-11-28. Статус: принято владельцем 2026-11-28. Изменяет
[ADR 0073](0073-locked-dependency-audit-gates.md). Подготовлено агентом, не человеком.

## Контекст

После партий ADR 0102/0103/0104/0109/0110 закреплённый cargo-vet 0.10.4
(`check --locked`) оставлял пробелы: root 7, netd 20, desktop 5; fuzz — 0.
В основном это native C/C++/ASM/FFI (OpenSSL, SQLCipher/SQLite, llama.cpp,
libdbus, kqueue, rdrand) и пакеты с воспроизведёнными находками. Кроме того, в
stores уже были 38 записей недостижимости (root 15, netd 18, desktop 5), которые
wrapper по ADR 0073 отвергал. Построчный native review до срока не выполним.

## Решение

Абсолютный запрет exemptions ADR 0073 заменяется узким исключением:

1. Разрешены только exemptions для **точных `name@version`** из
   `supply-chain/exemptions-allowlist.json`. Множество записей в config.toml
   каждого store должно совпадать с allowlist этого store. Новый непроверенный
   пакет или новая версия по-прежнему дают красный gate.
2. Каждая запись: `criteria = "safe-to-deploy"` и `notes`, где есть «ADR 0111»,
   причина (native code / почему не проверено), ссылка на ADR с источником и
   находками и условие отмены. Записи добавлены вручную.
3. Запрещены `cargo vet regenerate exemptions`, wildcard/диапазоны, `suggest`
   и фиктивные `certify`. Imports, audits и policies не менялись.
4. Exemption — **принятый риск, не аудит.** Известные дефекты ADR 0103/0110
   (recvmsg, openssl-sys ERR_GET_REASON, serialize-to-javascript, vswhom-sys,
   libdbus-sys fallback, dirs-sys, data-encoding, rdrand и другие) **не
   объявляются исправленными**; их native review остаётся задачей M6.

Gate `scripts/vet-dependencies.mjs` проверяет config.toml и allowlist до запуска
cargo-vet, затем требует, чтобы `vetted_with_exemptions` из JSON входили в
allowlist. Хеш allowlist входит в receipt. Fuzz store остаётся без exemptions.

## Перечень

| Store | Записей | Новые 2026-11-28 | Источник и находки |
|---|---|---|---|
| root | 22 | dbus-secret-service 4.1.0, libdbus-sys 0.2.7, libsqlite3-sys 0.40.0, llama-cpp-2 0.1.161, llama-cpp-sys-2 0.1.161, openssl-sys 0.9.118, sqlcipher-src 420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2 | [0102](0102-root-dependency-audit-sources.md), [0109](0109-secret-service-openssl.md), [0110](0110-cargo-vet-findings-and-ipc-reachability.md) |
| desktop | 10 | dbus-secret-service 4.1.0, serialize-to-javascript 0.1.2, serialize-to-javascript-impl 0.1.2, sqlcipher-src (та же версия), vswhom 0.1.0 | [0104](0104-desktop-dependency-audit-sources.md), [0109](0109-secret-service-openssl.md), [0110](0110-cargo-vet-findings-and-ipc-reachability.md) |
| netd | 38 | bitvec, convert_case, crypto-primes, data-encoding, dirs-sys, educe, enum-ordinalize, glob-match, iprange, kqueue, kqueue-sys, os_str_bytes, postage, rangemap, rdrand, recvmsg, reseeding_rng, sanitize-filename, strobe-rs, typed-index-collections (точные версии — в config.toml) | [0103](0103-netd-dependency-audit-sources.md), [0110](0110-cargo-vet-findings-and-ipc-reachability.md) |
| fuzz | 0 | — | [0088](0088-fuzz-dependency-audit-sources.md) |

Прежние 38 записей сохранены дословно, к их notes добавлен префикс ADR 0111;
их фраза «wrapper отвергает exemptions» устарела.

## Условия отмены

Запись удаляется (и gate снова краснеет, пока её не заменят аудитом) при:
смене версии пакета или его fork/патча; появлении подходящего внешнего аудита;
завершении собственного review; исправлении находки upstream; изменении
условия недостижимости, записанного в notes (новый caller, feature, target,
backend, режим сборки). Новая запись в allowlist требует нового ADR.

## Последствия

`cargo vet check --locked` зелёный для всех четырёх stores, но это не означает
проверенных зависимостей: 70 записей — явный долг аудита. Часть cargo-vet
THREAT_MODEL §9 п. 8 выполняется по формальному критерию gate с принятым риском;
SBOM в подписанном релизе и остальные пункты M6 этим не закрываются.
