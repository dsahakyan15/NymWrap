# Исправленная транзитивная cookie-зависимость desktop

Свежая проверка cargo-deny обнаружила RUSTSEC-2026-0594 в cookie 0.18.2 из
desktop workspace. По [advisory RustSec](https://github.com/RustSec/advisory-db/blob/main/crates/cookie/RUSTSEC-2026-0594.md)
private-cookie nonces могут повториться при fork без exec на Unix, использовании
одного ключа и определённого состояния thread-local RNG. Это не свидетельство
эксплуатации NymWrap; текущий Windows не удовлетворяет условию fork. Исключение
для этого advisory не добавляется, поскольку desktop имеет также Unix targets.

Через cargo update --precise транзитивный cookie закреплён в desktop Cargo.lock
на 0.18.3, checksum
d55f2d6c30eeec7d5c6f98bd4395d4abb1895629eab97ee6522d340623615f8a.
[Upstream исправление](https://github.com/rwf2/cookie-rs/commit/98de6032defb10ad5e49d83fa1a9bbed1873cbe4)
использует OS RNG для private nonce. Прямые зависимости и функции приложения
не добавляются. Решение Cargo также переиспользует уже имеющийся syn 2.0.119
в одной macro-зависимости вместо syn 3.0.10; остальные версии неизменны.

Проверка исправленной зависимости — прежний deny без ignore, native desktop
check и frontend tests. Cargo-vet требует отдельного покрытия новой версии;
обновление не считается её аудитом. Проверки Unix и актуальный CI остаются
открытыми до настоящего прогона.
