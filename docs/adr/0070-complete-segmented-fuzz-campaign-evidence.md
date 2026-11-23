# Полная цепочка длительного фаззинга в CI

30-секундный smoke не заменяет 24 часа. По [лимитам GitHub Actions](https://docs.github.com/en/actions/reference/limits)
один hosted job работает максимум 6 часов. Новый ручной workflow имеет два
явных режима: native preflight и полная кампания 24h. Каждый из трёх targets
(audit_import, ipc_frames, shield_roundtrip) проходит шесть последовательных
исполнений по четыре часа. Это 24 часа исполнения на target с перезапусками,
не один непрерывный процесс. Отчёт сохраняет continuous_process=false;
утверждение о непрерывных 24 часах этим не делается.

Cargo-fuzz 0.13.2, nightly-2026-11-20, AddressSanitizer и target x86_64 Linux
закреплены. Каждый target собирается один раз, исполняется native preflight,
после чего тот же SHA бинарника переходит между Ubuntu 24.04 jobs. Официальные
checkout/setup-node/upload/download actions закреплены прежними commit pins.
Основание прямого запуска — локально прочитанный исходник cargo-fuzz 0.13.2,
project.rs: target-dir/triple/release и ASAN_OPTIONS detect_odr_violation=0.
Сам fuzzer получает те же лимиты длины/RSS/input-timeout и синтетические seeds.

Каждый следующий job проверяет прошлый corpus hash и receipt; агрегатор требует
все 18 записей, одинаковые source/build/binary SHA, commit, workflow run и
attempt, непрерывную цепочку corpus и прежних receipts. Независимые wall time и
финальная статистика libFuzzer должны подтвердить полные четыре часа; ранний
exit 0, падение, таймаут, пропуск или повтор не засчитываются. Частичный rerun
не смешивается с предыдущей попыткой. Preflight не входит в 24 часа.

Размер corpus для артефакта ограничен явно; превышение завершает job ошибкой,
данные не отбрасываются для получения зелёного результата. Отчёт не объявляет
закрытым M6: остальные пункты THREAT_MODEL §9 и реальный зелёный CI обязательны.
Новые workflow пока не запускались из-за блокера Actions. Локальные unit-тесты
проверяют протокол полноты, а не исполняют 24 часа и не заменяют native preflight.

Для проверки YAML, схем и expression types закреплён dev/CI tool
[actionlint 1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12),
MIT, с официальными archive SHA для Windows/Linux в
scripts/workflow-tools.lock.json. В исходники поставки он не входит. Installer
проверяет archive SHA, читает единственный фиксированный member через tar в
память и сверяет существующий бинарник с ним. Произвольные archive paths не
извлекаются. Shellcheck/pyflakes не выдаются за выполненные проверки.
