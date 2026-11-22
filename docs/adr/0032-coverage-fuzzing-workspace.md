# Отдельный coverage-guided fuzz workspace

## Решение

Добавлен исключённый из production workspace каталог fuzz. Три libFuzzer target
проверяют import всех восьми форматов, IPC frames/Envelope/native host/core RPC и
Shield roundtrip/final canary veto. Успешный импорт дополнительно проверяется на
лимиты, отсутствие control characters и детерминизм. IPC target ничего не
исполняет: он только разбирает и повторно кодирует типизированные сообщения.
В его Tokio runtime включён таймер, но не I/O driver.

Новая dev-only зависимость libfuzzer-sys =0.4.13 закреплена отдельным Cargo.lock;
SHA-256 опубликованного package:
a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2.
Рантайм включает LLVM code под NCSA; точечное разрешение лицензии действует
только для этой версии libfuzzer-sys. Алгоритмы runtime не патчатся. Макрос
upstream создаёт FFI harness; handwritten unsafe code в проект не добавлен.
Остальные прямые зависимости используют закреплённые версии приложения.
Production SBOM и бинарники приложения libFuzzer не включают.

Инструмент cargo-fuzz закреплён на 0.13.2, nightly — 2026-11-20. Они установлены
рядом с основным Rust; root rust-toolchain и глобальный default не меняются.
Поддержка Windows проверяется по
[официальной инструкции](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html).
PowerShell wrapper добавляет установленный MSVC ASan DLL каталог только в PATH
текущего процесса. Адресный sanitizer задаётся явно и не отключается при ошибке.
Инструментация vendored C/ASM отдельно не аттестуется этим Rust smoke test.

## Синтетические corpus и отчёт

Corpus создаётся из синтетических seeds. SQLite/ZIP seed generator использует
in-memory database/archive и проверяет, что они действительно импортируются.
Сюда входят три browser SQLite schema, Takeout, chat exports, HTML, реальные
length-prefixed IPC frames, UTF-8/PII/placeholders для Shield. Corpus, crash
artifacts и coverage игнорируются Git. Реальные экспорты сюда не добавляются.

Runner отказывается читать seed/corpus через symlink/junction, не перезаписывает
существующий seed, ограничивает target, время, input, RSS и время одного input.
Перед сборкой metadata проверяется locked/offline; cargo-fuzz 0.13.2 не имеет
--locked для build/run, поэтому runner работает offline и сверяет lock hash и
хеши исходников до/после. Несовпадение делает результат неуспешным.

Отчёт target/fuzz/reports содержит только target, статус, время, версии и хеши;
успех записывается после нулевого exit code и проверок неизменности. Сборка
выполняется до начала измеряемого запуска. CI запускает короткий ASan smoke для
каждого target и сохраняет отчёт/crash artifacts. Это не 24-часовая кампания и
не закрывает M6. Полный запуск доступен тем же runner с 86400 секундами.

При подготовке corpus найден обход запрета nested ZIP через UTF-8 BOM: верхний
sniffer снимал BOM, а guard внутри ZIP смотрел исходные байты. Regression test
сначала воспроизвёл приём вложенного архива. Guard теперь применяет тот же
sniffer; вложение отвергается, top-level BOM остаётся поддержанным.
