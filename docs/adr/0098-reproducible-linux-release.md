# Воспроизводимый неподписанный выпуск Linux

Статус: принято для задачи 11, M6. Новых зависимостей приложения нет.

## Решение

`reproducible.yml` выполняет два независимых задания на GitHub-hosted
`ubuntu-24.04` и `ubuntu-22.04`. Каждое без Actions/Cargo/npm cache заново
создаёт инструментарий и запускает отдельный чистый контейнер. Первое задание
не передаёт второму ни объектных файлов, ни исполняемых файлов. Сравнивающий
job ждёт оба результата, заново считает SHA-256 реальных файлов, проверяет
полноту набора и исходный commit. Любое расхождение блокирует общий артефакт.
Это независимость окружений сборки, а не независимость доверия к GitHub или
скомпрометированному компилятору. Владелец повторяет сборку на своей машине.

`node scripts/repro-build.mjs <пустой-каталог>` — общий вход для CI и владельца.
Он экспортирует только `git archive HEAD`; незакоммиченные файлы, секреты,
домашний каталог, host environment и host caches в контейнер не передаются.
Рецепт Docker также берётся из HEAD. Требуется Docker с Linux amd64 containers;
на Windows/macOS Linux-сборка выполняется в его VM (на ARM — с эмуляцией).
Этот build-time инструмент не является сетевым процессом NymWrap.

Зафиксированы linux/amd64 OCI manifests официальных Rust 1.100.0 и Node
24.11.1 (digest в `scripts/release/Dockerfile`), Debian bookworm snapshot
`20261125T000000Z`, Cargo.lock всех трёх графов и оба npm lockfile. APT сохраняет
проверку подписей архива; отключается только срок давности snapshot metadata.
Транзитивные build-only пакеты берутся из того же snapshot. Фактические
dpkg-версии, rustc, Node, флаги, commit и рецепт записываются в buildinfo и
тоже обязаны совпасть. OCI digests получены через официальный Registry v2 API
26.11.2026, не из изменяемых тегов. Docker image ID не сравнивается: проверяются
байты поставляемого выпуска.

Пути, locale, TZ и CPU target фиксированы; `SOURCE_DATE_EPOCH` — commit time,
Cargo/CMake используют четыре задания. Rust remap и C/C++ prefix-map удаляют
путь сборки; `target-cpu=x86-64` исключает host-native оптимизацию llama.cpp.
Cargo собирает с `--frozen` после locked fetch. npm использует `ci` и integrity
из lockfile. Tauri собирается без установщика, с `tauri/custom-protocol` для
встроенного UI; updater не добавляется (инвариант 2).

Архив содержит все девять исполняемых файлов (включая desktop, inference и
netd), оба варианта расширения и закреплённый lyrebird. Последний скачивается
с проверкой существующих SHA-256, а не пересобирается: воспроизводимость
upstream Tor bundle здесь не заявляется. Тестовые программы и модели не входят.
Tar нормализует порядок, uid/gid, права и mtime; gzip использует `-n`.
Манифест `.files.sha256` даёт также хеши отдельных файлов внутри архива.

SBOM использует существующий `scripts/sbom.mjs` (ADR 0026): CycloneDX 1.6,
все features трёх locked Cargo-графов и хеши исходников UI/extension. Это
консервативная source inventory, не точный список linked features, не npm/OS
SBOM и не список моделей. Нативные системные зависимости перечислены отдельно
в buildinfo; для запуска Linux desktop нужны системные GTK/WebKit 4.1.
Схема SBOM проверяется перед публикацией общего артефакта.

## Границы платформ

Задача гарантирует проверку байтовой идентичности только Linux x86_64. Нативные
Windows/macOS сборки продолжают проверяться прежним CI, но в этот выпуск не
включены. Их невоспроизводимость не объявляется доказанной: два независимых
нативных release build здесь не измерялись. Windows потребует закрепить
MSVC/Windows SDK и проверить PE timestamp/PDB GUID и пути нативных библиотек;
macOS — Xcode/SDK/linker, Mach-O UUID и ad-hoc/code signing. Плавающие hosted
runner images не дают такого закрепления. Authenticode/notarization добавляют
отдельный подписывающий этап и не подменяют сравнение неподписанных байтов.
Вместо ложного обещания переносимость зафиксирована как последующая работа.

Два job должны реально пройти в CI; код workflow сам по себе не закрывает
пункт M6. Полное M6 также требует остальных критериев THREAT_MODEL §9.

Источники: [Rust remap](https://doc.rust-lang.org/rustc/remap-source-paths.html),
[Debian snapshot](https://snapshot.debian.org/),
[метаданные архивов](https://reproducible-builds.org/docs/archives/),
[повторное использование workflow](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).
