# Fuzzing NymWrap

Только синтетические входы; не добавляйте реальные экспорты или секреты в corpus.
Root workspace продолжает использовать Rust 1.100.0. Отдельные инструменты:

```text
rustup toolchain install nightly-2026-11-20 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
```

На Windows нужны обычные build dependencies проекта и MSVC AddressSanitizer:

```powershell
./scripts/fuzz.ps1 -Target ipc_frames -Seconds 60
./scripts/fuzz.ps1 -Target audit_import -Seconds 60
./scripts/fuzz.ps1 -Target shield_roundtrip -Seconds 60
```

На Linux/macOS с C++ compiler:

```text
node scripts/fuzz.mjs --target ipc_frames --seconds 60
node scripts/fuzz.mjs --target audit_import --seconds 60
node scripts/fuzz.mjs --target shield_roundtrip --seconds 60
```

Runner создаёт corpus и включает ASan, затем пишет отчёт с хешами в
target/fuzz/reports. Успешный короткий smoke не заменяет M6: для кампании на
24 часа укажите 86400, сохраните отчёты для каждого target, платформу и сведения
о сборке. Для проверки vendored C/ASM нужна отдельная проверка инструментации.

IPC corpus включает синтетические корректные frames для HTTP submit receipt,
результата Purge и begin/validate/finish поискового permit. Они проверяются только
парсером и roundtrip; никакие действия этих команд не исполняются.

Crash artifacts находятся в fuzz/artifacts/TARGET. Рассматривайте их как
недоверенные данные: воспроизводите только в тестовом окружении. Никаких сетевых
запросов, model inference или действий RPC fuzz targets не выполняют.
