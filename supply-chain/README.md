# Аудиты зависимостей

Проверка: `node scripts/vet-dependencies.mjs` или один scope `root`, `desktop`,
`netd`, `fuzz`. Инструмент 0.10.4 и архивы закреплены в
`scripts/workflow-tools.lock.json`, решение — ADR 0073 с изменением ADR 0111.
Проверяются все features каждого графа, с неизменными Cargo.lock и imports.lock.
JSON и receipts — в `target/vet/`; отсутствие отчёта, ошибка инструмента или
partial не становятся зелёной проверкой. Это build tooling, не код приложения.

`node scripts/vet-dependencies.mjs --update-imports` явно выполняет
`cargo vet regenerate imports`, затем обычный `check --locked`. Источники
импортов Mozilla/Google указывают immutable commits. Новая версия upstream
аудитов требует изменения конфигурации и просмотра diff imports.lock.

## Exemptions (ADR 0111)

С 2026-11-28 по решению владельца gate принимает exemptions, но только:

- точные `name@version` из [exemptions-allowlist.json](exemptions-allowlist.json);
  множество `[[exemptions.*]]` в config.toml каждого store должно совпадать с
  allowlist, а `vetted_with_exemptions` из JSON cargo-vet — входить в него;
- `criteria = "safe-to-deploy"` и `notes` со ссылкой на ADR 0111, причиной,
  ADR с источником/находками и условием отмены.

`cargo vet regenerate exemptions`, wildcard, `suggest` и фиктивные `certify`
запрещены. Новый непроверенный пакет или новая версия дают красный gate.
Exemption — **принятый риск, не аудит**: известные дефекты ADR 0103/0110 не
исправлены, native C/C++/ASM/FFI review остаётся задачей M6.

Состояние 2026-11-28, локально закреплённым cargo-vet 0.10.4: root, desktop,
netd, fuzz — `check_passed`; exemptions root 22, desktop 10, netd 38, fuzz 0.
Это четыре пересекающихся графа; числа нельзя складывать как число разных
зависимостей.

## Собственные аудиты

Собственный дельтааудит equivalent 1.0.2 → 1.0.3 выполнен Codex после
просмотра всех изменений двух опубликованных архивов из локального Cargo cache
с проверенными SHA-256. Менялись только documentation contracts и метаданные,
исполняемый код остался прежним. Это AI source review, не независимый
человеческий аудит; исходную базу покрывают записи Google. Так же отмечены
дельтааудиты proc-macro2, serde_spanned, toml_datetime и полный просмотр
cfg-if 1.0.5; полная проверка cfg-if не заменяет отдельный аудит optional
dependency. Дельта даёт покрытие только при полной цепочке аудитов базы и
зависимостей.

Path forks llama-cpp-2, rustls и Tor crates проверяются как опубликованная
third-party база. Это не сертифицирует локальные изменения или вложенный
C/ASM; их аудит остаётся открытым. Собственный совместимый re-export shim
rusqlite 0.40.99 не заменяет проверку фактического rusqlite из registry.
