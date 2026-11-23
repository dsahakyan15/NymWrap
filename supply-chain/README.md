# Аудиты зависимостей

Проверка: `node scripts/vet-dependencies.mjs` или один scope `root`, `desktop`,
`netd`, `fuzz`. Инструмент 0.10.4 и архивы закреплены в
`scripts/workflow-tools.lock.json`, решение — ADR 0073. Проверяются все features
каждого графа, с неизменными Cargo.lock и imports.lock. JSON и receipts — в
`target/vet/`; отсутствие отчёта, ошибка инструмента, partial или exemptions
не становятся зелёной проверкой. Это build tooling, не код приложения.

`node scripts/vet-dependencies.mjs --update-imports` явно выполняет
`cargo vet regenerate imports`, затем обычный `check --locked`. Источники
импортов Mozilla/Google указывают immutable commits. Новая версия upstream
аудитов требует изменения конфигурации и просмотра diff imports.lock.
Автоматических exemptions нет. Собственный дельтааудит equivalent 1.0.2 → 1.0.3
выполнен Codex после просмотра всех изменений двух опубликованных архивов из
локального Cargo cache с проверенными SHA-256. Менялись только documentation
contracts и метаданные, исполняемый код остался прежним. Это AI source review,
не независимый человеческий аудит; исходную базу покрывают записи Google.

Проверка пока **красная**. После первого полного refresh закреплённым инструментом
не хватало критериев для root 273, desktop 517, netd 502, fuzz 253 версий
пакетов. После дельтааудита equivalent и нового refresh: root 272, desktop 516,
netd 501, fuzz 252. Это четыре пересекающихся графа; числа нельзя складывать как число
разных зависимостей. Нужны реальные проверки исходников или подходящие
проверенные внешние аудиты, после которых повторяется locked check. Списки
пакетов остаются в машинных отчётах; нерешённые пробелы не исключаются из графа.

Path forks llama-cpp-2, rustls и Tor crates проверяются как опубликованная
third-party база. Это не сертифицирует локальные изменения или вложенный
C/ASM; их аудит остаётся открытым. Собственный совместимый re-export shim
rusqlite 0.40.99 не заменяет проверку фактического rusqlite из registry.
Зелёных CI для этой проверки нет; M6 и THREAT_MODEL §9 не закрыты.
