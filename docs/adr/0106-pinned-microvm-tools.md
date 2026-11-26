# 0106 — Закреплённые инструменты MicroVM

Как в ADR 0048, VMM и гостевые бинарники устанавливает отдельный явный
build/install tool, а приложение ничего не скачивает. Единственный manifest
`scripts/microvm-binaries.json` фиксирует версии, HTTPS URLs, размеры и SHA-256:

- Firecracker 1.18.0, официальный x86_64 release archive и извлечённый VMM;
- Linux 6.18.54 из датированного Firecracker CI snapshot
  `20261014-be8fe2826184-0`, без выбора latest в установщике;
- Alpine minirootfs 3.24.4: только BusyBox и musl, без служб, пакетного
  менеджера, SSH, импортированной конфигурации и сертификатов хоста;
- Zig 0.15.2 для Windows/Linux — только build tool для собственного
  `scripts/microvm/guest-init.c`, не библиотека Rust и не runtime launcher.

`node scripts/fetch-microvm.mjs --prepare` проверяет каждый архив до чтения
его членов, извлекает только выбранные rootfs/VMM файлы в память и проверяет
их отдельные SHA-256. Компилятор распаковывается в новый каталог; исходник C
передаётся stdin. Static stripped ELF собирается для фиксированной цели
x86_64-linux-musl с SOURCE_DATE_EPOCH=0, без build-id и путей компилятора;
его размер и SHA-256 тоже закреплены. Несовпадение сборки — ошибка, не повод
переписать pin. При изменении гостевого init новый digest должен быть проверен
и внесён отдельным изменением. В CI используется та же сборка и тот же pin.

В runtime manifest включён в бинарник Rust: hash/size проверяются при каждом
запуске, включая guest init. Проверенные байты копируются в sealed memfd;
последующая подмена файла на диске не меняет запущенные байты. Нет поиска VMM
в PATH, произвольного VMM config, скачивания из гостя или fallback.
Публичные инструменты и исходники не содержат пользовательских данных.

Это внешние инструменты, не новые Cargo dependencies. Внешний аудит и
обновление Firecracker/kernel/BusyBox/musl остаются обязанностью проекта;
cargo-vet их не покрывает. Лицензии: Firecracker Apache-2.0, Linux GPL-2.0-only,
BusyBox GPL-2.0-only, musl MIT, Zig MIT. Установщик сохраняет исходные публичные
архивы; при распространении производных образов нужно приложить соответствующие
лицензии и исходники. Этот шаг не включает их в release-пакеты проекта.

Происхождение пинов: [Firecracker release checksums](https://github.com/firecracker-microvm/firecracker/releases/download/v1.18.0/firecracker-v1.18.0-x86_64.tgz.sha256.txt),
[Alpine checksum](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.4-x86_64.tar.gz.sha256),
[Zig 0.15.2](https://ziglang.org/download/0.15.2/release-notes.html).
SHA ядра вычислен по скачанному бинарнику из указанного официального snapshot;
отдельной подписи этого объекта источник не предоставляет.
