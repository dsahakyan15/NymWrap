# 0105 — Явный Linux MicroVM-бэкенд для теневого агента

## Решение

`nymwrap run --microvm /absolute/tools -- /guest/program [args]` выбирает
отдельный модуль `nw-sandbox::microvm`. Прежний `run -- ...` вызывает прежний
bwrap-путь. Launcher демонов, netns и Windows/Linux workers не меняются.
Переключение явное; отсутствие Linux x86_64, KVM, прав, инструментов или ошибка
старта завершают запуск. Автоматического fallback нет.

Firecracker получает одно vCPU, 256 MiB RAM, initramfs и virtio-vsock. Нет
virtio-net/TAP, дисков, shared filesystem, MMDS, VMM API или снимков памяти.
Все процессы этой сессии принадлежат `shadow`; гостю не передаются vault,
core RPC, model RPC, домашний каталог хоста или данные cover-полосы.
Единственная прикладная связь — отдельный приватный сокет `api.sock` владельца
процесса, через ограниченный хостовый relay и guest vsock CID 2, port 8000.
Гостевой `/run/nymwrap/api.sock` подходит для Unix transport SDK; HTTP проходит
обычный nw-api/Shield/approval/nw-netd pipeline. Relay не выбирает URL и не
предоставляет произвольные хостовые сокеты. Порты 8001/8002 передают только
stdout/stderr и код завершения пользователю, не являются сетевым выходом.

Гостевой PID 1 задаёт `localhost`, uid/gid 1000, `user`, UTC, C.UTF-8,
`/home/user`, `/work`, общий machine-id и git identity. Окружение очищается,
`/sys` и службы хоста отсутствуют. Агент теряет группы/root и получает NNP;
stdin закрыт. Запускается точный argv, без интерполяции shell. Вводимые моделью
строки не становятся host-командами; выбор исполняемой программы принадлежит
человеку, как в существующем CLI.

## Хранение и ограничения минимальной реализации

Проект копируется в RAM: максимум 64 MiB initramfs и 4096 записей. Принимаются
обычные файлы и каталоги, без symlink/hardlink/special files. Открытие через
дескрипторы каталогов и `openat(O_NOFOLLOW)` не даёт гонке с заменой symlink
прочитать другой хостовый путь. UID, mode и время файлов нормализуются.
Изменения `/work` исчезают при остановке, автоматического writeback нет.

Initramfs, argv, конфигурация, ядро и VMM передаются как запечатанные memfd;
хостовые временные каталоги содержат только Unix sockets. Буферы проекта
`Zeroizing`, core dumps запрещены. Запуск требует выключенного swap хоста
на всё время сессии; гостю swap-диск не предоставляется. Hibernate/дампы RAM
администратором вне защиты процесса. Время старта ограничено 30 секундами,
сессия — одним часом. Drop убивает и reaps VMM, PDEATHSIG закрывает смерть
launcher. Журналы VMM/serial отключены; вывод агента идёт в терминал.
Управляющие terminal/bidi символы вывода экранируются, stdout/stderr не
интерпретируются как команды терминала; relay-буферы обнуляются при освобождении.

Piped `kernel.core_pattern` также запрещён: Linux игнорирует RLIMIT_CORE для
crash helper, способного записать память VMM на диск после exec. Выключенные
swap и crash helpers должны сохраняться всё время работы; runtime не меняет
настройки ОС. В одноразовом CI runner они подготавливаются явно.

Это минимальный backend для BusyBox и статических Linux x86_64 программ из
проекта. Полные динамические Python/Node окружения, интерактивный stdin,
экспорт результатов и автоматическая установка KVM не добавлены. VMM работает
не от root, наследует запрет IP-сокетов и NNP. Jailer/полная файловая песочница
самого VMM ещё не подключены: уязвимость Firecracker/KVM остаётся отдельной
границей доверия. Изоляция гостя не означает, что весь M6 закрыт.

## Проверка

Отдельный обязательный job `linux-microvm` использует настоящий `/dev/kvm`
на Ubuntu runner, закреплённые инструменты и синтетический HTTP endpoint.
Гостевой тест проверяет нормализованное окружение, machine-id, отсутствие
host env, отказ TCP/UDP IPv4/IPv6 и DNS, чтение ответа через Unix/vsock relay
и отсутствие writeback. Отсутствие KVM не превращает job в skip.
Локальная Windows-проверка не считается проверкой KVM.

Реиспользуются уже закреплённые `serde`, `serde_json`, `sha2`, `tempfile`,
`zeroize` и `libc` (последний только в существующей OS-границе nw-platform).
Новых crates/версий нет; Cargo.lock меняет только рёбра своих пакетов.
Новые сторонние cargo-vet exemptions не нужны; существующий cargo-vet gate
остаётся обязательным. Небезопасный код ограничен новым OS-модулем memfd/fd.

Основания: [Firecracker vsock](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/docs/vsock.md),
[initrd](https://github.com/firecracker-microvm/firecracker/blob/v1.18.0/docs/initrd.md),
[memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html).
