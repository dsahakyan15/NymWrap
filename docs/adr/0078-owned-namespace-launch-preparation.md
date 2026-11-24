# Подготовка запуска дочернего транспорта в отдельном netns

## Граница решения — интеграция ещё в работе

Для процессного CI-сценария core должен потерять IP-сокеты, а его дочерний
nw-netd — войти в другой заранее созданный namespace. Запуск через sudo/ip
с дополнительным monitor-процессом не даёт права подменить проверку точного
kernel PID на имя файла. Поэтому подготовка netns/UID выполняется в pre-exec
того же сохранённого child. Это административная операция уже привилегированного
coordinator, до обработки данных. Она не приобретает root и не устанавливает
setuid helper или службу на компьютере пользователя.

Client::spawn_prepared принимает команду доверенного launcher с абсолютным
canonical program. Stdin всегда заменяется собственным anonymous pipe; key
остаётся в памяти, stdout/stderr закрыты, child имеет kill_on_drop, IPC проверяет
его kernel PID/liveness. Подключения к произвольному существующему PID нет.
Обычный spawn сохраняет прежний минимальный env и использует ту же реализацию.
Настройка args/env/pre-exec в prepared API принадлежит доверенному коду, не модели.

Linux OS boundary получает owned duplicate fd netns и ненулевые UID/GID.
setns явно требует CLONE_NEWNET. До exec удаляются supplementary groups,
real/effective/saved UID/GID переходят к выбранному пользователю, KEEP_CAPS
выключен и включается NO_NEW_PRIVS. Необычные securebits и UID/GID 0/-1
отвергаются. В child используются прямые syscalls, без блокировок/аллокаций
после fork. В самом coordinator libc setxid wrappers синхронизируют threads;
дополнительно проверяются все три UID/GID. Любая ошибка прекращает переход.
NNP является per-thread: coordinator дополнительно ставит deny_remote_sockets
с seccomp TSYNC до обработки данных. Тест охватывает уже существующий thread,
новый child и kernel отказ вернуть UID/GID 0.

2026-11-25 runtime regression прошёл в одноразовой QEMU/Alpine VM с Linux
6.18.60-0-virt: разные netns cookies, child/coordinator с UID/GID 1000,
пустые supplementary groups, NO_NEW_PRIVS у уже существующего thread, отказ
kernel вернуть root и прочитать root-only канарейку. Неверный namespace fd
не запускает payload; coordinator не может открыть IP-сокет после TSYNC.
Логи target/netns-vm-identity-green.{serial.log,report.json}; teardown выполнен.
Native nw-netd lifecycle отдельно проверил retained child/private bootstrap
prepared launch на Windows. Эти проверки не соединены в полный production
сценарий core/netd. API пока не подключены к production launcher и не считаются
выполнением M2/M6; новый CI остаётся непроведённым.

Основания: [setns](https://man7.org/linux/man-pages/man2/setns.2.html),
[setresuid и threads](https://man7.org/linux/man-pages/man2/setresuid.2.html),
[capabilities и securebits](https://man7.org/linux/man-pages/man7/capabilities.7.html).
