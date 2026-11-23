# Дочерний процесс как удостоверение model peer

Linux ограничивает чтение /proc/PID/exe через ptrace-проверку. PR_SET_DUMPABLE=0
сохраняет защиту памяти, но мешает прежней проверке пути образа у отдельного
nw-llmd. Kernel PID без удерживаемого child handle недостаточен из-за повторного
использования PID. Источники: [proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html),
[PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html),
[ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Доверенный launcher уже владеет Child запущенного бинарника. UnixModel получает
weak receipt этого объекта, проверяет живость и kernel peer PID до HTTP-тела.
Завершившийся/reaped child и исчезнувший владелец всегда отвергаются; fallback
к пути образа после отказа receipt отсутствует. Receipt нельзя передать через
RPC как PID или строку. Внешний ручной режим сохраняет проверку образа и её
fail-closed ограничения. PR_SET_DUMPABLE остаётся нулём, дополнительные права
процессу не выдаются. Целостность установленных бинарников — отдельный пункт M6.

Core сохраняет receipt для Engine, persona/планов, Mirror и синтеза приманок.
Старт нового worker обновляет Engine и инвалидирует старые разрешения; изменение
endpoint завершает прежний managed worker. Это не исправляет открытую авторизацию
входящего shadow RPC против другого процесса того же пользователя.

В evaluator worker запускает сам Rust parent с той же схемой receipt. План
запуска поступает по stdin, технические пути не сохраняются в отчёте. Временный
encrypted Workspace находится внутри каталога supervisor: его удаляет и Rust
при нормальном выходе, и Node после наблюдаемого завершения дочернего процесса.
Регрессии проверяют чужой процесс с тем же образом, исчезнувшего владельца,
отсутствие передачи канарейки и сохранение недоступности /proc у hardened child
на unprivileged Linux. Применение к вложенным launcher требует отдельного receipt;
несовпадение PID не ослабляет проверку.
