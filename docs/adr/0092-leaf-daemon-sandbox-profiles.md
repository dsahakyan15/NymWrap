# Профили API, модели и native host в nw-sandbox

`nw-sandbox/profiles/daemons.json` фиксирует отдельные shadow-профили API и
модели и cover-профиль native host. Во всех трёх запрещены внешняя сеть и
дочерние процессы. Ошибка настройки завершает запуск, обходного запуска нет.
Новых внешних зависимостей нет: используются уже закреплённые tokio,
serde_json, windows-sys и libc; внутренние зависимости связывают launcher и
проверку удерживаемого процесса. В windows-sys включена только возможность
RemoteDesktop для чтения номера текущей Windows-сессии.

Windows запускает LPAC с атомарно назначенным Job Object:
ActiveProcessLimit=1 и KILL_ON_JOB_CLOSE. Бинарник копируется в закрытый
каталог профиля; пакетное хранилище и Temp остаются недоступны для записи.
GGUF выдаются только дублированными read-only handles без доступа к каталогу;
на время жизни handle запрещено совместное открытие модели на запись.
Модель сохраняет одноразовый жизненный цикл ADR 0029: новый процесс на каждый
Probe/Complete/Embed, предел 240 секунд и 8 GiB. Бывший обычный HTTP-брокер
не запускается: core удерживает только read-sharing handles и типизированный
Rust-шаблон запуска. Native GGUF-код в core не линкуется. Единственный bounded
shadow-кадр передаётся по private stdio; reply проверяется после успешного
завершения worker. Отмена запроса, timeout и отзыв сессии уничтожают job.
Одновременные запросы ограничены; background уступает foreground. Нет повторного
использования native контекста между запросами и fallback к HTTP endpoint.
LPAC не получает internet/location/Wi-Fi capabilities. До приёма данных
AccessCheck проверяет отказ AAP-only ACL; положительный контроль в обычном
AppContainer обязан разрешить тот же доступ. Зарезервированный запрос
TokenIsLessPrivilegedAppContainer не используется: на Windows 11 он возвращает
ERROR_INVALID_PARAMETER. Для каждого выданного
named pipe выводится отдельный capability SID; общий ALL APPLICATION PACKAGES
в ACL не добавляется. Сохраняются проверка владельца, kernel PID и AEAD core RPC.

Windows виртуализирует LOCAL-pipes в AppContainerNamedObjects. Поэтому
listener имеет стабильный профиль, определённый логическим endpoint внутри
уникального namespace экземпляра. Клиент вычисляет физический путь через SID
этого профиля и номер Windows-сессии. Эксклюзивный нулевой lock-файл
сериализует владельцев профиля; старую регистрацию после crash можно удалить
только при удержании этого lock. Процесс удерживается Win32 handle, а не
поиском PID по имени. Наличие старого endpoint не авторизует новый процесс.

Linux использует bwrap с отдельными mount/user/network/IPC/UTS/cgroup
namespaces и без capabilities. Видны публичные системные библиотеки,
закреплённый бинарник, явно переданные read-only модели и сокеты. Listener
пишет только в отдельный пустой приватный каталог; data/store не монтируется.
`/proc`, `/sys`, домашняя папка, D-Bus и остальные IPC отсутствуют. PID namespace
пока общий с core: иначе SO_PEERCRED обнуляет PID внешнего родителя, нарушая
существующую аутентификацию. Компенсации — отсутствие procfs и seccomp-запреты
ptrace/process_vm/pidfd, сигналов чужим процессам и создания процессов.

Первый BPF передаётся bwrap через sealed memfd и действует до первого exec.
До runtime и входных данных демон добавляет необратимый seccomp TSYNC,
запрещающий также execve. clone разрешён только для потоков без новых
namespaces; clone3 возвращает ENOSYS для штатного fallback libc. Удерживаются
monitor bwrap, status socket и pidfd payload: IPC сверяется с PID payload,
завершение payload не превращается в право подключиться к повторно занятому PID.

Native host, который запускает браузер, оставляет снаружи только ограниченный
по размеру кадров stdio-переходник. Разбор команд и cover IPC выполняет
изолированный дочерний процесс. Этот переходник и общие core/netd не считаются
выполнением требования «каждый процесс»: M6 остаётся открытым. Production
Linux netns launcher ADR 0078/0082 и изоляция PT ADR 0085 не заменяются.

Проверки ОС находятся в `tests/leak/src/daemon_sandbox.rs`: отдельный
отрицательный тест каждого профиля, разрешённый IPC и совпадение PID,
недоступность shadow IPC для cover-профиля. Они обязательны в Windows/Linux CI.

Основания: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[named objects](https://learn.microsoft.com/en-us/windows/apps/develop/communication/sharing-named-objects),
[capability SID](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-derivecapabilitysidsfromname),
[bwrap status](https://github.com/containers/bubblewrap/blob/main/bwrap.xml).
