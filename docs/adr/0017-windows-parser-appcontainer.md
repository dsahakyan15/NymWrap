# Windows-парсер в AppContainer без сети и записи

## Решение

Импорт Windows запускается через профиль nw-sandbox и Win32-границу nw-platform.
Создаётся новый временный профиль AppContainer с уникальным SID и без capabilities.
Включён ALL_APPLICATION_PACKAGES_OPT_OUT (LPAC): нет общего доступа от имени всех
App Packages. Нельзя открыть хранилище ядра, импортированные исходные файлы или
другие пользовательские каталоги. Свежие каталоги профиля доступны worker только
для чтения; TEMP/TMP указывают внутрь них. Парсеру не нужны файлы для записи.

Код worker копируется как публичный read-only asset в Code этого профиля.
Настоящие данные передаются только через две наследуемые анонимные трубы.
HANDLE_LIST содержит только концы stdin/stdout; DACL труб даёт доступ текущему
пользователю и SID этого запуска, mandatory label — low. Файловая DACL содержит
только пользователя и read/execute SID worker. ACL чужих родительских директорий
и интерактивного desktop не меняется.

Worker использует отдельный невидимый desktop с собственным SID и low label;
нет переключения рабочего стола или доступа к окнам пользователя. Job Object
назначается атомарно при CreateProcess: максимум один процесс, 512 МиБ commit,
KILL_ON_JOB_CLOSE, без breakaway. При падении core последняя ссылка на job
закрывается и worker завершается. Время работы после запуска — 30 секунд;
трубы ограничены по размеру, родитель проверяет exit code, точную длину одного
кадра, схему и содержательные пределы Summary. Отказ не запускает парсер обычным
процессом. CLI audit использует тот же путь, без отдельного прямого парсинга.

Профиль, код и desktop удаляются после завершения worker. Ничего из исходного
экспорта, Summary или vault не записывается в профиль. На неподдерживаемой ОС
без реализованного профиля импорт прекращается (для macOS App Sandbox ещё нужен).

## Win32-совместимость и владение

Дополнительный CHILD_PROCESS_POLICY=RESTRICTED на этой Windows вызывает
STATUS_DLL_INIT_FAILED ещё до main, воспроизводимо даже на минимальном EXE с
одним kernel32. Этот атрибут не применяется. Необходимый запрет потомков
обеспечивает непокидаемый job с ActiveProcessLimit=1; попытка реального spawn
внутри worker проверена. Автоматического ослабления LPAC или job нет.

UpdateProcThreadAttribute сохраняет указатели. Attributes связывает время жизни
с заимствованными SID/массивами/политиками; выделение списка выровнено usize.
Win32 handles, SID, security descriptors, профиль и desktop имеют одного владельца
и освобождаются соответствующими API. В unsafe остаются только OS-границы.

## Проверки

Настоящий Windows-тест запускает probe и проверяет запрет чтения/записи закрытого
fixture, записи TEMP и дочернего процесса. На принимающей стороне TCP и UDP не
получают ничего. LPAC без registryRead может отклонить даже WSAStartup; Rust std
тогда паникует при инициализации сокетов. Probe считает этот отказ закрытым и
независимо проверяет отсутствие пакета. Это не тест всех процессов M6.

Дополнительных пакетов нет: расширены features закреплённого windows-sys 0.61.2;
nw-sandbox использует уже закреплённые nw-platform и zeroize. Первичные контракты:
[AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[атрибуты процесса](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
