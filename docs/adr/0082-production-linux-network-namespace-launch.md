# Production launcher Linux: подготовленный netns и необратимый сброс прав

ADR 0078 подключён к `nymwrapd`: административный coordinator получает заранее
созданный netns и ненулевые UID/GID через фиксированные аргументы запуска.
До Tokio, bootstrap и пользовательских данных проверяется тип fd через
NS_GET_NSTYPE, отвергается текущий namespace и создаётся пустой netns core.
`nw-net::launcher::LinuxNamespace` запускает тот же удерживаемый `nw-netd`
через `Client::spawn_prepared`, затем сбрасывает права coordinator и ставит
seccomp TSYNC. Stdin, эфемерный ключ, точный kernel PID и kill_on_drop сохраняются.

Административная подготовка и обычная desktop-сессия различаются намеренно:
программа не приобретает root, не устанавливает setuid helper и не запускает
sudo. В обычном Linux desktop-запуске без подготовленного namespace доступен
только L0; прежний запуск netd в host network namespace удалён. Доверенный
внешний coordinator должен подготовить маршруты/firewall транспорта, окружение
целевого пользователя и приватный bootstrap pipe, сохранив PID core и перейдя
к тому же пользователю до RPC. Интеграция такого coordinator с GUI и установка
службы этим изменением не добавляются. Ручной запуск из терминала без bootstrap
полномочий не получает. GUI от root запускать не требуется.

Владелец `LinuxNamespace` сбрасывает права и при ошибке exec, отмене future или
раннем выходе. Если необратимый сброс либо seccomp не удался, процесс аварийно
завершается: вернуть ошибку привилегированному обработчику данных нельзя.
Отдельный fd не даёт права на setns после сброса UID; namespace ядро закрепляет
по открытому дескриптору. Файловая изоляция netd остаётся отдельной работой M6.

CI tor-pcap теперь требует два свидетельства. Настоящий `nymwrapd` с настоящими
idle netd/API проверяет namespace всех threads, UID/GID/groups, NNP/seccomp,
недоступность внешнего адреса из core netns, отказ неверной конфигурации и
завершение children по EOF. Отдельный процессный сценарий использует тот же
production launcher и `Client`, настоящий AEAD dispatcher и Tor/TLS/HTTP.
Только worker из `cfg(test)` получает частные authorities, CA и TLS key log;
production бинарник таких переключателей не имеет. Синтетические канарейки
проходят Shield и IPC; circuit IDs записываются с тех потоков, которые несут
HTTP, а pcap сверяется независимым oracle. После остановки релеев требуется
именно AEAD-ответ с ошибкой при живом provider; таймаут не считается успехом.
Полный core/model/approval pipeline этим pcap не проверяется.

Windows предоставляет AppContainer/LPAC, macOS — App Sandbox с сетевыми
entitlements. В текущей поставке core/netd ещё не запускаются в этих профилях;
эквивалентную Linux защиту от IP-сокета из core на этих ОС не заявляем.
Работают проверки IPC и прикладной Tor fail-closed; этого недостаточно для
изоляции скомпрометированного процесса. Нативные Windows workers имеют LPAC,
но его свойства нельзя переносить на core. Новых зависимостей нет.

Основания: [NS_GET_NSTYPE](https://man7.org/linux/man-pages/man2/NS_GET_NSTYPE.2const.html),
[network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
[AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation),
[App Sandbox network.client](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client).
