# Владелец новых объектов API Windows

Минимальная CI-регрессия создания одного AppContainer воспроизвела
appcontainer_profile_acl:foreign_directory_owner за 0,02 с без запуска worker
(run 45090415120, job 137418461882). Явного владельца у CreateDirectoryW недостаточно:
папки профиля создаёт Windows API. Перед его вызовом процесс задаёт TokenOwner
равным TokenUser через SetTokenInformation и проверяет результат. Это выбирает
SID из уже имеющегося токена; группы, привилегии и capabilities не добавляются.
Владелец и ACL существующих файлов не заменяются. При запрете ОС функция
отказывает; повышения прав и fallback к чужому владельцу нет.

Независимый child-test проверяет, что изменение остаётся в дочернем процессе
и не меняет токен родителя. Исходная регрессия и отрицательные AppContainer
проверки остаются обязательными в CI; до их зелёного результата гипотеза не
считается подтверждённым исправлением.

Та же короткая проверка прошла на hosted Windows runner в
[run 45091002400, job 137420285407](https://github.com/dsahakyan15/NymWrap/actions/runs/45091002400/job/137420285407):
область токена, свежий профиль и три отрицательных AppContainer-теста. Это
подтверждает исправление исходного отказа; остальные критерии M6 остаются открыты.

Основания: [TOKEN_OWNER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner),
[SetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation).
