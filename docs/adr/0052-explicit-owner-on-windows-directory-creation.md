# Явный владелец новых каталогов Windows

CI с административным токеном создал временный каталог с владельцем
Administrators. Проверка private_directory верно отказала с
foreign_directory_owner. При создании отсутствующих каталогов хранилища и PT
теперь используется CreateDirectoryW с SECURITY_ATTRIBUTES: текущий SID как
владелец и защищённый DACL только для него. Это исключает зависимость от
TokenDefaultOwner и промежуток с унаследованным публичным доступом.

Владелец существующего каталога не меняется: прежний отказ сохраняется.
Reparse points и относительные пути не принимаются. Регрессия проверяет
создание вложенных каталогов и отказ для ссылки/файла; настоящий PT проверяется
отдельно на Windows runner. До зелёного CI ошибка не считается закрытой.

Основание: [CreateDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).
