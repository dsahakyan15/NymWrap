# Чтение GGUF по уже открытому read handle

## Решение

На Windows native loader должен работать в LPAC без доступа к каталогу
пользователя. Вместо копий GGUF на диск или выдачи прав на родительские каталоги
используем уже открытый read handle. Публичный upstream C API
llama_model_load_from_file_ptr присутствует в закреплённом llama.cpp.

Узкий patch llama-cpp-2 0.1.161 добавляет safe load_from_open_file. В model/sys
маленький CRT bridge дублирует handle, создаёт read/binary FILE* и закрывает
только копию. Native parser читает синхронно из начала файла; mmap/direct IO
выключены, явный mlock сохраняется. Модель не меняет representation; алгоритмы
GGUF, inference, grammar и sampler остаются upstream. Другой filename или
файловые права не требуются. Проверка SHA-256 до/после загрузки сохраняется.

## Происхождение и проверки

В vendor/llama-cpp-2 записаны commit, исходная версия и проверенный архивный
SHA-256, приложены лицензии. Build dependency cc =1.11.3 уже присутствует в
проверяемом lock; новых внешних пакетов или версий нет. cfg common импортов
исправлен для сборки с отключёнными default features. Локальный package hash
попадает в source SBOM, cargo-deny применяется к новому графу.

Первый критерий — настоящий CPU/NER/embedding тест через FILE*; следующий —
запуск загрузчика в LPAC с унаследованными только двумя read handles и stdio.
Сам bridge ещё не является файловой изоляцией брокера или доказательством M6.
