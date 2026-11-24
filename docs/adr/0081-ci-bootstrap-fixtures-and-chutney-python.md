# CI: авторизованный родитель core и совместимость Chutney

## Причина

Публичные runs 45482671411 и 45489021996 выявили устаревшую Firefox native
fixture после ADR 0076 и несовместимость закреплённого Chutney с Python runner.
Непосредственный запуск `nymwrapd` без bootstrap и отдельный `nymwrap rpc`
больше не имеют полномочий desktop-сессии. На свежих release-компонентах
это воспроизведено локально как `fixture_core_start_failed`.

## Решение

Native fixture использует отдельный Cargo example `native_browser_fixture`,
исходник которого находится в tests/leak. Он запускает настоящий release core
через production `Client::spawn_daemon`, удерживает parent pipe и выполняет
ограниченный набор команд синтетического теста через аутентифицированный RPC.
JSON-строки ограничены 4096 байтами, буферы зануляются. Bootstrap, проверка
точного PID, challenge и AEAD не подменяются. Example не входит в runtime bins
и не копируется в desktop-комплект. Ключи не передаются Node-процессу, в argv,
окружение или файлы. Артефакт Firefox содержит хеши helper и его исходника.

Диагностика macOS в 45491843655 уточнила RPC-сбой: второй запуск не получает API.
При обычном завершении core Drop принудительно убивал API, не давая ему удалить
Unix socket; Windows named pipes этого остатка не имеют. Core теперь закрывает
parent pipe API и до собственного выхода ожидает завершение retained child
не более пяти секунд. При ошибке Drop по-прежнему принудительно завершает тот
же child. Файлы чужих/существующих endpoints не удаляются, разрешения и
авторизация не ослабляются. Исходный actual_ regression уже проверяет повторный
запуск после Lock, а также окончание следующей сессии при потере parent pipe.

Для tor-pcap выбран Python 3.12.16 из setup-python v6, закреплённого SHA
ece7cb06caefa5fff74198d8649806c4678c61a1. Абсолютный python-path передаётся
через явный `PYTHON` в очищенное окружение relay netns; версия проверяется
до запуска и записывается в tools.txt вместе с версиями системных Tor tools.

Run 45491843655 показал, что одного Python 3.12 недостаточно: Chutney импортирует
удалённый `asyncore` через `Traffic`. Минимальный tracked patch удаляет ровно
неиспользуемый `import chutney.Traffic` из TorNet.py. `scripts/chutney_tests/verify.py`
уже импортирует Traffic самостоятельно; его реализация не меняется. Текущий
сценарий использует только configure/start/stop Chutney, а реальную передачу
проверяют production Tor::send и независимый pcap oracle (ADR 0064).
Патч применяется только к чистому checkout commit
62b54a55215c94eb14adc22c5acd17b2ada04b76 с `git apply --check`; затем проверяется
импорт TorNet. SHA-256 патча входит в tools.txt. Новых Python-пакетов нет.

После старта релеев run 45493086233 выявил ещё и старый формат authorities в
Chutney arti.toml. Test-only загрузчик переводит его список name/v3ident в
AuthorityContacts Arti 0.48: v3idents и пустые uploads/downloads/votes.
Fallback caches остаются ровно из локальной конфигурации Chutney. Регрессия
строит настоящий TorClientConfig и проверяет отсутствие публичных directory
defaults; production Tor constructor не меняется.

Run 45494924136 уточнил следующий отказ: ранний consensus содержал лишь четыре
authority, все с reject-all, и Arti не находил exit для 443. Перед клиентским
сценарием теперь обязателен штатный Chutney wait_for_bootstrap, включая проверку
descriptor readiness всех узлов. Предел подготовки сети — 180 секунд; отказ
не пропускается и отправка не повторяется. Namespace/firewall, 16 запросов,
канарейки, пять корзин, разные circuits и fail-closed oracle не меняются.

В 45495540470 настоящий Tor/TLS/HTTP-тест уже прошёл, но tshark отказал при
чтении pcap из /home/runner: AppArmor образа Ubuntu 26.04 разрешает user-tmp,
но не этот путь (runner-images #15310). Анализ получает байт-в-байт сверенные
копии двух pcap и синтетических TLS session keys в mktemp-каталоге /tmp с 0700.
Результаты возвращаются в исходную fixture и проходят прежний oracle. AppArmor
не отключается и не расширяется; каталог анализа удаляется проверенным teardown.

Повторный run 45503174436 выявил IPv6 router solicitation: fe80::/64 → ff02::2
от ядра одного veth. IPv4-only fixture теперь выключает IPv6 all/default/interface
только внутри обоих созданных namespace до поднятия интерфейсов и проверяет
sysctl обратно. Хостовые настройки не меняются. Oracle всё так же отвергает
любой IPv6-пакет; отдельный отрицательный тест фиксирует этот случай.

Core matrix использует fail-fast=false: ошибка одной ОС больше не отменяет
проверки остальных. Все задания и отрицательные проверки остаются обязательными;
dependency-audits не изменены. Это исправление CI не закрывает этапы SPEC.

Тот же run выявил WSAEACCES при создании UDP-приёмника AppContainer fixture:
она повторно использовала номер TCP-порта, не выделенный ОС для UDP. Теперь
Windows выделяет каждый порт отдельно, адреса передаются probe независимо.
Перед запуском sandbox проверяется положительная TCP/UDP-доставка; затем
требование отсутствия пакетов от confined child сохраняется. Настройки ОС,
ACL и capabilities не меняются.

## Проверка

2026-11-25 run [45503957290](https://github.com/dsahakyan15/NymWrap/actions/runs/45503957290)
для кода c337c22 завершил успешно все 16 jobs вне dependency-audits, включая
core/network трёх ОС, настоящий Tor/OS pcap и Firefox native с release core.
Четыре cargo-vet jobs остаются красными и не менялись. Это не закрывает M6
или production-интеграцию namespace/full core pipeline, отсутствующую в pcap.

Основания: [удаление cgitb в Python 3.13](https://docs.python.org/3.13/whatsnew/3.13.html#removed-modules-and-apis),
[удаление asyncore в Python 3.12](https://docs.python.org/3.12/library/asyncore.html),
[tshark на Ubuntu 26.04](https://github.com/actions/runner-images/issues/15310),
[закреплённый Chutney](https://github.com/torproject/chutney/tree/62b54a55215c94eb14adc22c5acd17b2ada04b76).
