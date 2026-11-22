# Канарейки на границе HTTP serializer в nw-netd

## Решение

Внутри Tor::exchange выделен приватный http_exchange, которому единственный
production caller передаёт уже проверенный TLS stream поверх Arti. Установка
цепочки, DNS, TLS roots/SNI, запрет resumption/early data и общий timeout не
изменились. Ни нового транспорта, ни возможности передать stream по IPC нет.
Зависимости и lock остаются прежними.

HTTP helper использует тот же Hyper handshake, builder, тело, credential owner,
чтение ответа и детерминированный parser. Test-only duplex stream позволяет
прочитать фактические сериализованные байты до TLS. Canary module находится в
tests/leak/src/netd_http.rs и включён именно в test target отдельного nw-netd
workspace; обычный сетевой CI запускает его без доступа в интернет.

## Проверки и границы

Для каждой из пяти корзин проверяются точное совпадение тела с ShapedRequest,
Content-Length, отсутствие chunked framing, conversation id и канарейки в
прямом/base64/hex виде. Полный allowlist заголовков исключает неявные Cookie,
User-Agent, proxy и локальные параметры. Тест проходит Shield и формирование
history до реального HTTP serializer. Все данные и ключ синтетические.

Через этот же HTTP helper отдельно проверяются отказы на redirect, gzip,
HTML, tool_calls и ответ больше 1 MiB. Redirect не исполняется. Тестовый сервер
находится в памяти, не открывает сокетов, не пишет содержимое в файлы.

Эта проверка усиливает границу M3, но не равна захвату реальных Tor/TLS пакетов.
TLS overhead, packetization и ритм на выходе ОС здесь не измеряются; критерий
сетевого захвата и непрерывного ритма остаётся открытым.
