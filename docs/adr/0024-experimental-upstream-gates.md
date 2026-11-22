# Границы подключения экспериментальных upstream

## Проверено 2026-11-22

Ветка zkAPI из SPEC закреплена на
`0fb263b0da04986cfe5c63b12340c1581018ae9b`. Её
[LOCAL_PROTOCOL_MIGRATION](https://github.com/vbuterin/zkapi/blob/0fb263b0da04986cfe5c63b12340c1581018ae9b/zkapi-clientd/docs/LOCAL_PROTOCOL_MIGRATION.md)
указывает `not_deployed` для обеих поставляемых сетей и отсутствие production
ceremony keys. Старые vault, dev-setup и фикстуры не заменяют эти активы.
Поэтому рабочие L1/L2 и финансовый жизненный цикл этой версии ещё не проверяемы.
Программа не запускает funding, не подписывает транзакции и не обещает zkAPI.

Проверены опубликованные Apache-2.0 `nym-sdk =3.0.0` и `nym-smolmix =3.0.0`,
соответствующие официальному [smolmix API](https://nym.com/docs/developers/smolmix).
Изолированная dependency-проба вне рабочего графа выявила:

- smolmix включает default features SDK, в том числе дисковое хранение;
- IpMixStream создаёт MixnetClient внутри и не принимает настроенный builder;
- StatsReporting по умолчанию enabled, хотя без provider_address отправки нет;
- cargo-deny отвергает выбранный граф: rustls-webpki 0.101.7, rustls 0.21,
  crypto-bigint 0.5.5 и libsqlite3-sys 0.30.1. Среди кодов проверены
  RUSTSEC-2026-0098/0099/0104/0258/0346/0349/0382/0387/0459.

## Решение

Эти пакеты пока не добавлены в рабочие manifests/locks и не включают Nym в UI.
Требуются узкий upstream patch для builder/telemetry/ephemeral storage и
обновление уязвимых транзитивных пакетов, затем зелёный deny, канареечные тесты,
проверка отсутствия прямого DNS/fallback и настоящее соединение без средств
пользователя. Подключение внешнего демона с собственной сетью не заменяет
инвариант «выход только через nw-netd». M7 остаётся незавершённым.

Проба и её журналы лежат только в игнорируемом target; новых зависимостей
производственной программы это решение не вводит.
