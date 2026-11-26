# Nym: SDK не допущен, остаётся отключённый интерфейс

Проверено 2026-11-26. Продолжает ADR 0024. `experimental-nym` оставляет только
интерфейс `nw_net::nym::Nym::initialize`, всегда возвращающий
`transport_unavailable`, и кандидата L1 для проверок допуска zkAPI.
Нет SDK, сетевого connector, файлов ключей, телеметрии или рабочего mixnet.
Флаг выключен по умолчанию; даже его включение не открывает L1.

## Актуальная версия и предел проверки

[Registry metadata nym-sdk](https://crates.io/api/v1/crates/nym-sdk) на дату
проверки сообщает latest/max stable **3.0.1**, опубликованную
`2026-11-26T03:05:15.007750Z`, checksum
`d13fd4376589a7e999c0bcf867b7d1170fbae85a051bcbe31d64a21abe89c409`.
Её feature metadata сохраняет `fs-storage` в default; этот feature включает
файловое хранение credentials, SURB и gateways. `tcp-proxy` тоже включает
`fs-storage`; `sqlcipher` отдельный opt-in. Само включение дискового feature
не доказывает запись незашифрованных ключей, а opt-in SQLCipher не доказывает
шифрование всех видов состояния.

Исходный архив 3.0.1 по registry `/download` и static.crates.io вернул HTTP 500;
docs.rs для этой версии не дал исходников. Поэтому исправление хранения ключей
и телеметрии в **3.0.1 не подтверждено**. Проверка ниже относится к доступному
исходному коду **3.0.0**, а не переносится на новую версию:

- `nym-sdk/src/mixnet/client.rs`: `new_ephemeral` использует in-memory storage;
  отдельно доступны persistent storage и `with_statistics_reporting`.
- `nym-client-core-config-types/src/lib.rs`: `StatsReporting::default()`
  задаёт `enabled: true`, `provider_address: None`. Без collector-адреса
  отправки статистики нет; это не явный запрет телеметрии при иной конфигурации.
- `nym-sdk/src/ipr_wrapper/ip_mix_stream.rs` создаёт клиент внутри IPR API;
  прямой проверенный путь передачи ephemeral builder с отключённой статистикой
  для выбранного smolmix/IPR-пути ADR 0024 не подтверждён.

Первичные ссылки для повторной проверки: [3.0.1 package](https://crates.io/crates/nym-sdk/3.0.1),
[3.0.0 builder](https://docs.rs/crate/nym-sdk/3.0.0/source/src/mixnet/client.rs),
[3.0.0 StatsReporting](https://docs.rs/crate/nym-client-core-config-types/3.0.0/source/src/lib.rs),
[3.0.0 IPR](https://docs.rs/crate/nym-sdk/3.0.0/source/src/ipr_wrapper/ip_mix_stream.rs).
Ранее найденные ADR 0024 проблемы транзитивного графа не объявляются исправленными:
для 3.0.1 cargo-deny и cargo-vet не запускались, сетевые обещания не проверялись.

## Решение и последующий SDK-эксперимент

Безопасная для наших инвариантов версия **не подтверждена**; это не утверждение,
что все версии SDK небезопасны. По разрешённому минимальному варианту SDK не
добавлен. Root, netd, desktop и fuzz сохраняют зависимости и Cargo.lock.

Если квалификация станет возможной, SDK с большим графом разрешён только в
отдельном `experimental/nym-transport` workspace со своим Cargo.lock, явно
исключённом из root workspace и сборки по умолчанию. Он **не проходит текущий
cargo-vet четырёх выпускных графов и не поставляется**. Такой workspace в этой
задаче не создаётся: пустой SDK-проект не подтвердил бы безопасность. Связь с
основным кодом — только существующая граница nw-netd/`experimental-nym`, без
внешнего демона с самостоятельной сетью.

До подключения нужны закреплённый проверенный архив/граф, deny/vet, явные
ephemeral storage и запрет stats, проверка отсутствия записей ключей и логов
с содержанием, DNS только через транспорт, fail-closed без прямого fallback,
изоляция разговоров, канарейки, проверка cover-трафика и соединение на синтетике.
До этого Nym не отображается как доступная защита.
