# Наблюдения гигиены с явным неизвестным состоянием

Пункты SPEC §4.9.7 получают отдельные состояния Pass/Fail/Unknown. Только
прочитанное и однозначное значение подтверждает пункт; отсутствие доступа,
наследуемое значение, неподдержанный источник и непроведённая проверка остаются
Unknown. Снимок хранится в зашифрованном Vault. hygiene_score — число Pass / 6,
с отдельным покрытием наблюдений; при отсутствии наблюдений значение неизвестно,
а не 100%. Ручная инструкция не подтверждает измерение.

Для WLAN используется `quick-xml =0.42.0` без дополнительных features, закреплённый
checksum в lock и cargo-deny. Прежний поиск SSID по подстроке заменяется строгим
ограниченным разбором XML: namespace/path, единственное поле, без DTD/entities,
лимиты байтов/глубины/событий. Читаются только SSID hex и enableRandomization;
пароли и randomizationSeed не извлекаются. В Windows остаются flags=0 у
WlanGetProfile и прежние capabilities; запрет ОС не обходится.

Основания: [схема Microsoft WLAN v3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpwl/d36f7a68-6219-42d1-a820-70f53098b6ed),
[quick-xml 0.42.0](https://docs.rs/quick-xml/0.42.0/quick_xml/reader/struct.NsReader.html),
[параметры NetworkManager](https://www.networkmanager.dev/docs/api/latest/settings-802-11-wireless.html),
[политика геолокации Windows](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system#allowlocation).
Метрики и UI используют только снимок моложе суток; будущее время и старые
записи без наблюдений дают неизвестную оценку. Проверяются зашифрованное
переоткрытие и сохранение неизвестных пунктов. Полнота наблюдений каждой ОС,
проверка часов и браузера остаются открыты до реализации и зелёного CI.
