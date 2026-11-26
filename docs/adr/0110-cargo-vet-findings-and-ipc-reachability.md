# ADR 0110 — recvmsg: достижимость дефекта и оставшиеся решения cargo-vet

Дата: 2026-11-26. Статус: scoped recvmsg exception принят для текущего кода;
остальные находки **требуют человеческого решения**. Проверено агентом, не человеком.
Графы: root и desktop. Связанные решения: ADR 0102, 0104, 0109.

## recvmsg 1.0.0

Удалено `[[trusted.recvmsg]]` из root/audits.toml: доверие на основании README
не отвечает воспроизведённой ошибке владения. Архив SHA-256:
`d3edd4d5d42c92f0a659926464d4cce56b562761267ecf0f469d85b7de384175`.

Повторно запущен `node supply-chain/desktop/review-tests-2026-11-26-desktop-5.mjs`.
LedgerOwner намеренно не освобождает 32-байтную синтетическую allocation, а считает
nonempty Drop. Результат try_extend_lifetime: **1 преждевременный, 2 всего Drop**.
Для настоящего Vec это риск use-after-free/double-free. Освобождённая память не
читалась, UB не исполнялось; Miri/ASan не запускались. `make_owned` вызывает
try_extend_lifetime, поэтому тоже входит в запрещённый путь. Upstream recvmsg
не объявляется исправленным или безопасным в целом.

Прослежен текущий исполняемый путь:

1. В root и desktop обратное дерево показывает
   `recvmsg 1.0.0 <- interprocess 2.4.9 <- nw-ipc`. Других прямых пользователей
   interprocess/recvmsg в crates/ и app/src-tauri нет.
2. nw-ipc экспортирует `local_socket::tokio::Stream` и создаёт local Listener;
   platform helpers работают только с ACL, именами и peer credentials.
   `read_frame_timeout` ограничивает length, создаёт `Zeroizing<Vec<u8>>` и
   передаёт **заимствованный срез** в AsyncReadExt::read_exact. Этот Vec не
   передаётся во владение recvmsg. HTTP/RPC используют тот же AsyncRead stream.
3. В Windows local_socket/tokio/stream.rs выбирает
   `DuplexPipeStream<Bytes>`, listener — `PipeListener<Bytes, Bytes>`.
   AsyncRead для Bytes вызывает RawPipeStream::poll_read_readbuf, затем
   Tokio try_read_buf(ReadBuf) и poll_read_ready. Это не MsgBuf.
4. На Linux/macOS local socket — Tokio UnixStream; poll_read вызывает
   try_read_buf с ReadBuf. Split halves сохраняют тот же byte-stream путь.
5. MsgBuf/RecvMsg в interprocess находятся в отдельных message-mode impl для
   `PipeStream<Messages, Sm>`. Наш код их не конструирует и не вызывает.
   В прочитанных interprocess sources нет вызовов recvmsg try_extend_lifetime
   или MsgBuf::make_owned. Одноимённый MaybeArc::try_make_owned — другой тип.

Поэтому ошибочная операция владения **не вызывается текущим кодом**, хотя crate
остаётся скомпилированной зависимостью. В обоих config.toml добавлено по одной
version-specific exemption с **одинаковым текстом**, точным путём и отменой при
изменении nw-ipc/framing/LocalStream, любом новом caller/dependency edge,
message/datagram API, owner conversion, значимых features/platforms или версий
interprocess/recvmsg. Перед продлением нужны новый path review и ledger probe.
Это исключение конкретного deployment, не safe-to-deploy аудит пакета.
Замена interprocess и патч unsafe recvmsg сейчас не нужны. Код nw-ipc не изменён.
Wrapper по-прежнему запрещает любые exemptions, gate остаётся красным.

Исходники, hashes, обратные деревья и результаты:
[review-2026-11-26-dep-fixes.json](../../supply-chain/root/review-2026-11-26-dep-fixes.json).

## Требует человеческого решения

В перечисленных ниже зависимостях версии, код, trust/audit и exemptions **не
меняются** этой задачей. Оценка риска относится к нашему пути, а не ко всему пакету.

| Находка | Наш путь и риск | Решение человека |
|---|---|---|
| serialize-to-javascript / -impl 0.1.2 | Template повторно заменяет `__TEMPLATE_b__` внутри уже сериализованного поля; стенд снова дал SyntaxError. Доказаны порча JS/DoS, не выполнение внедрённого кода. Недоверенные summary/history/model replies действительно проходят Tauri IPC, но callback format_callback.rs использует прямой Serialized::new для крупных JSON, raw JSON для коротких значений. В проверенных многоэлементных init Templates — фиксированный JS, OS/command constants, случайный invoke key; недоверенные значения NymWrap туда не подставляются. Нативных eval/initialization_script с пользовательским текстом в app нет; capabilities permissions=[] не включают event/path команды. Полная недостижимость во всех Tauri features не доказана. Текущий риск низкий/средний, потенциальный XSS не исключается без дополнительного review. | Проследить оставшиеся Tauri templates/features, выбрать upstream fix/update или локальный патч; новый шаблон с недоверенными полями требует повторного анализа. |
| vswhom 0.1.0 / vswhom-sys 0.1.3 | Windows build tool discovery. Реестр возвращает байты, native код использует длину как wchar_t index: source finding OOB. Только сборка, пользовательские данные runtime туда не передаются; риск средний для машины сборки, потенциально высокий при атаке на окружение build. ASan/эксплуатация не проверялись. | Исправление/обновление или дальнейший native review; не выдавать source audit только за Rust wrapper. |
| sqlcipher-src 420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2 | Активный шифрующий native storage, инвариант 4: высокий риск последствий. Уточнённое происхождение компонентов из desktop-5 и root-6 не заменяет аудит C; полное воспроизводимое восстановление amalgamation и C review не завершены. | Native security review/regeneration или обоснованная замена; не ослаблять шифрование и не заменять SQLCipher обычным SQLite. |
| llama-cpp-2 / llama-cpp-sys-2 0.1.161 | Native parser/FFI, модель — недоверенный вход. Совпадение с commit есть, соответствующий официальный release-tag не подтверждён; sys build.rs в dynamic-link режиме hard-links DLL за пределами OUT_DIR. Наш nw-llmd использует default-features=false и CPU; спорная dynamic-link ветка сейчас не выбрана. Rust/FFI и текущий local FILE bridge полностью не аудированы. Риск средний/высокий, build containment требует отдельной проверки. | Принять/отклонить development snapshot после review, выбрать release, решить судьбу DLL output и проверить sandbox/toolchain. |
| libdbus-sys 0.2.7 | Сетевой fallback `git submodule update --init vendor/dbus` при отсутствии vendor/dbus/dbus. В точной проверенной поставке каталог присутствует; наш vendored путь не выбирает fallback. Guard ADR 0109 проверяет prerequisite перед CI build. Нет Linux no-network execution evidence; `--offline` не изолирует build scripts. Риск низкий при полных inputs, высокий при повреждённом vendor input без sandbox. Native C всё ещё отдельно. | Удаление fallback/upstream update либо отдельное решение о герметичной сборке. Проверка текущей недостижимости не является аудитом fallback. |
| openssl-sys 0.9.118 | В Rust ERR_GET_REASON для system errors возвращается ERR_LIB_SYS (=2), native OpenSSL возвращает reason bits/system errno. Прочитаны err.rs и наши DH/derive/HKDF/cipher callers: они проверяют Result/FFI return codes и не вызывают reason_code/ERR_GET_REASON для решений. SQLCipher вызывает native C, сетевой TLS — rustls в netd. Непосредственного ослабления проверки ключа/расшифрования здесь не найдено; низкий текущий риск неверной классификации/диагностики ошибок, потенциально средний для будущих callers. | Подтвердить исправление/обновление либо точечный upstream patch; доверие к openssl wrapper не закрывает известный дефект openssl-sys. |
| libsqlite3-sys 0.40.0 (открытый root gap) | Дополнительный существующий пробел root-6: generated ABI/WASI VFS review не завершён, найденный SQLCipher C review не закрывает весь FFI слой. Наш путь — bundled SQLCipher, не WASI. Риск высокий по последствиям для storage, текущий дефект не заявляется. | Завершить native/ABI review отдельно; не добавлять доверие лишь ради зелёного cargo-vet. |

Изменения для первых двух находок не разрешают релиз остальных зависимостей.
Перечень не заменяет отчёты ADR 0102/0104 и полный threat-model checklist.
