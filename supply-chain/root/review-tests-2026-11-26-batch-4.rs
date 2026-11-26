// Synthetic review checks only; no application stores, credentials or network are opened.
#![allow(dead_code)]

#[test]
fn reproduced_broadcast_capacity_bug_stays_unaudited() {
    let (mut sender, _receiver) = async_broadcast::broadcast(1);
    sender.set_capacity(0);
    sender.set_overflow(true);
    for value in 0..32 {
        sender.try_broadcast(value).unwrap();
    }
    assert_eq!(sender.capacity(), 0);
    assert_eq!(sender.len(), 32);
}

#[derive(zvariant::Value)]
struct Pair {
    a: u32,
    b: u32,
}

#[test]
fn reproduced_short_structure_bug_stays_unaudited() {
    let value = zvariant::Value::from(zvariant::Structure::from((7_u32,)));
    assert!(std::panic::catch_unwind(|| Pair::try_from(value)).is_err());
}

#[cfg(windows)]
#[test]
fn loaded_system_symbol_keeps_its_library_borrow_and_calls_the_right_abi() {
    // kernel32 is already loaded; this acquires a reference without loading a new image.
    let library: libloading::Library =
        libloading::os::windows::Library::open_already_loaded("kernel32.dll")
            .unwrap()
            .into();
    {
        let symbol: libloading::Symbol<unsafe extern "system" fn() -> u32> =
            unsafe { library.get(b"GetCurrentProcessId\0") }.unwrap();
        let cloned = symbol.clone();
        assert_eq!(unsafe { cloned() }, std::process::id());
        assert!(matches!(
            unsafe { library.get::<unsafe extern "system" fn() -> u32>(b"Get\0CurrentProcessId") },
            Err(libloading::Error::CreateCString { .. })
        ));
    }
    library.close().unwrap();
}
