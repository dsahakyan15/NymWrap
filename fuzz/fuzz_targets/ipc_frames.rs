#![no_main]
use libfuzzer_sys::fuzz_target;
use nw_proto::{Envelope, Lane};
thread_local! {
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 * 1024 + 4 {
        return;
    }
    for lane in [Lane::Shadow, Lane::Cover] {
        if let Ok(envelope) = Envelope::decode(data, lane) {
            assert_eq!(envelope.lane, lane);
            let other = if lane == Lane::Shadow {
                Lane::Cover
            } else {
                Lane::Shadow
            };
            assert!(envelope.encode(other).is_err());
            let encoded = envelope.encode(lane).unwrap();
            assert!(Envelope::decode(&encoded, lane).is_ok());
        }
        RUNTIME.with(|runtime| {
            runtime.block_on(async {
                let mut reader = data;
                if let Ok(packet) =
                    nw_ipc::read_packet::<serde_json::Value, _>(&mut reader, lane).await
                {
                    assert_eq!(packet.lane, lane);
                    assert_eq!(packet.version, nw_proto::SCHEMA_VERSION);
                }
            })
        });
    }
    RUNTIME.with(|runtime| {
        runtime.block_on(async {
            let mut reader = data;
            if let Ok(frame) = nw_ipc::read_frame(&mut reader, 16 * 1024 * 1024).await {
                if let Ok(packet) =
                    serde_json::from_slice::<nw_ipc::Packet<nw_core::service::Command>>(&frame)
                {
                    let encoded = serde_json::to_vec(&packet).unwrap();
                    assert!(
                        serde_json::from_slice::<nw_ipc::Packet<nw_core::service::Command>>(
                            &encoded
                        )
                        .is_ok()
                    );
                }
            }
        })
    });
    let mut native = data;
    if let Ok(Some(request)) = nw_bridge::read_native(&mut native) {
        assert_eq!(request.version, nw_proto::SCHEMA_VERSION);
        assert_ne!(request.id, 0);
        request.command.validate().unwrap();
        let json = serde_json::to_vec(&request).unwrap();
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&json);
        let decoded = nw_bridge::read_native(&mut frame.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), json);
    }
});
