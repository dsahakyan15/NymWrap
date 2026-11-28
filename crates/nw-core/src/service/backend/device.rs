use super::*;
pub(in crate::service) fn device_probe_status(
    state: &State,
) -> Result<workspace::DeviceProbeStatus, String> {
    let mut session = state.session.lock().map_err(|_| "session_unavailable")?;
    require(&mut session)?.device_probe_status().map_err(code)
}
pub(in crate::service) fn maybe_device_probe(state: &State) {
    let Ok(gate) = state.probe_start.clone().try_lock_owned() else {
        return;
    };
    let epoch = {
        let Ok(mut session) = state.session.lock() else {
            return;
        };
        let epoch = session.epoch;
        if session.in_tail() {
            return;
        }
        let Some(w) = session.workspace.as_mut() else {
            return;
        };
        if !matches!(w.device_probe_due(), Ok(true)) {
            return;
        }
        epoch
    };
    let state = state.clone();
    tokio::spawn(async move {
        let _gate = gate;
        let _ = collect_device_probe(&state, epoch).await;
    });
}
/// Runs a due probe before open_workspace reports the space as unlocked. A
/// first probe that adds device secrets rebuilds Shield and advances the epoch;
/// in the background it cancelled the user's first import, research or plan as
/// session_changed. The result is recorded in the probe status either way, and
/// device_probe_ready still gates remote sends.
pub(in crate::service) async fn probe_if_due(state: &State) {
    let _gate = state.probe_start.lock().await;
    let epoch = {
        let Ok(mut session) = state.session.lock() else {
            return;
        };
        let epoch = session.epoch;
        if session.in_tail() {
            return;
        }
        let Some(w) = session.workspace.as_mut() else {
            return;
        };
        if !matches!(w.device_probe_due(), Ok(true)) {
            return;
        }
        epoch
    };
    let _ = collect_device_probe(state, epoch).await;
}
pub(in crate::service) async fn run_device_probe(
    state: &State,
) -> Result<workspace::DeviceProbeStatus, String> {
    let _gate = state.probe_start.lock().await;
    let epoch = {
        let mut session = state.session.lock().map_err(|_| "session_unavailable")?;
        require(&mut session)?;
        session.epoch
    };
    collect_device_probe(state, epoch).await
}
async fn collect_device_probe(
    state: &State,
    epoch: u64,
) -> Result<workspace::DeviceProbeStatus, String> {
    {
        let mut session = state.session.lock().map_err(|_| "session_unavailable")?;
        if session.epoch != epoch {
            return Err("session_changed".into());
        }
        require(&mut session)?.begin_device_probe().map_err(code)?;
    }
    let report = crate::probe_worker::collect().await;
    let mut session = state.session.lock().map_err(|_| "session_unavailable")?;
    if session.epoch != epoch {
        return Err("session_changed".into());
    }
    let changed = require(&mut session)?
        .save_device_probe(report)
        .map_err(code)?;
    if changed {
        state.invalidate(&mut session);
        refresh_engine(&mut session)?;
    }
    require(&mut session)?.device_probe_status().map_err(code)
}
