use super::*;
#[test]
fn legacy_or_missing_source_evidence_cannot_authorize_egress() {
    let fixture = tempfile::tempdir().unwrap();
    let mut workspace = Workspace::create_with(
        &fixture.path().join("coverage"),
        SecretString::from(""),
        Profile::Standard,
        Arc::new(tests::MemoryKeys::default()),
    )
    .unwrap();
    let mut report = nw_probe::Report {
        version: 1,
        lane: nw_proto::Lane::Shadow,
        values: vec![],
        observed: vec![],
        unavailable: vec![],
        hygiene: Default::default(),
    };
    workspace.save_device_probe(Ok(report)).unwrap();
    assert!(!workspace.device_probe_ready().unwrap());
    assert_eq!(
        workspace.device_probe_status().unwrap().unavailable.len(),
        9
    );
    report = nw_probe::Report {
        version: 1,
        lane: nw_proto::Lane::Shadow,
        values: vec![],
        observed: nw_probe::Source::ALL.to_vec(),
        unavailable: vec![],
        hygiene: Default::default(),
    };
    report
        .observed
        .retain(|source| *source != nw_probe::Source::Wifi);
    workspace.save_device_probe(Ok(report)).unwrap();
    assert!(!workspace.device_probe_ready().unwrap());
    assert!(workspace.device_probe_status().unwrap().unavailable == [nw_probe::Source::Wifi]);
    assert!(
        !workspace.device_probe_due().unwrap(),
        "partial results must not cause an automatic retry loop"
    );
    let mut legacy = workspace.device_probe_status().unwrap();
    legacy.coverage_version = 0;
    workspace
        .store
        .put_json(Domain::Vault, "device-probe-status", &legacy, now())
        .unwrap();
    assert!(
        workspace.device_probe_due().unwrap(),
        "an upgrade must refresh legacy coverage without waiting a day"
    );
}
#[test]
fn only_fresh_observations_have_scores_and_encrypted_reopen_preserves_unknowns() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("hygiene");
    let keys = Arc::new(tests::MemoryKeys::default());
    let mut w = Workspace::create_with(
        &root,
        SecretString::from(""),
        Profile::Standard,
        keys.clone(),
    )
    .unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, None);
    let mut hygiene = nw_probe::hygiene::Report::default();
    hygiene.checks[0].verdict = nw_probe::hygiene::Verdict::Pass;
    hygiene.checks[1].verdict = nw_probe::hygiene::Verdict::Fail;
    let report = nw_probe::Report {
        version: 1,
        lane: nw_proto::Lane::Shadow,
        values: vec![],
        unavailable: vec![],
        observed: nw_probe::Source::ALL.to_vec(),
        hygiene,
    };
    w.save_device_probe(Ok(report)).unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, Some(1.0 / 6.0));
    assert_eq!(
        w.overview().unwrap().metrics.hygiene_coverage,
        Some(2.0 / 6.0)
    );
    drop(w);
    let mut w = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, Some(1.0 / 6.0));
    let mut status = w.device_probe_status().unwrap();
    status.last_success = now() + 3600;
    w.store
        .put_json(Domain::Vault, "device-probe-status", &status, now())
        .unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, None);
    status.last_success = now() - 86401;
    w.store
        .put_json(Domain::Vault, "device-probe-status", &status, now())
        .unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, None);
    assert_eq!(w.overview().unwrap().metrics.hygiene_coverage, None);
    // Legacy encrypted records predate these observations. Their absence is not success.
    status.last_success = now();
    let mut legacy = serde_json::to_value(&status).unwrap();
    legacy.as_object_mut().unwrap().remove("hygiene");
    w.store
        .put_json(Domain::Vault, "device-probe-status", &legacy, now())
        .unwrap();
    assert_eq!(w.overview().unwrap().metrics.hygiene_score, None);
}
