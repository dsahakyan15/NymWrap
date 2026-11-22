use super::*;
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
