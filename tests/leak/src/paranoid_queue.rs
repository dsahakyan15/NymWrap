// Compiled inside core: these exercise the actual dispatcher and encrypted jobs.
use super::super::queue_tests::{Keys, Model};

const CANARY: &str = "PARANOID_QUEUE_SYNTHETIC_CANARY_63182";

#[test]
fn paranoid_dispatch_requires_individual_approval_l1_and_a_live_single_use_slot() {
    let mut config = Config::for_profile(Profile::Paranoid).unwrap();
    // Disabling automatic decoys cannot disable the mandatory real-request queue.
    assert!(!config.cover.enabled);
    assert!(needs_slot(&config));
    let slot = Slot::new();
    let now = Instant::now();
    // Sleep can advance wall time while monotonic time is suspended. A clock
    // rollback cannot extend a permit either; both cases fail without sleeping.
    assert_eq!(
        slot.check_at(now, slot.wall_deadline),
        Err(CoreError::Queue)
    );
    assert_eq!(
        slot.check_at(now, slot.wall_start - Duration::from_secs(1)),
        Err(CoreError::Queue)
    );
    for actual in [TrustLevel::L2, TrustLevel::L3] {
        assert_eq!(
            check_dispatch(&config, TrustLevel::L3, actual, true, Some(&slot), now),
            Err(CoreError::Trust)
        );
    }
    assert_eq!(
        check_dispatch(
            &config,
            TrustLevel::L1,
            TrustLevel::L1,
            false,
            Some(&slot),
            now
        ),
        Err(CoreError::Approval)
    );
    assert_eq!(
        check_dispatch(&config, TrustLevel::L1, TrustLevel::L1, true, None, now),
        Err(CoreError::Queue)
    );
    // This is a synthetic L1 adapter contract, not an implemented remote route.
    assert_eq!(
        check_dispatch(
            &config,
            TrustLevel::L1,
            TrustLevel::L1,
            true,
            Some(&slot),
            now
        ),
        Ok(())
    );
    assert_eq!(
        check_dispatch(
            &config,
            TrustLevel::L1,
            TrustLevel::L1,
            true,
            Some(&slot),
            slot.deadline
        ),
        Err(CoreError::Queue)
    );
    slot.consume(now).unwrap();
    assert_eq!(slot.consume(now), Err(CoreError::Queue));
    assert_eq!(
        check_dispatch(
            &config,
            TrustLevel::L1,
            TrustLevel::L1,
            true,
            Some(&slot),
            now
        ),
        Err(CoreError::Queue)
    );
    // Neither a caller nor stale weakened config can downgrade the profile floor.
    config.shield.min_trust = TrustLevel::L3;
    assert_eq!(
        check_route(&config, TrustLevel::L3, TrustLevel::L3),
        Err(CoreError::Trust)
    );
    assert_eq!(
        check_route(&config, TrustLevel::L0, TrustLevel::L1),
        Err(CoreError::Trust)
    );
}

fn fixture() -> (tempfile::TempDir, State, Arc<Keys>) {
    let directory = tempfile::tempdir().unwrap();
    let keys = Arc::new(Keys::default());
    let mut w = Workspace::create_with(
        &directory.path().join("queue"),
        SecretString::from("synthetic paranoid passphrase"),
        Profile::Paranoid,
        keys.clone(),
    )
    .unwrap();
    let mut config = w.config.clone();
    config.cover.mean_interval_s = 10;
    config.cover.max_requests_per_day = 1;
    config.net = crate::config::NetConfig {
        transport: crate::config::Transport::Nym,
        provider_host: Some("example.test".into()),
        provider_path: Some("/v1/chat/completions".into()),
        credential_ref: Some("keyring:pool".into()),
        provider_model: Some("synthetic".into()),
        max_request_cost_microusd: Some(1),
    };
    w.save_config(config).unwrap();
    w.set_secrets(vec![SecretRecord {
        kind: nw_shield::SecretKind::Secret,
        value: CANARY.into(),
        local_only: false,
    }])
    .unwrap();
    let state = State::default();
    state.session.lock().unwrap().workspace = Some(w);
    (directory, state, keys)
}

#[tokio::test]
async fn paranoid_unavailable_route_refuses_before_slots_budget_or_network_even_with_stale_l3() {
    let (_directory, state, _keys) = fixture();
    let prepared = nw_shield::Shield::new(vec![])
        .unwrap()
        .prepare(
            "Explain pottery",
            &mut nw_shield::ConversationVault::default(),
            |s| Ok(s.into()),
        )
        .unwrap();
    let body = nw_net::ShapedRequest::new(&prepared).unwrap();
    for transport in [crate::config::Transport::Nym, crate::config::Transport::Tor] {
        let mut config = require(&mut state.session.lock().unwrap())
            .unwrap()
            .config
            .clone();
        config.net.transport = transport;
        // Test the last gate even if an upstream caller supplied weaker requirements.
        config.shield.min_trust = TrustLevel::L3;
        let route = Route {
            state: state.clone(),
            epoch: 0,
            config,
            context: "a".repeat(64),
            required: TrustLevel::L3,
            job: Some("b".repeat(64)),
            slot: Some(Slot::new()),
        };
        assert!(matches!(
            route.send_now("synthetic", &body).await,
            Err(CoreError::Trust)
        ));
        assert!(matches!(
            route.complete("synthetic", &prepared, 32).await,
            Err(CoreError::Trust)
        ));
    }
    assert_eq!(
        super::super::traffic_tick_at(&state, workspace::now())
            .await
            .unwrap_err(),
        "trust_policy_violation"
    );
    let mut session = state.session.lock().unwrap();
    let w = require(&mut session).unwrap();
    assert!(w.traffic_status().unwrap().jobs.is_empty());
    assert!(w.remote_jobs().unwrap().is_empty());
    assert!(state.pending_sends.lock().unwrap().is_empty());
}

#[tokio::test]
async fn paranoid_slots_skip_misses_hold_budget_and_reopen_never_replays_uncertain() {
    use crate::{
        RemoteStep,
        workspace::{RemoteJobState, TrafficPurpose},
    };
    struct FutureL1;
    impl RemoteCompletion for FutureL1 {
        fn trust(&self) -> TrustLevel {
            TrustLevel::L1
        }
        fn context(&self) -> &str {
            "synthetic-l1-contract"
        }
        async fn complete(
            &self,
            _: &str,
            _: &nw_shield::Prepared,
            _: u32,
        ) -> Result<SecretString, CoreError> {
            panic!("no production L1 implementation and no network in this test")
        }
    }
    let (directory, state, keys) = fixture();
    let config = require(&mut state.session.lock().unwrap())
        .unwrap()
        .config
        .clone();
    let shield = require(&mut state.session.lock().unwrap())
        .unwrap()
        .shield()
        .unwrap();
    let engine = crate::link_fixture::configured(Model, shield, &config).unwrap();
    let input = [Message {
        role: nw_llm::Role::User,
        content: format!("Explain pottery for {CANARY}"),
    }];
    let RemoteStep::Review(review) = engine
        .review_remote("new", &input, 32, &FutureL1)
        .await
        .unwrap()
    else {
        panic!("individual review required")
    };
    assert!(!review.transcript.contains(CANARY));
    let approved = engine
        .take_remote_approval(&review.approval_id, &review.hash, &FutureL1)
        .await
        .unwrap();
    assert!(matches!(
        engine
            .take_remote_approval(&review.approval_id, &review.hash, &FutureL1)
            .await,
        Err(CoreError::Approval)
    ));
    let mut w = state.session.lock().unwrap().workspace.take().unwrap();
    let info = w.create_remote_job(&approved, 0).unwrap();
    let at = workspace::now() + 1_000_000;
    assert!(w.take_traffic_slot(at, true).unwrap().is_none());
    assert!(w.take_traffic_slot(at + 9, true).unwrap().is_none());
    assert!(w.take_traffic_slot(at + 10, false).unwrap().is_none());
    // Missing the exact slot cannot turn the next arrival into a send.
    assert!(w.take_traffic_slot(at + 11, true).unwrap().is_none());
    let job = w.take_traffic_slot(at + 20, true).unwrap().unwrap();
    assert!(matches!(job.purpose, TrafficPurpose::Real));
    w.remote_job_sending(&info.id).unwrap();
    w.finish_remote_job(&info.id, Err("remote_transport_unavailable"))
        .unwrap();
    assert!(matches!(
        w.remote_job(&info.id).unwrap().info.state,
        RemoteJobState::Uncertain
    ));
    assert!(w.remote_job_sending(&info.id).is_err());
    w.finish_traffic_job(&job.id, Err("remote_transport_unavailable"))
        .unwrap();
    assert!(w.take_traffic_slot(at + 20, true).unwrap().is_none());
    assert!(w.take_traffic_slot(at + 30, true).unwrap().is_none());
    assert!(
        w.finish_remote_job(&info.id, Err("session_changed"))
            .is_err()
    );
    drop(approved);
    drop(w);
    // The public clock intentionally advanced for deterministic slot tests;
    // reopening a future snapshot fails closed until the wall clock catches up.
    let mut w = Workspace::open_with(
        &directory.path().join("queue"),
        SecretString::from("synthetic paranoid passphrase"),
        keys,
    )
    .unwrap();
    assert!(matches!(
        w.remote_job(&info.id).unwrap().info.state,
        RemoteJobState::Uncertain
    ));
    assert!(w.remote_job_sending(&info.id).is_err());
    assert!(w.traffic_status().is_err());
    drop(w);
    for entry in std::fs::read_dir(directory.path().join("queue")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert!(
                !std::fs::read(path)
                    .unwrap()
                    .windows(CANARY.len())
                    .any(|s| s == CANARY.as_bytes())
            );
        }
    }
}
