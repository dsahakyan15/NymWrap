#[tokio::test]
async fn experimental_zkapi_uses_existing_admission_but_never_spends_or_falls_back() {
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
    let mut candidates = vec![(crate::config::Transport::Tor, TrustLevel::L2)];
    if cfg!(feature = "experimental-nym") {
        candidates.push((crate::config::Transport::Nym, TrustLevel::L1));
    }
    for (transport, level) in candidates {
        let mut config = require(&mut state.session.lock().unwrap())
            .unwrap()
            .config
            .clone();
        config.net.transport = transport;
        config.net.credential_ref = Some(nw_net::zkapi::CREDENTIAL_REF.into());
        config.validate().unwrap();
        assert_eq!(Route::candidate_trust(&config), level);
        // L2 can join strict admission; paranoid retains its L1 floor.
        assert_eq!(
            check_route(&config, TrustLevel::L1, level).is_ok(),
            level == TrustLevel::L1
        );
        config.profile = Profile::Strict;
        config.shield.min_trust = TrustLevel::L2;
        assert_eq!(check_route(&config, TrustLevel::L2, level), Ok(()));
        assert_eq!(
            check_dispatch(&config, TrustLevel::L2, level, false, None, Instant::now()),
            Err(CoreError::Approval)
        );
        if level == TrustLevel::L1 {
            config.profile = Profile::Paranoid;
            config.shield.min_trust = TrustLevel::L1;
            assert_eq!(
                check_dispatch(&config, level, level, true, None, Instant::now()),
                Err(CoreError::Queue)
            );
        }
        let route = Route {
            state: state.clone(),
            epoch: 0,
            config,
            context: "a".repeat(64),
            required: level,
            job: Some("b".repeat(64)),
            slot: Some(Slot::new()),
        };
        assert_eq!(route.check_available(), Err(CoreError::Transport));
        assert!(matches!(
            route.complete("synthetic", &prepared, 32).await,
            Err(CoreError::Transport)
        ));
        assert!(matches!(
            route.send_now("synthetic", &body).await,
            Err(CoreError::Transport)
        ));
        if level == TrustLevel::L1 {
            require(&mut state.session.lock().unwrap())
                .unwrap()
                .save_config(route.config.clone())
                .unwrap();
            assert_eq!(
                super::super::traffic_tick_at(&state, workspace::now())
                    .await
                    .unwrap_err(),
                "remote_transport_unavailable"
            );
        }
        // No egress child, keyring or budget needed to reach the closed gate.
        assert!(state.pending_sends.lock().unwrap().is_empty());
        let mut session = state.session.lock().unwrap();
        let w = require(&mut session).unwrap();
        assert!(w.traffic_status().unwrap().jobs.is_empty());
        assert!(w.remote_jobs().unwrap().is_empty());
    }
}
