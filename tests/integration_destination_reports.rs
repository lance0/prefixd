#![forbid(unsafe_code)]
#![cfg(feature = "test-utils")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use prefixd::AppState;
use prefixd::api::create_test_router;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{AuthMode, BgpMode, Inventory, Playbooks, Settings};
use prefixd::db::{MockRepository, RepositoryTrait};
use prefixd::domain::{
    ActionParams, ActionType, AttackEvent, AttackVector, MatchCriteria, Mitigation,
    MitigationIntent,
};
use tower::ServiceExt;
use uuid::Uuid;

fn mitigation(target: &str, prefix: &str) -> Mitigation {
    Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("allocation-owner".into()),
            service_id: None,
            pop: "test-pop".into(),
            match_criteria: MatchCriteria {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![443],
                ..Default::default()
            },
            action_type: ActionType::Police,
            action_params: ActionParams {
                rate_bps: Some(8_000_000),
                ..Default::default()
            },
            ttl_seconds: 300,
            reason: "subnet port attack".into(),
        },
        target.into(),
        AttackVector::Unknown,
    )
}

#[tokio::test]
async fn cidr_incident_reports_use_exact_stored_targets_without_host_aggregation() {
    for (target, base, host, host_prefix, overlapping) in [
        (
            "203.0.112.0/22",
            "203.0.112.0",
            "203.0.113.10",
            "203.0.113.10/32",
            "203.0.112.0/23",
        ),
        (
            "2001:db8:1234::/48",
            "2001:db8:1234::",
            "2001:db8:1234::10",
            "2001:db8:1234::10/128",
            "2001:db8:1234::/64",
        ),
    ] {
        let repo = Arc::new(MockRepository::new());
        let mut settings: Settings =
            serde_saphyr::from_str(include_str!("../configs/prefixd.yaml")).unwrap();
        settings.http.auth.mode = AuthMode::None;
        settings.bgp.mode = BgpMode::Mock;
        // A base-address service must not supply context for the whole CIDR.
        let inventory: Inventory = serde_json::from_value(serde_json::json!({
            "customers": [{
                "customer_id": "allocation-owner", "name": "Allocation Owner",
                "prefixes": [target],
                "services": [{
                    "service_id": "base-only-service", "name": "Base Only Service",
                    "assets": [{"ip": base}]
                }]
            }]
        }))
        .unwrap();
        let state = AppState::new(
            settings,
            inventory,
            Playbooks { playbooks: vec![] },
            repo.clone(),
            Arc::new(MockAnnouncer::new()),
            ".".into(),
        )
        .unwrap();
        let app = create_test_router(state);
        let mut selected = mitigation(target, target);
        let source = if target.contains(':') {
            "2001:db8:5678::/48"
        } else {
            "198.51.100.0/24"
        };
        selected.match_criteria.src_prefix = Some(source.into());
        let mut same_target = mitigation(target, target);
        // Historical incomplete action data must not be rendered as a zero rate.
        same_target.action_params.rate_bps = None;
        let host_rule = mitigation(host, host_prefix);
        let overlap_rule = mitigation(overlapping, overlapping);
        for rule in [&selected, &same_target, &host_rule, &overlap_rule] {
            repo.insert_mitigation(rule).await.unwrap();
        }
        for ip in [base, host] {
            let input = serde_json::from_value(serde_json::json!({
                "timestamp": "2026-10-23T00:00:00Z", "source": "detector",
                "victim_ip": ip, "vector": "udp_flood", "bps": 9_000_000_000_i64
            }))
            .unwrap();
            repo.insert_event(&AttackEvent::from_input(input))
                .await
                .unwrap();
        }
        let response = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/reports/incident?mitigation_id={}",
                    selected.mitigation_id
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{target}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(report.contains(&format!("# Incident Report — {target}")));
        assert!(report.contains("exact destination CIDR"));
        assert!(report.contains("not aggregated"));
        assert!(report.contains("| Total Events | 0 |"));
        assert!(report.contains("| Total Mitigations | 2 |"));
        assert!(report.contains(&selected.mitigation_id.to_string()));
        assert!(report.contains(&same_target.mitigation_id.to_string()));
        assert!(!report.contains(&host_rule.mitigation_id.to_string()));
        assert!(!report.contains(&overlap_rule.mitigation_id.to_string()));
        assert!(!report.contains("Peak Traffic"));
        assert!(!report.contains("Base Only Service"));
        assert!(report.contains("Allocation Owner (`allocation-owner`)"));
        assert!(report.contains(&format!("UDP; from `{source}`; dst ports 443")));
        assert!(report.contains("police 8000000 bps"));
        assert!(!report.contains("police 0 bps"));
        assert!(report.contains(&format!(
            "| `{}` | {} | police |",
            same_target.mitigation_id, same_target.status
        )));
        assert!(report.contains(&selected.expires_at.to_rfc3339()));
        assert!(report.contains("router enforcement is unobserved"));

        // The public IP selector remains host-only; CIDRs need a mitigation ID.
        let response = app
            .oneshot(
                Request::get(format!(
                    "/v1/reports/incident?ip={}",
                    urlencoding::encode(target)
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target}");
    }
}
