//! Manual CIDR intent through a released local speaker, including restart repair.
//! These observations do not establish router installation or packet filtering.
use super::contract;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    bgp::FlowSpecAnnouncer,
    config::{BgpConfig, Customer, Inventory, OperationMode, Playbooks, PolicyProfile, Settings},
    db::{MockRepository, RepositoryTrait},
    domain::{FlowSpecRule, MitigationStatus, SpeakerTarget},
    scheduler::ReconciliationLoop,
};
use std::sync::Arc;
use tower::ServiceExt;

pub struct Harness {
    state: Arc<AppState>,
    repo: Arc<MockRepository>,
    speaker: Arc<dyn FlowSpecAnnouncer>,
    ids: Vec<uuid::Uuid>,
    pub wanted: Vec<FlowSpecRule>,
}

impl Harness {
    pub async fn start(bgp: BgpConfig, speaker: Arc<dyn FlowSpecAnnouncer>) -> Self {
        let mut settings: Settings =
            serde_saphyr::from_str(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.bgp = bgp;
        settings.pop = "destination-cidr".into();
        settings.mode = OperationMode::Enforced;
        settings.http.auth.mode = prefixd::config::AuthMode::None;
        settings.guardrails.dst_prefix_minlen = 22;
        settings.guardrails.dst_prefix_minlen_v6 = Some(48);
        settings.guardrails.allow_src_prefix_match = true;
        settings.guardrails.allow_packet_length_match = true;
        let repo = Arc::new(MockRepository::new());
        let binding = repo
            .register_speaker_target(
                &settings.pop,
                &SpeakerTarget::from_config(&settings.bgp).unwrap(),
                false,
            )
            .await
            .unwrap();
        let inventory = Inventory::new(vec![Customer {
            customer_id: "subnet-owner".into(),
            name: "Subnet owner".into(),
            prefixes: vec!["203.0.112.0/22".into(), "2001:db8:1234::/48".into()],
            policy_profile: PolicyProfile::Normal,
            services: vec![],
        }]);
        let state = AppState::new(
            settings,
            inventory,
            Playbooks { playbooks: vec![] },
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap()
        .with_speaker_binding(binding)
        .unwrap();
        let wanted = contract::destination_prefix_rules();
        let mut ids = Vec::new();
        for rule in &wanted {
            let payload = serde_json::json!({"victim_ip":rule.nlri.dst_prefix, "protocol":"udp", "dst_ports":rule.nlri.dst_ports, "src_prefix":rule.nlri.src_prefix, "src_ports":rule.nlri.src_ports, "packet_length":rule.nlri.packet_length, "action":rule.actions[0].action_type, "rate_bps":rule.actions[0].rate_bps, "ttl_seconds":300, "reason":"released destination CIDR lifecycle"});
            let response = prefixd::api::create_test_router(state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/mitigations")
                        .header("content-type", "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["dst_prefix"], rule.nlri.dst_prefix);
            ids.push(body["mitigation_id"].as_str().unwrap().parse().unwrap());
        }
        contract::wait_inventory(speaker.as_ref(), &wanted)
            .await
            .unwrap();
        Self {
            state,
            repo,
            speaker,
            ids,
            wanted,
        }
    }

    pub async fn repair(&self) {
        let reconciler =
            ReconciliationLoop::new(self.repo.clone(), self.speaker.clone(), 30, false)
                .with_app_state(self.state.clone());
        reconciler.reconcile().await.unwrap();
        contract::wait_inventory(self.speaker.as_ref(), &self.wanted)
            .await
            .unwrap();
        // A converged pass must preserve the exact source/port/action siblings.
        reconciler.reconcile().await.unwrap();
        contract::wait_inventory(self.speaker.as_ref(), &self.wanted)
            .await
            .unwrap();
    }

    pub async fn finish(self) {
        for (index, id) in self.ids.iter().enumerate() {
            if index % 2 == 0 {
                let response = prefixd::api::create_test_router(self.state.clone())
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(format!("/v1/mitigations/{id}/withdraw"))
                            .header("content-type", "application/json")
                            .body(Body::from(r#"{"reason":"explicit CIDR withdrawal"}"#))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            } else {
                let mut mitigation = self.repo.get_mitigation(*id).await.unwrap().unwrap();
                mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
                self.repo.update_mitigation(&mitigation).await.unwrap();
            }
        }
        ReconciliationLoop::new(self.repo.clone(), self.speaker.clone(), 30, false)
            .with_app_state(self.state)
            .reconcile()
            .await
            .unwrap();
        contract::wait_inventory(self.speaker.as_ref(), &[])
            .await
            .unwrap();
        for (index, id) in self.ids.iter().enumerate() {
            let mitigation = self.repo.get_mitigation(*id).await.unwrap().unwrap();
            assert_eq!(
                mitigation.status,
                if index % 2 == 0 {
                    MitigationStatus::Withdrawn
                } else {
                    MitigationStatus::Expired
                }
            );
            assert_eq!(
                mitigation.match_criteria.dst_prefix,
                self.wanted[index].nlri.dst_prefix
            );
        }
    }
}
