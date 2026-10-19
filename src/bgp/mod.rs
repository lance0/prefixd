mod announcer;
mod gobgp;
mod mock;
mod proto;
#[cfg(feature = "bgp-rustbgpd")]
mod rustbgpd_proto;

pub use announcer::*;
pub use gobgp::*;
pub use mock::*;
pub use proto::apipb;
#[cfg(feature = "bgp-rustbgpd")]
pub use rustbgpd_proto::rustbgpd_pb;

/// Equality terms per port list the rustbgpd encoder emits. Settings refuse a
/// rustbgpd `guardrails.max_ports` above it, so the guardrail never admits a
/// rule this encoder would refuse at announcement. GoBGP has no per-list cap.
pub const RUSTBGPD_MAX_PORTS_PER_LIST: usize = 8;

#[cfg(feature = "bgp-rustbgpd")]
mod rustbgpd;
#[cfg(feature = "bgp-rustbgpd")]
pub use rustbgpd::RustBgpdAnnouncer;

pub async fn speaker_factory(
    config: &crate::config::BgpConfig,
) -> anyhow::Result<std::sync::Arc<dyn FlowSpecAnnouncer>> {
    use crate::config::BgpMode;
    tracing::info!(mode = ?config.mode, "selecting BGP speaker");
    Ok(match config.mode {
        BgpMode::Mock => std::sync::Arc::new(MockAnnouncer::new()),
        BgpMode::Sidecar | BgpMode::Gobgp => {
            anyhow::ensure!(!config.gobgp_grpc.is_empty(), "bgp.gobgp_grpc is required");
            let target = crate::domain::SpeakerTarget::from_config(config)?;
            let mut speaker = GoBgpAnnouncer::new(target.endpoint().to_owned());
            speaker.connect().await?;
            std::sync::Arc::new(speaker)
        }
        BgpMode::Rustbgpd => {
            #[cfg(feature = "bgp-rustbgpd")]
            {
                let mut settings = config
                    .rustbgpd
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("bgp.rustbgpd is required"))?;
                settings.endpoint = crate::domain::SpeakerTarget::from_config(config)?
                    .endpoint()
                    .to_owned();
                std::sync::Arc::new(RustBgpdAnnouncer::connect(&settings).await?)
            }
            #[cfg(not(feature = "bgp-rustbgpd"))]
            {
                anyhow::bail!("rustbgpd backend requires the bgp-rustbgpd feature")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn factory_selects_mock_and_rejects_unavailable_backends() {
        let mut config: crate::config::BgpConfig =
            crate::config::parse_yaml("mode: mock\nlocal_asn: 65010\nrouter_id: 192.0.2.1")
                .unwrap();
        assert!(
            speaker_factory(&config)
                .await
                .unwrap()
                .reader()
                .unwrap()
                .list_active()
                .await
                .unwrap()
                .is_empty()
        );
        config.mode = crate::config::BgpMode::Gobgp;
        assert!(speaker_factory(&config).await.is_err());
        config.mode = crate::config::BgpMode::Rustbgpd;
        let error = speaker_factory(&config).await.err().unwrap().to_string();
        #[cfg(feature = "bgp-rustbgpd")]
        assert!(error.contains("bgp.rustbgpd is required"));
        #[cfg(not(feature = "bgp-rustbgpd"))]
        assert!(error.contains("bgp-rustbgpd feature"));
    }
}
