use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::config::{CorrelationConfig, MatchDimension, PlaybookCorrelationOverride};

/// A confidence-weight-age triple used by the decay-aware compute path.
/// (confidence, source_weight, ingested_at)
pub type ConfidenceTriple = (Option<f32>, f32, Option<DateTime<Utc>>);

/// Represents a signal group — a collection of related attack events grouped
/// by (victim_ip, vector) within a time window.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignalGroup {
    pub group_id: Uuid,
    pub victim_ip: String,
    pub vector: String,
    pub created_at: DateTime<Utc>,
    pub window_expires_at: DateTime<Utc>,
    pub derived_confidence: f32,
    pub source_count: i32,
    pub status: SignalGroupStatus,
    pub corroboration_met: bool,
    /// Aggregated dimensions contributed by primary events in this group.
    /// Used by the corroborator matching flow (ADR 021).
    #[serde(default)]
    pub primary_dimensions: PrimaryDimensions,
    /// Name of the playbook that matched the primary event(s) for this
    /// group. Used by the corroborator path (PR B) to re-resolve the
    /// playbook-specific correlation override (`min_sources`,
    /// `confidence_threshold`) without needing the full primary-event
    /// context. NULL means: no primary event resolved a playbook yet
    /// (or we're upgrading from a pre-PR-B build); corroborator-only
    /// recompute falls back to the conservative no-flip behavior.
    #[serde(default)]
    pub playbook_name: Option<String>,
}

/// Serializable form of aggregated primary-event dimensions. Stored in the
/// `signal_groups.primary_dimensions` JSONB column.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrimaryDimensions {
    #[serde(default)]
    pub customer_ids: Vec<String>,
    #[serde(default)]
    pub pops: Vec<String>,
    #[serde(default)]
    pub service_ids: Vec<String>,
    #[serde(default)]
    pub interfaces: Vec<String>,
}

impl PrimaryDimensions {
    pub fn add_customer(&mut self, v: impl Into<String>) {
        let v = v.into();
        if !self.customer_ids.contains(&v) {
            self.customer_ids.push(v);
        }
    }
    pub fn add_pop(&mut self, v: impl Into<String>) {
        let v = v.into();
        if !self.pops.contains(&v) {
            self.pops.push(v);
        }
    }
    pub fn add_service(&mut self, v: impl Into<String>) {
        let v = v.into();
        if !self.service_ids.contains(&v) {
            self.service_ids.push(v);
        }
    }
    pub fn add_interface(&mut self, v: impl Into<String>) {
        let v = v.into();
        if !self.interfaces.contains(&v) {
            self.interfaces.push(v);
        }
    }

    /// Returns true if any of `dims`' populated values overlap with this
    /// group's stored primary dimensions.
    pub fn matches_probe(&self, dims: &EventDimensions) -> bool {
        dims.customer_ids
            .iter()
            .any(|c| self.customer_ids.contains(c))
            || dims.pops.iter().any(|p| self.pops.contains(p))
            || dims
                .service_ids
                .iter()
                .any(|s| self.service_ids.contains(s))
            || dims.interfaces.iter().any(|i| self.interfaces.contains(i))
    }

    pub fn to_event_dimensions(&self) -> EventDimensions {
        EventDimensions {
            customer_ids: self.customer_ids.iter().cloned().collect(),
            pops: self.pops.iter().cloned().collect(),
            service_ids: self.service_ids.iter().cloned().collect(),
            interfaces: self.interfaces.iter().cloned().collect(),
        }
    }
}

/// Status of a signal group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignalGroupStatus {
    Open,
    Resolved,
    Expired,
}

impl SignalGroupStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for SignalGroupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SignalGroupStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "resolved" => Ok(Self::Resolved),
            "expired" => Ok(Self::Expired),
            _ => Err(format!("unknown signal group status: {}", s)),
        }
    }
}

/// An event linked to a signal group, with its source weight.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignalGroupEvent {
    pub group_id: Uuid,
    pub event_id: Uuid,
    pub source_weight: f32,
    #[serde(default)]
    pub is_corroborating: bool,
    // Denormalized fields from the event (for API responses)
    pub source: Option<String>,
    pub confidence: Option<f32>,
    pub ingested_at: Option<DateTime<Utc>>,
}

/// Filter parameters for listing signal groups.
#[derive(Debug, Clone, Default)]
pub struct SignalGroupFilter {
    pub status: Option<SignalGroupStatus>,
    pub vector: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

/// A corroborating signal produced by a source in `mode: corroborating`.
/// Does not carry a `victim_ip`; instead, carries one or more dimensions
/// used to match open signal groups whose primary events share the same
/// dimension. See ADR 021.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CorroboratingSignal {
    pub signal_id: Uuid,
    pub source: String,
    /// Optional vector narrower. When `Some`, only groups with a matching
    /// vector are considered. When `None`, any open group whose dimensions
    /// match is eligible.
    #[serde(default)]
    pub vector: Option<String>,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub pop: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    /// Frozen at ingest from the source's configured weight.
    pub weight: f32,
    pub ingested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub raw_details: Option<serde_json::Value>,
    /// Groups this signal has been attached to. Populated when the signal
    /// attaches either at ingest or later via cache drain.
    #[serde(default)]
    pub attached_group_ids: Vec<Uuid>,
}

impl CorroboratingSignal {
    /// True iff at least one matching dimension is populated.
    pub fn has_any_dimension(&self) -> bool {
        self.customer_id.is_some()
            || self.pop.is_some()
            || self.service_id.is_some()
            || self.interface.is_some()
    }
}

/// The set of dimensions extracted from one or more primary events in a
/// signal group. Corroborating signals match if ANY of their populated
/// dimensions equals the corresponding dimension in this struct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventDimensions {
    pub customer_ids: std::collections::HashSet<String>,
    pub pops: std::collections::HashSet<String>,
    pub service_ids: std::collections::HashSet<String>,
    pub interfaces: std::collections::HashSet<String>,
}

impl EventDimensions {
    pub fn is_empty(&self) -> bool {
        self.customer_ids.is_empty()
            && self.pops.is_empty()
            && self.service_ids.is_empty()
            && self.interfaces.is_empty()
    }

    pub fn add_customer(&mut self, v: impl Into<String>) {
        self.customer_ids.insert(v.into());
    }
    pub fn add_pop(&mut self, v: impl Into<String>) {
        self.pops.insert(v.into());
    }
    pub fn add_service(&mut self, v: impl Into<String>) {
        self.service_ids.insert(v.into());
    }
    pub fn add_interface(&mut self, v: impl Into<String>) {
        self.interfaces.insert(v.into());
    }
}

/// Explanation of a correlation decision — for human-readable audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CorrelationExplanation {
    pub signal_group_id: Uuid,
    pub contributing_sources: Vec<SourceContribution>,
    pub derived_confidence: f32,
    pub corroboration_met: bool,
    pub explanation: String,
}

/// Per-source contribution to a signal group's derived confidence.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceContribution {
    pub source: String,
    pub confidence: f32,
    pub weight: f32,
    pub weighted_confidence: f32,
}

/// The correlation engine — pure logic, no I/O.
/// Repository calls are done externally; this struct provides the computation.
pub struct CorrelationEngine;

impl CorrelationEngine {
    const ALL_MATCH_DIMENSIONS: [MatchDimension; 4] = [
        MatchDimension::CustomerId,
        MatchDimension::Pop,
        MatchDimension::ServiceId,
        MatchDimension::Interface,
    ];

    /// Create a new signal group for the given (victim_ip, vector).
    pub fn create_group(victim_ip: &str, vector: &str, window_seconds: u32) -> SignalGroup {
        let now = Utc::now();
        SignalGroup {
            group_id: Uuid::new_v4(),
            victim_ip: victim_ip.to_string(),
            vector: vector.to_string(),
            created_at: now,
            window_expires_at: now + Duration::seconds(window_seconds as i64),
            derived_confidence: 0.0,
            source_count: 0,
            status: SignalGroupStatus::Open,
            corroboration_met: false,
            primary_dimensions: PrimaryDimensions::default(),
            playbook_name: None,
        }
    }

    /// Recompute derived_confidence as a weighted average of all events'
    /// confidences. Each event contributes (confidence * source_weight).
    ///
    /// `events` is a slice of (confidence, source_weight) pairs.
    /// Null/None confidence is treated as 0.0.
    pub fn compute_derived_confidence(events: &[(Option<f32>, f32)]) -> f32 {
        if events.is_empty() {
            return 0.0;
        }

        let mut sum_weighted = 0.0f64;
        let mut sum_weights = 0.0f64;

        for &(confidence, weight) in events {
            let conf = confidence.unwrap_or(0.0) as f64;
            let w = weight as f64;
            sum_weighted += conf * w;
            sum_weights += w;
        }

        if sum_weights == 0.0 {
            return 0.0;
        }

        (sum_weighted / sum_weights) as f32
    }

    /// Decay-aware variant of [`compute_derived_confidence`]. Each event's
    /// source weight is multiplied by an exponential factor of
    /// `0.5^(age_seconds / half_life_seconds)` before participating in the
    /// weighted average.
    ///
    /// Semantics:
    /// - `half_life_seconds == 0` short-circuits to the original
    ///   weighted average (`events_with_age` is mapped to `(confidence, weight)`
    ///   pairs and decay is skipped). This keeps the v0.17.x behavior
    ///   bit-identical when decay is disabled.
    /// - Events whose `ingested_at` is `None` (e.g. older rows that
    ///   pre-date denormalization) are treated as age=0, i.e. they
    ///   contribute at full weight. This avoids destabilizing existing
    ///   groups on upgrade.
    /// - Future-dated events (clock skew) are clamped to age=0.
    ///
    /// See ADR 022.
    pub fn compute_derived_confidence_decayed(
        events_with_age: &[ConfidenceTriple],
        now: DateTime<Utc>,
        half_life_seconds: u32,
    ) -> f32 {
        if events_with_age.is_empty() {
            return 0.0;
        }

        if half_life_seconds == 0 {
            let pairs: Vec<(Option<f32>, f32)> =
                events_with_age.iter().map(|(c, w, _)| (*c, *w)).collect();
            return Self::compute_derived_confidence(&pairs);
        }

        let half_life = half_life_seconds as f64;
        let mut sum_weighted = 0.0f64;
        let mut sum_weights = 0.0f64;

        for &(confidence, weight, ingested_at) in events_with_age {
            let conf = confidence.unwrap_or(0.0) as f64;
            let base_weight = weight as f64;
            let age_secs = match ingested_at {
                Some(t) => {
                    let dt = (now - t).num_milliseconds() as f64 / 1000.0;
                    dt.max(0.0)
                }
                None => 0.0,
            };
            let decay = (0.5f64).powf(age_secs / half_life);
            let effective_weight = base_weight * decay;
            sum_weighted += conf * effective_weight;
            sum_weights += effective_weight;
        }

        if sum_weights == 0.0 {
            return 0.0;
        }

        (sum_weighted / sum_weights) as f32
    }

    /// Count distinct sources from a list of source names.
    pub fn count_distinct_sources(sources: &[String]) -> i32 {
        let mut seen = std::collections::HashSet::new();
        for s in sources {
            seen.insert(s.as_str());
        }
        seen.len() as i32
    }

    /// Check whether corroboration requirements are met.
    ///
    /// Uses per-playbook override if present, else global config defaults.
    pub fn check_corroboration(
        source_count: i32,
        derived_confidence: f32,
        config: &CorrelationConfig,
        playbook_override: Option<&PlaybookCorrelationOverride>,
    ) -> bool {
        let min_sources = config.effective_min_sources(playbook_override);
        let threshold = config.effective_confidence_threshold(playbook_override);

        source_count as u32 >= min_sources && derived_confidence >= threshold
    }

    /// Corroboration is only "met" when the group contains ≥1 primary event.
    /// A group composed entirely of corroborating signals can never trigger
    /// a mitigation (ADR 021 invariant).
    pub fn check_corroboration_with_primary(
        source_count: i32,
        derived_confidence: f32,
        has_primary_event: bool,
        config: &CorrelationConfig,
        playbook_override: Option<&PlaybookCorrelationOverride>,
    ) -> bool {
        has_primary_event
            && Self::check_corroboration(
                source_count,
                derived_confidence,
                config,
                playbook_override,
            )
    }

    /// Decide whether a corroborating signal matches a group based on its
    /// dimensions vs the group's aggregated dimensions. Matching is an OR
    /// over each populated dimension — any shared value qualifies.
    ///
    /// If the signal carries a `vector`, the group's vector must match.
    pub fn corroborator_matches(
        signal: &CorroboratingSignal,
        group: &SignalGroup,
        group_dims: &EventDimensions,
    ) -> bool {
        Self::corroborator_matches_declared(
            signal,
            &group.vector,
            group_dims,
            &Self::ALL_MATCH_DIMENSIONS,
        )
    }

    pub fn corroborator_matches_declared(
        signal: &CorroboratingSignal,
        group_vector: &str,
        group_dims: &EventDimensions,
        declared_dims: &[MatchDimension],
    ) -> bool {
        if let Some(v) = &signal.vector
            && v != group_vector
        {
            return false;
        }

        declared_dims.iter().any(|dim| match dim {
            MatchDimension::CustomerId => signal
                .customer_id
                .as_ref()
                .is_some_and(|cid| group_dims.customer_ids.contains(cid)),
            MatchDimension::Pop => signal
                .pop
                .as_ref()
                .is_some_and(|pop| group_dims.pops.contains(pop)),
            MatchDimension::ServiceId => signal
                .service_id
                .as_ref()
                .is_some_and(|sid| group_dims.service_ids.contains(sid)),
            MatchDimension::Interface => signal
                .interface
                .as_ref()
                .is_some_and(|iface| group_dims.interfaces.contains(iface)),
        })
    }

    /// Produce a human-readable explanation of the correlation decision.
    pub fn compute_explanation(
        group: &SignalGroup,
        contributions: Vec<SourceContribution>,
        config: &CorrelationConfig,
        playbook_override: Option<&PlaybookCorrelationOverride>,
    ) -> CorrelationExplanation {
        let min_sources = config.effective_min_sources(playbook_override);
        let threshold = config.effective_confidence_threshold(playbook_override);

        let source_list: Vec<String> = contributions
            .iter()
            .map(|c| format!("{}(conf={:.2}, w={:.1})", c.source, c.confidence, c.weight))
            .collect();

        let explanation = if group.corroboration_met {
            format!(
                "Corroboration met: {} distinct source(s) (min={}) with derived confidence {:.2} (threshold={:.2}). Sources: {}",
                group.source_count,
                min_sources,
                group.derived_confidence,
                threshold,
                source_list.join(", ")
            )
        } else {
            let mut reasons = Vec::new();
            if (group.source_count as u32) < min_sources {
                reasons.push(format!(
                    "need {} source(s), have {}",
                    min_sources, group.source_count
                ));
            }
            if group.derived_confidence < threshold {
                reasons.push(format!(
                    "confidence {:.2} below threshold {:.2}",
                    group.derived_confidence, threshold
                ));
            }
            format!(
                "Corroboration not met: {}. Sources: {}",
                reasons.join("; "),
                source_list.join(", ")
            )
        };

        CorrelationExplanation {
            signal_group_id: group.group_id,
            contributing_sources: contributions,
            derived_confidence: group.derived_confidence,
            corroboration_met: group.corroboration_met,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Group creation ─────────────────────────────────────────────────

    #[test]
    fn test_create_group() {
        let group = CorrelationEngine::create_group("10.0.0.1", "udp_flood", 300);
        assert_eq!(group.victim_ip, "10.0.0.1");
        assert_eq!(group.vector, "udp_flood");
        assert_eq!(group.status, SignalGroupStatus::Open);
        assert!(!group.corroboration_met);
        assert_eq!(group.derived_confidence, 0.0);
        assert_eq!(group.source_count, 0);
        // window_expires_at should be ~300 seconds from now
        let diff = group.window_expires_at - group.created_at;
        assert_eq!(diff.num_seconds(), 300);
    }

    #[test]
    fn test_different_vectors_create_separate_groups() {
        let g1 = CorrelationEngine::create_group("10.0.0.1", "udp_flood", 300);
        let g2 = CorrelationEngine::create_group("10.0.0.1", "syn_flood", 300);
        assert_ne!(g1.group_id, g2.group_id);
        assert_eq!(g1.victim_ip, g2.victim_ip);
        assert_ne!(g1.vector, g2.vector);
    }

    // ── Derived confidence computation ─────────────────────────────────

    #[test]
    fn test_derived_confidence_single_event() {
        let events = vec![(Some(0.9), 1.0)];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert!((confidence - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_derived_confidence_equal_weights() {
        // Two events with equal weights: (0.9 + 0.3) / 2 = 0.6
        let events = vec![(Some(0.9), 1.0), (Some(0.3), 1.0)];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert!((confidence - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_derived_confidence_weighted_average() {
        // Event A: conf=0.9, weight=2.0 → 1.8
        // Event B: conf=0.3, weight=1.0 → 0.3
        // Total: 2.1 / 3.0 = 0.7
        let events = vec![(Some(0.9), 2.0), (Some(0.3), 1.0)];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert!((confidence - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_derived_confidence_null_confidence_treated_as_zero() {
        // Event A: conf=0.9, weight=1.0
        // Event B: conf=None→0.0, weight=1.0
        // Average: 0.45
        let events = vec![(Some(0.9), 1.0), (None, 1.0)];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert!((confidence - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_derived_confidence_zero_pulls_down() {
        // VAL-ENGINE-007: confidence=0.9 + confidence=0.0 (equal weights) → 0.45
        let events = vec![(Some(0.9), 1.0), (Some(0.0), 1.0)];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert!((confidence - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_derived_confidence_empty_events() {
        let events: Vec<(Option<f32>, f32)> = vec![];
        let confidence = CorrelationEngine::compute_derived_confidence(&events);
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn test_derived_confidence_three_events_incremental() {
        // VAL-ENGINE-006: verify derived_confidence updates incrementally
        // After 1 event: 0.8 * 1.0 / 1.0 = 0.8
        let e1 = vec![(Some(0.8), 1.0)];
        assert!((CorrelationEngine::compute_derived_confidence(&e1) - 0.8).abs() < 0.001);

        // After 2 events: (0.8 + 0.6) / 2 = 0.7
        let e2 = vec![(Some(0.8), 1.0), (Some(0.6), 1.0)];
        assert!((CorrelationEngine::compute_derived_confidence(&e2) - 0.7).abs() < 0.001);

        // After 3 events: (0.8 + 0.6 + 0.4) / 3 = 0.6
        let e3 = vec![(Some(0.8), 1.0), (Some(0.6), 1.0), (Some(0.4), 1.0)];
        assert!((CorrelationEngine::compute_derived_confidence(&e3) - 0.6).abs() < 0.001);
    }

    // ── Confidence decay (ADR 022) ─────────────────────────────────────

    #[test]
    fn test_decay_disabled_matches_undecayed() {
        // half_life=0 ⇒ identical result to the unadorned helper, ignoring
        // ingested_at entirely.
        let now = Utc::now();
        let events = vec![
            (Some(0.9), 2.0, Some(now - chrono::Duration::seconds(300))),
            (Some(0.3), 1.0, Some(now - chrono::Duration::seconds(900))),
        ];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 0);
        let pairs = vec![(Some(0.9), 2.0), (Some(0.3), 1.0)];
        let plain = CorrelationEngine::compute_derived_confidence(&pairs);
        assert!((decayed - plain).abs() < 1e-6);
    }

    #[test]
    fn test_decay_single_event_at_half_life_halves_weight() {
        // One event at age=half_life ⇒ effective weight halves but it's
        // the only event, so derived confidence is unchanged.
        let now = Utc::now();
        let events = vec![(Some(0.8), 1.0, Some(now - chrono::Duration::seconds(60)))];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert!((decayed - 0.8).abs() < 1e-3);
    }

    #[test]
    fn test_decay_clamps_negative_age() {
        // Future-dated ingested_at (clock skew) is treated as age=0.
        let now = Utc::now();
        let events = vec![(Some(0.6), 1.0, Some(now + chrono::Duration::seconds(120)))];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert!((decayed - 0.6).abs() < 1e-3);
    }

    #[test]
    fn test_decay_none_ingested_at_full_weight() {
        // Rows that pre-date denormalization (ingested_at=None) contribute
        // at full weight rather than being silently dropped.
        let now = Utc::now();
        let events = vec![(Some(1.0), 1.0, None)];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert!((decayed - 1.0).abs() < 1e-3);
    }

    #[test]
    fn test_decay_two_events_fresh_dominates_stale() {
        // Fresh confidence=0.9, weight=1.0, age=0 ⇒ effective weight = 1.0
        // Stale confidence=0.1, weight=1.0, age=2*HL ⇒ effective weight = 0.25
        // Expected: (0.9*1.0 + 0.1*0.25) / (1.0 + 0.25) = 0.925 / 1.25 = 0.74
        let now = Utc::now();
        let events = vec![
            (Some(0.9), 1.0, Some(now)),
            (Some(0.1), 1.0, Some(now - chrono::Duration::seconds(120))),
        ];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert!((decayed - 0.74).abs() < 1e-3);
    }

    #[test]
    fn test_decay_empty_events_returns_zero() {
        let now = Utc::now();
        let events: Vec<ConfidenceTriple> = vec![];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert_eq!(decayed, 0.0);
    }

    #[test]
    fn test_decay_extreme_age_does_not_panic() {
        // Very old event with reasonable half-life ⇒ contribution rounds to ~0
        // but math is finite and non-NaN.
        let now = Utc::now();
        let events = vec![(
            Some(0.7),
            1.0,
            Some(now - chrono::Duration::seconds(10_000_000)),
        )];
        let decayed = CorrelationEngine::compute_derived_confidence_decayed(&events, now, 60);
        assert!(decayed.is_finite());
        assert!((0.0..=1.0).contains(&decayed));
    }

    // ── Distinct source counting ───────────────────────────────────────

    #[test]
    fn test_count_distinct_sources() {
        let sources = vec!["alpha".to_string(), "beta".to_string(), "alpha".to_string()];
        assert_eq!(CorrelationEngine::count_distinct_sources(&sources), 2);
    }

    #[test]
    fn test_count_distinct_sources_single() {
        let sources = vec!["alpha".to_string(), "alpha".to_string()];
        assert_eq!(CorrelationEngine::count_distinct_sources(&sources), 1);
    }

    #[test]
    fn test_count_distinct_sources_empty() {
        let sources: Vec<String> = vec![];
        assert_eq!(CorrelationEngine::count_distinct_sources(&sources), 0);
    }

    // ── Corroboration checking ─────────────────────────────────────────

    #[test]
    fn test_corroboration_met() {
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        assert!(CorrelationEngine::check_corroboration(
            2, 0.6, &config, None
        ));
    }

    #[test]
    fn test_corroboration_not_met_insufficient_sources() {
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        assert!(!CorrelationEngine::check_corroboration(
            1, 0.9, &config, None
        ));
    }

    #[test]
    fn test_corroboration_not_met_low_confidence() {
        // VAL-ENGINE-013
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.7,
            ..Default::default()
        };
        assert!(!CorrelationEngine::check_corroboration(
            2, 0.3, &config, None
        ));
    }

    #[test]
    fn test_corroboration_with_playbook_override() {
        // VAL-ENGINE-012: per-playbook override
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        let override_ = PlaybookCorrelationOverride {
            min_sources: Some(3),
            ..Default::default()
        };
        // 2 sources meets global (2), but override requires 3
        assert!(!CorrelationEngine::check_corroboration(
            2,
            0.6,
            &config,
            Some(&override_)
        ));
        // 3 sources meets override
        assert!(CorrelationEngine::check_corroboration(
            3,
            0.6,
            &config,
            Some(&override_)
        ));
    }

    #[test]
    fn test_corroboration_playbook_override_confidence() {
        let config = CorrelationConfig {
            min_sources: 1,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        let override_ = PlaybookCorrelationOverride {
            confidence_threshold: Some(0.8),
            ..Default::default()
        };
        // 0.6 meets global (0.5) but not override (0.8)
        assert!(!CorrelationEngine::check_corroboration(
            1,
            0.6,
            &config,
            Some(&override_)
        ));
        assert!(CorrelationEngine::check_corroboration(
            1,
            0.9,
            &config,
            Some(&override_)
        ));
    }

    #[test]
    fn test_corroboration_single_source_backward_compat() {
        // VAL-ENGINE-010: min_sources=1 should trigger with single source
        let config = CorrelationConfig {
            min_sources: 1,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        assert!(CorrelationEngine::check_corroboration(
            1, 0.7, &config, None
        ));
    }

    #[test]
    fn test_corroboration_fallback_to_global_defaults() {
        // VAL-ENGINE-035: no override → use global
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        assert!(CorrelationEngine::check_corroboration(
            2, 0.6, &config, None
        ));
    }

    // ── Explanation generation ──────────────────────────────────────────

    #[test]
    fn test_explanation_corroboration_met() {
        let group = SignalGroup {
            group_id: Uuid::new_v4(),
            victim_ip: "10.0.0.1".to_string(),
            vector: "udp_flood".to_string(),
            created_at: Utc::now(),
            window_expires_at: Utc::now() + Duration::seconds(300),
            derived_confidence: 0.75,
            source_count: 2,
            status: SignalGroupStatus::Open,
            corroboration_met: true,
            primary_dimensions: PrimaryDimensions::default(),
            playbook_name: None,
        };

        let contributions = vec![
            SourceContribution {
                source: "fastnetmon".to_string(),
                confidence: 0.9,
                weight: 1.0,
                weighted_confidence: 0.9,
            },
            SourceContribution {
                source: "alertmanager".to_string(),
                confidence: 0.6,
                weight: 1.0,
                weighted_confidence: 0.6,
            },
        ];

        let config = CorrelationConfig::default();
        let explanation =
            CorrelationEngine::compute_explanation(&group, contributions, &config, None);

        assert!(explanation.corroboration_met);
        assert!((explanation.derived_confidence - 0.75).abs() < 0.001);
        assert_eq!(explanation.contributing_sources.len(), 2);
        assert!(explanation.explanation.contains("Corroboration met"));
        assert!(explanation.explanation.contains("2 distinct source(s)"));
    }

    #[test]
    fn test_explanation_corroboration_not_met() {
        let group = SignalGroup {
            group_id: Uuid::new_v4(),
            victim_ip: "10.0.0.1".to_string(),
            vector: "udp_flood".to_string(),
            created_at: Utc::now(),
            window_expires_at: Utc::now() + Duration::seconds(300),
            derived_confidence: 0.3,
            source_count: 1,
            status: SignalGroupStatus::Open,
            corroboration_met: false,
            primary_dimensions: PrimaryDimensions::default(),
            playbook_name: None,
        };

        let contributions = vec![SourceContribution {
            source: "alpha".to_string(),
            confidence: 0.3,
            weight: 1.0,
            weighted_confidence: 0.3,
        }];

        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        let explanation =
            CorrelationEngine::compute_explanation(&group, contributions, &config, None);

        assert!(!explanation.corroboration_met);
        assert!(explanation.explanation.contains("Corroboration not met"));
        assert!(explanation.explanation.contains("need 2 source(s), have 1"));
        assert!(
            explanation
                .explanation
                .contains("confidence 0.30 below threshold 0.50")
        );
    }

    // ── Signal group status parsing ────────────────────────────────────

    #[test]
    fn test_signal_group_status_roundtrip() {
        for status in &[
            SignalGroupStatus::Open,
            SignalGroupStatus::Resolved,
            SignalGroupStatus::Expired,
        ] {
            let s = status.as_str();
            let parsed: SignalGroupStatus = s.parse().unwrap();
            assert_eq!(*status, parsed);
        }
    }

    #[test]
    fn test_signal_group_status_invalid() {
        let result: Result<SignalGroupStatus, _> = "invalid".parse();
        assert!(result.is_err());
    }

    // ── Corroborating signal matching (ADR 021) ────────────────────────

    fn test_group(vector: &str) -> SignalGroup {
        SignalGroup {
            group_id: Uuid::new_v4(),
            victim_ip: "203.0.113.5".to_string(),
            vector: vector.to_string(),
            created_at: Utc::now(),
            window_expires_at: Utc::now() + Duration::seconds(300),
            derived_confidence: 0.0,
            source_count: 0,
            status: SignalGroupStatus::Open,
            corroboration_met: false,
            primary_dimensions: PrimaryDimensions::default(),
            playbook_name: None,
        }
    }

    fn test_signal() -> CorroboratingSignal {
        CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: "router-cpu".into(),
            vector: None,
            customer_id: None,
            pop: None,
            service_id: None,
            interface: None,
            confidence: Some(0.6),
            weight: 0.5,
            ingested_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            raw_details: None,
            attached_group_ids: vec![],
        }
    }

    #[test]
    fn corroborator_matches_on_customer_id() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_customer("cust_42");
        let mut sig = test_signal();
        sig.customer_id = Some("cust_42".into());
        assert!(CorrelationEngine::corroborator_matches(&sig, &group, &dims));
    }

    #[test]
    fn corroborator_matches_on_pop() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_pop("iad1");
        let mut sig = test_signal();
        sig.pop = Some("iad1".into());
        assert!(CorrelationEngine::corroborator_matches(&sig, &group, &dims));
    }

    #[test]
    fn corroborator_matches_on_interface() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_interface("et-0/0/12");
        let mut sig = test_signal();
        sig.interface = Some("et-0/0/12".into());
        assert!(CorrelationEngine::corroborator_matches(&sig, &group, &dims));
    }

    #[test]
    fn corroborator_matches_or_logic_across_dimensions() {
        // Only pop matches; customer_id does not. OR logic means it still matches.
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_pop("iad1");
        dims.add_customer("cust_real");
        let mut sig = test_signal();
        sig.customer_id = Some("cust_mismatch".into());
        sig.pop = Some("iad1".into());
        assert!(CorrelationEngine::corroborator_matches(&sig, &group, &dims));
    }

    #[test]
    fn corroborator_no_match_when_no_dimension_overlaps() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_pop("iad1");
        let mut sig = test_signal();
        sig.pop = Some("sfo3".into());
        sig.customer_id = Some("cust_42".into()); // not in group
        assert!(!CorrelationEngine::corroborator_matches(
            &sig, &group, &dims
        ));
    }

    #[test]
    fn corroborator_vector_filter_rejects_mismatched_group() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_pop("iad1");
        let mut sig = test_signal();
        sig.vector = Some("syn_flood".into());
        sig.pop = Some("iad1".into());
        assert!(!CorrelationEngine::corroborator_matches(
            &sig, &group, &dims
        ));
    }

    #[test]
    fn corroborator_vector_filter_accepts_matching_group() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_pop("iad1");
        let mut sig = test_signal();
        sig.vector = Some("udp_flood".into());
        sig.pop = Some("iad1".into());
        assert!(CorrelationEngine::corroborator_matches(&sig, &group, &dims));
    }

    #[test]
    fn corroborator_declared_matching_ignores_undeclared_dimensions() {
        let group = test_group("udp_flood");
        let mut dims = EventDimensions::default();
        dims.add_customer("cust_42");
        let mut sig = test_signal();
        sig.customer_id = Some("cust_42".into());
        assert!(!CorrelationEngine::corroborator_matches_declared(
            &sig,
            &group.vector,
            &dims,
            &[MatchDimension::Pop],
        ));
    }

    #[test]
    fn has_any_dimension_detects_populated_signal() {
        let mut sig = test_signal();
        assert!(!sig.has_any_dimension());
        sig.pop = Some("iad1".into());
        assert!(sig.has_any_dimension());
    }

    #[test]
    fn check_corroboration_with_primary_requires_primary_event() {
        let config = CorrelationConfig {
            min_sources: 2,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        // 2 sources, confidence 0.8 — numerically meets corroboration...
        assert!(CorrelationEngine::check_corroboration(
            2, 0.8, &config, None
        ));
        // ...but with zero primary events, corroboration_with_primary says no.
        assert!(!CorrelationEngine::check_corroboration_with_primary(
            2, 0.8, false, &config, None,
        ));
        // Flip has_primary_event to true and it fires.
        assert!(CorrelationEngine::check_corroboration_with_primary(
            2, 0.8, true, &config, None,
        ));
    }
}
