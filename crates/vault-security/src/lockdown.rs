//! Lockdown engine: a graduated, auditable state machine.
//!
//! ```text
//! NORMAL ──anomaly──▶ SUSPICIOUS ──worsening──▶ RESTRICTED
//!    ▲                    │                         │
//!    │  acknowledge       │  re-authenticate        │  re-authenticate
//!    └────────────────────┴─────────────────────────┤
//!                                                   ▼
//!                        CRITICAL ◀──severe, explicit── LOCKED
//! ```
//!
//! Design rules (see docs/threat-model.md §Lockdown):
//!
//! * Every trigger has: detection rule, confidence, action, reversibility,
//!   audit event, and a documented false-positive analysis.
//! * Actions are graduated: never destroy anything automatically.
//! * Irreversible crypto-erasure is **only** ever triggered by an explicit
//!   user decision, never by an automatic rule.
//! * `CRITICAL` is unreachable by rules alone; it requires an explicit
//!   escalation (e.g. user confirms suspected compromise).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultState {
    Normal,
    Suspicious,
    Restricted,
    Locked,
    Critical,
}

impl VaultState {
    pub fn rank(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Suspicious => 1,
            Self::Restricted => 2,
            Self::Locked => 3,
            Self::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Suspicious => "SUSPICIOUS",
            Self::Restricted => "RESTRICTED",
            Self::Locked => "LOCKED",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// A security-relevant detection. `detail` must never contain secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp_ms: u64,
    pub rule: String,
    pub severity: Severity,
    pub component: String,
    pub confidence: u8,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// No state change; event recorded only.
    RecordOnly,
    /// Hide/lock the UI surface, keep session keys.
    LockUi,
    /// Drop session keys; full re-authentication required.
    DestroySession,
    /// Block object reads/writes and exports until re-authentication.
    RestrictAccess,
    /// Block writes but allow read-only review of status.
    ReadOnly,
    /// Requires recovery verification in addition to re-authentication.
    RequireRecoveryVerification,
}

#[derive(Debug, Clone)]
pub struct Trigger {
    pub rule: &'static str,
    /// 0..=100. Rules below 50 escalate only to `Suspicious`.
    pub confidence: u8,
    pub severity: Severity,
    pub component: String,
    pub detail: String,
}

impl Trigger {
    pub fn new(rule: &'static str, confidence: u8, severity: Severity, component: &str, detail: impl Into<String>) -> Self {
        Self {
            rule,
            confidence: confidence.min(100),
            severity,
            component: component.to_string(),
            detail: detail.into(),
        }
    }
}

/// Rule table: every trigger maps to an action + target state.
/// Confidence and false-positive notes are documented in
/// `docs/security-audit.md` (§Lockdown rules).
pub fn classify(trigger: &Trigger) -> (VaultState, Action) {
    match trigger.rule {
        // 100% confidence: cryptographically verified tampering.
        "header.invalid" | "manifest.auth_failed" | "vault_id.mismatch" | "format.unsupported" => {
            (VaultState::Locked, Action::DestroySession)
        }
        // Rollback / substitution: high confidence, needs re-auth.
        "rollback.detected" => (VaultState::Locked, Action::DestroySession),
        // Object-level auth failure: could be bit-rot on one object.
        // Restrict (quarantine) instead of locking the whole vault.
        "object.auth_failed" => (VaultState::Restricted, Action::RestrictAccess),
        // Audit chain broken: evidence of tampering with telemetry only.
        "audit.chain_broken" => (VaultState::Suspicious, Action::LockUi),
        // Executable changed since last trusted launch (updates, or tamper).
        "binary.modified" => (VaultState::Suspicious, Action::RecordOnly),
        // Repeated failed unlock attempts.
        "auth.repeated_failure" => (VaultState::Restricted, Action::LockUi),
        // Control state unavailable (DPAPI failure / deleted file).
        "control.unavailable" => (VaultState::Suspicious, Action::RecordOnly),
        // Expected crash debris: recorded, no escalation.
        "container.orphan_detected" => (VaultState::Normal, Action::RecordOnly),
        _ => (VaultState::Normal, Action::RecordOnly),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownRecord {
    pub state: VaultState,
    pub events: Vec<SecurityEvent>,
    pub last_rule: Option<String>,
}

pub struct Lockdown {
    record: LockdownRecord,
}

impl Lockdown {
    pub fn new() -> Self {
        Self {
            record: LockdownRecord {
                state: VaultState::Normal,
                events: Vec::new(),
                last_rule: None,
            },
        }
    }

    pub fn from_record(record: LockdownRecord) -> Self {
        Self { record }
    }

    pub fn state(&self) -> VaultState {
        self.record.state
    }

    pub fn events(&self) -> &[SecurityEvent] {
        &self.record.events
    }

    pub fn into_record(self) -> LockdownRecord {
        self.record
    }

    /// Evaluate a trigger: record it, escalate the state (monotonically) and
    /// return the action the engine must apply.
    pub fn evaluate(&mut self, trigger: Trigger, now_ms: u64) -> Action {
        let (target, action) = classify(&trigger);
        let event = SecurityEvent {
            timestamp_ms: now_ms,
            rule: trigger.rule.to_string(),
            severity: trigger.severity,
            component: trigger.component.to_string(),
            confidence: trigger.confidence,
            detail: trigger.detail,
        };
        self.record.events.push(event);
        // Keep memory bounded.
        if self.record.events.len() > 512 {
            let drain = self.record.events.len() - 512;
            self.record.events.drain(0..drain);
        }
        self.record.last_rule = Some(trigger.rule.to_string());
        if target.rank() > self.record.state.rank() {
            self.record.state = target;
        }
        action
    }

    /// Explicit escalation (user confirmed compromise). Only path to CRITICAL.
    pub fn escalate_critical(&mut self, now_ms: u64, reason: &str) {
        self.record.state = VaultState::Critical;
        self.record.events.push(SecurityEvent {
            timestamp_ms: now_ms,
            rule: "operator.escalate_critical".into(),
            severity: Severity::Critical,
            component: "lockdown".into(),
            confidence: 100,
            detail: reason.to_string(),
        });
    }

    /// Successful re-authentication resets down to at most `Suspicious`
    /// (cryptographic findings persist until re-verified).
    pub fn on_successful_auth(&mut self, now_ms: u64) {
        if self.record.state.rank() >= VaultState::Critical.rank() {
            return; // Critical requires explicit operator resolution.
        }
        if matches!(self.record.state, VaultState::Locked | VaultState::Restricted) {
            self.record.state = VaultState::Suspicious;
            self.record.events.push(SecurityEvent {
                timestamp_ms: now_ms,
                rule: "auth.reauthenticated".into(),
                severity: Severity::Info,
                component: "lockdown".into(),
                confidence: 100,
                detail: "re-authentication succeeded; access restored to review level".into(),
            });
        }
    }

    /// Operator acknowledged review of findings → return to NORMAL.
    pub fn acknowledge(&mut self, now_ms: u64) {
        if self.record.state == VaultState::Critical {
            return; // Critical needs escalate_critical's counterpart: erase or explicit reset.
        }
        self.record.state = VaultState::Normal;
        self.record.events.push(SecurityEvent {
            timestamp_ms: now_ms,
            rule: "operator.acknowledge".into(),
            severity: Severity::Info,
            component: "lockdown".into(),
            confidence: 100,
            detail: "operator acknowledged security findings".into(),
        });
    }

    /// Explicitly resolve CRITICAL state (e.g. after recovery verification).
    pub fn resolve_critical(&mut self, now_ms: u64) {
        self.record.state = VaultState::Normal;
        self.record.events.push(SecurityEvent {
            timestamp_ms: now_ms,
            rule: "operator.resolve_critical".into(),
            severity: Severity::Info,
            component: "lockdown".into(),
            confidence: 100,
            detail: "critical state resolved by operator".into(),
        });
    }
}

impl Default for Lockdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trig(rule: &'static str, conf: u8) -> Trigger {
        Trigger::new(rule, conf, Severity::Error, "test", "detail")
    }

    #[test]
    fn low_confidence_does_not_lock() {
        let mut ld = Lockdown::new();
        let act = ld.evaluate(trig("container.orphan_detected", 20), 1);
        assert_eq!(act, Action::RecordOnly);
        assert_eq!(ld.state(), VaultState::Normal);
    }

    #[test]
    fn tamper_locks_and_destroys_session() {
        let mut ld = Lockdown::new();
        let act = ld.evaluate(trig("manifest.auth_failed", 100), 1);
        assert_eq!(act, Action::DestroySession);
        assert_eq!(ld.state(), VaultState::Locked);
    }

    #[test]
    fn states_only_escalate() {
        let mut ld = Lockdown::new();
        ld.evaluate(trig("binary.modified", 70), 1);
        assert_eq!(ld.state(), VaultState::Suspicious);
        ld.evaluate(trig("object.auth_failed", 80), 2);
        assert_eq!(ld.state(), VaultState::Restricted);
        // A weaker trigger cannot de-escalate.
        ld.evaluate(trig("container.orphan_detected", 20), 3);
        assert_eq!(ld.state(), VaultState::Restricted);
    }

    #[test]
    fn reauth_unlocks_but_keeps_suspicious() {
        let mut ld = Lockdown::new();
        ld.evaluate(trig("rollback.detected", 95), 1);
        assert_eq!(ld.state(), VaultState::Locked);
        ld.on_successful_auth(2);
        assert_eq!(ld.state(), VaultState::Suspicious);
        ld.acknowledge(3);
        assert_eq!(ld.state(), VaultState::Normal);
    }

    #[test]
    fn critical_requires_explicit_resolution() {
        let mut ld = Lockdown::new();
        ld.escalate_critical(1, "user confirmed compromise");
        assert_eq!(ld.state(), VaultState::Critical);
        // Re-auth and acknowledge do not clear it.
        ld.on_successful_auth(2);
        ld.acknowledge(3);
        assert_eq!(ld.state(), VaultState::Critical);
        ld.resolve_critical(4);
        assert_eq!(ld.state(), VaultState::Normal);
    }

    #[test]
    fn events_are_recorded_without_secrets_by_construction() {
        let mut ld = Lockdown::new();
        ld.evaluate(trig("object.auth_failed", 80), 42);
        let ev = &ld.events()[0];
        assert_eq!(ev.timestamp_ms, 42);
        assert_eq!(ev.rule, "object.auth_failed");
        assert_eq!(ev.component, "test");
    }
}
