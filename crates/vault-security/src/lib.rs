//! Vault security subsystem: lockdown engine, tamper detection, platform
//! facilities, and the machine-bound control state.

pub mod control;
pub mod error;
pub mod lockdown;
pub mod platform;

pub use control::{ControlState, CAPABILITY_DPAPI};
pub use error::SecurityError;
pub use lockdown::{
    classify, Action, Lockdown, LockdownRecord, SecurityEvent, Severity, Trigger, VaultState,
};
pub use platform::{probe_capabilities, PlatformCapability};
