//! Shared protocol types for zecret-dms: envelope format, session state machine,
//! and crypto helpers used by all roles.
//!
//! Normative specs: `docs/envelope-v0.md`, `docs/session-v0.md`, `docs/policy-v1.md`.

/// Envelope format version written into every record.
pub const PROTOCOL_VERSION: &str = "DMS/1";

pub mod envelope;
pub mod hash;
pub mod keys;
pub mod net;
pub mod policy;
pub mod record;
pub mod session;

pub use net::Net;
