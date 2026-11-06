//! Abstract state-machine model of the SSH binary packet protocol sequence
//! counters and the OpenSSH "strict KEX" extension (PROTOCOL §1.9).
//!
//! No sockets, no cryptography. A MAC/AEAD tag is modelled as the value the
//! receiver must reproduce from its own state (implicit sequence number for
//! seq-bound MACs, invocation counter for AEAD per RFC 5647). The verdict for
//! each scenario is derived from the transitions executed, never written by
//! hand.

pub mod model;
pub mod scenario;

pub use model::*;
pub use scenario::*;
