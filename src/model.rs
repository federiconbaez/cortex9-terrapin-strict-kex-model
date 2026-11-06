use serde::{Deserialize, Serialize};

pub const MARKER_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const MARKER_SERVER: &str = "kex-strict-s-v00@openssh.com";

/// Message types used by the model (numbers from RFC 4253 §12, RFC 8308,
/// RFC 5656, RFC 4252, RFC 4254).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    ExtInfo,
    Kexinit,
    Newkeys,
    KexEcdhInit,
    KexEcdhReply,
    UserauthRequest,
    UserauthSuccess,
    ChannelData,
}

impl Msg {
    pub fn code(self) -> u8 {
        match self {
            Msg::Ignore => 2,
            Msg::Unimplemented => 3,
            Msg::Debug => 4,
            Msg::ServiceRequest => 5,
            Msg::ServiceAccept => 6,
            Msg::ExtInfo => 7,
            Msg::Kexinit => 20,
            Msg::Newkeys => 21,
            Msg::KexEcdhInit => 30,
            Msg::KexEcdhReply => 31,
            Msg::UserauthRequest => 50,
            Msg::UserauthSuccess => 52,
            Msg::ChannelData => 94,
        }
    }
    /// RFC 4253 §11: IGNORE/DEBUG/UNIMPLEMENTED may be received at any time
    /// by a legacy implementation.
    pub fn is_any_time(self) -> bool {
        matches!(self, Msg::Ignore | Msg::Debug | Msg::Unimplemented)
    }
    /// Messages surfaced to the upper layer when established.
    pub fn is_upper_layer(self) -> bool {
        !self.is_any_time()
            && !matches!(
                self,
                Msg::Kexinit | Msg::Newkeys | Msg::KexEcdhInit | Msg::KexEcdhReply
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn own_marker(self) -> &'static str {
        match self {
            Role::Client => MARKER_CLIENT,
            Role::Server => MARKER_SERVER,
        }
    }
    pub fn peer_marker(self) -> &'static str {
        match self {
            Role::Client => MARKER_SERVER,
            Role::Server => MARKER_CLIENT,
        }
    }
    /// The key-exchange method message this role expects from its peer
    /// (ECDH, RFC 5656 §4).
    pub fn expected_kex_method_msg(self) -> Msg {
        match self {
            Role::Client => Msg::KexEcdhReply,
            Role::Server => Msg::KexEcdhInit,
        }
    }
}

/// How the per-packet integrity tag binds to receiver state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherBinding {
    /// MAC computed over the implicit uint32 sequence number (RFC 4253 §6.4).
    /// Stands for chacha20-poly1305@openssh.com and *-etm@openssh.com modes.
    SeqBound,
    /// AEAD nonce from a per-key invocation counter incremented per encrypted
    /// packet (RFC 5647 §7.1). Stands for AES-GCM.
    InvocationCounter,
}

/// Per-endpoint configuration. `reject_unexpected` and `reset_seq` exist so
/// that each strict-KEX defense can be switched off independently for
/// counterfactual runs; real OpenSSH applies both when strict is negotiated.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct EndpointCfg {
    pub supports_strict: bool,
    #[serde(default = "yes")]
    pub reject_unexpected: bool,
    #[serde(default = "yes")]
    pub reset_seq: bool,
    /// Defect variant for counterfactuals: reset only at the first NEWKEYS
    /// instead of at every NEWKEYS as PROTOCOL §1.9 (b) requires.
    #[serde(default)]
    pub reset_seq_first_only: bool,
}
fn yes() -> bool {
    true
}

impl EndpointCfg {
    pub fn legacy() -> Self {
        Self {
            supports_strict: false,
            reject_unexpected: true,
            reset_seq: true,
            reset_seq_first_only: false,
        }
    }
    pub fn strict() -> Self {
        Self {
            supports_strict: true,
            reject_unexpected: true,
            reset_seq: true,
            reset_seq_first_only: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    /// Plaintext packet (before NEWKEYS in this direction).
    None,
    /// Tag bound to this sequence number.
    Seq(u32),
    /// Tag bound to this AEAD invocation counter.
    Inv(u64),
    /// Attacker-produced bytes claiming to be encrypted; verifies under no
    /// receiver state.
    Forged,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePacket {
    pub msg: Msg,
    pub tag: Tag,
    pub markers: Vec<String>,
    /// Index in the honest sender stream; None when injected by the attacker.
    pub honest_index: Option<usize>,
    /// Set when the attacker altered the KEXINIT payload in transit.
    pub tampered: bool,
}

/// Sending half of an endpoint for one direction.
#[derive(Clone, Debug)]
pub struct Sender {
    pub role: Role,
    pub cfg: EndpointCfg,
    pub binding: CipherBinding,
    pub send_seq: u32,
    pub inv_out: u64,
    pub keys_out: bool,
    pub strict: bool,
    pub newkeys_sent: u32,
}

impl Sender {
    pub fn new(role: Role, cfg: EndpointCfg, binding: CipherBinding) -> Self {
        Self {
            role,
            cfg,
            binding,
            send_seq: 0,
            inv_out: 0,
            keys_out: false,
            strict: false,
            newkeys_sent: 0,
        }
    }

    /// Called when this endpoint has processed the peer's *initial* KEXINIT
    /// (PROTOCOL §1.9: markers only valid in the initial KEXINIT).
    pub fn learn_peer_initial_kexinit(&mut self, peer_markers: &[String]) {
        self.strict =
            self.cfg.supports_strict && peer_markers.iter().any(|m| m == self.role.peer_marker());
    }

    pub fn send(&mut self, msg: Msg, markers: Vec<String>, honest_index: usize) -> WirePacket {
        let tag = if self.keys_out {
            match self.binding {
                CipherBinding::SeqBound => Tag::Seq(self.send_seq),
                CipherBinding::InvocationCounter => Tag::Inv(self.inv_out),
            }
        } else {
            Tag::None
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        if self.keys_out && self.binding == CipherBinding::InvocationCounter {
            self.inv_out += 1;
        }
        if msg == Msg::Newkeys {
            self.keys_out = true;
            self.inv_out = 0; // new keys, new IV (RFC 5647 §7.1)
            self.newkeys_sent += 1;
            if self.strict
                && self.cfg.reset_seq
                && (!self.cfg.reset_seq_first_only || self.newkeys_sent == 1)
            {
                self.send_seq = 0;
            }
        }
        WirePacket {
            msg,
            tag,
            markers,
            honest_index: Some(honest_index),
            tampered: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    AwaitKexinit,
    AwaitKexMethod,
    AwaitNewkeys,
    Established,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Termination {
    /// Tag did not verify under receiver state (seq / invocation mismatch,
    /// forged bytes, or plaintext after keys were activated).
    IntegrityFailure,
    /// Encrypted bytes arrived while the receiver had no keys yet.
    Undecryptable,
    /// PROTOCOL §1.9 (a): unexpected packet during initial strict KEX.
    StrictUnexpectedDuringInitialKex,
    /// PROTOCOL §1.9 (a): first packet received was not KEXINIT.
    StrictFirstPacketNotKexinit,
    /// Message not valid in the current key-exchange stage.
    OutOfSequence,
    /// KEXINIT payloads differ between what was sent and received, so the
    /// exchange hash H (RFC 4253 §8 covers I_C and I_S) does not match and
    /// the host signature fails.
    ExchangeHashMismatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceStep {
    pub wire_index: usize,
    pub msg: Msg,
    pub honest_index: Option<usize>,
    pub tag: Tag,
    pub recv_seq_before: u32,
    pub recv_seq_after: u32,
    pub phase_before: Phase,
    pub phase_after: Phase,
    pub strict: bool,
    pub action: String,
}

/// Receiving half of an endpoint for one direction.
#[derive(Clone, Debug)]
pub struct Receiver {
    pub role: Role,
    pub cfg: EndpointCfg,
    pub binding: CipherBinding,
    pub recv_seq: u32,
    pub inv_in: u64,
    pub keys_in: bool,
    pub strict: bool,
    pub phase: Phase,
    pub initial_kex_done: bool,
    pub received_count: u64,
    pub newkeys_received: u32,
    pub saw_initial_kexinit: bool,
    /// Whether the receiver's own KEXINIT reached the peer unmodified.
    pub own_kexinit_intact_at_peer: bool,
    pub peer_kexinit_tampered: bool,
    pub delivered: Vec<(Msg, Option<usize>)>,
}

impl Receiver {
    pub fn new(role: Role, cfg: EndpointCfg, binding: CipherBinding) -> Self {
        Self {
            role,
            cfg,
            binding,
            recv_seq: 0,
            inv_in: 0,
            keys_in: false,
            strict: false,
            phase: Phase::AwaitKexinit,
            initial_kex_done: false,
            received_count: 0,
            newkeys_received: 0,
            saw_initial_kexinit: false,
            own_kexinit_intact_at_peer: true,
            peer_kexinit_tampered: false,
            delivered: Vec::new(),
        }
    }

    fn check_tag(&self, p: &WirePacket) -> Result<(), Termination> {
        if self.keys_in {
            let ok = match (self.binding, p.tag) {
                (CipherBinding::SeqBound, Tag::Seq(s)) => s == self.recv_seq,
                (CipherBinding::InvocationCounter, Tag::Inv(i)) => i == self.inv_in,
                _ => false,
            };
            if ok {
                Ok(())
            } else {
                Err(Termination::IntegrityFailure)
            }
        } else if p.tag != Tag::None {
            Err(Termination::Undecryptable)
        } else {
            Ok(())
        }
    }

    fn strict_initial_a(&self) -> bool {
        self.strict && self.cfg.reject_unexpected && !self.initial_kex_done
    }

    /// Process one packet. Returns a description of the transition.
    pub fn receive(&mut self, p: &WirePacket) -> Result<String, Termination> {
        self.check_tag(p)?;
        let seq_of_packet = self.recv_seq;
        self.recv_seq = self.recv_seq.wrapping_add(1);
        if self.keys_in && self.binding == CipherBinding::InvocationCounter {
            self.inv_in += 1;
        }
        self.received_count += 1;

        match self.phase {
            Phase::AwaitKexinit => match p.msg {
                Msg::Kexinit => {
                    if !self.saw_initial_kexinit {
                        self.saw_initial_kexinit = true;
                        self.peer_kexinit_tampered = p.tampered;
                        self.strict = self.cfg.supports_strict
                            && p.markers.iter().any(|m| m == self.role.peer_marker());
                        if self.strict && self.cfg.reject_unexpected && seq_of_packet != 0 {
                            return Err(Termination::StrictFirstPacketNotKexinit);
                        }
                    }
                    self.phase = Phase::AwaitKexMethod;
                    Ok(format!("kexinit(strict={})", self.strict))
                }
                m if m.is_any_time() => {
                    // Strictness is unknown until KEXINIT arrives; the check
                    // above (seq of KEXINIT != 0) catches this case.
                    Ok("ignored_before_kexinit".into())
                }
                _ => Err(Termination::OutOfSequence),
            },
            Phase::AwaitKexMethod | Phase::AwaitNewkeys => {
                if p.msg.is_any_time() {
                    if self.strict_initial_a() {
                        return Err(Termination::StrictUnexpectedDuringInitialKex);
                    }
                    return Ok("ignored_during_kex".into());
                }
                let expected = if self.phase == Phase::AwaitKexMethod {
                    self.role.expected_kex_method_msg()
                } else {
                    Msg::Newkeys
                };
                if p.msg != expected {
                    return Err(if self.strict_initial_a() {
                        Termination::StrictUnexpectedDuringInitialKex
                    } else {
                        Termination::OutOfSequence
                    });
                }
                if p.msg == Msg::KexEcdhReply
                    && (self.peer_kexinit_tampered || !self.own_kexinit_intact_at_peer)
                {
                    return Err(Termination::ExchangeHashMismatch);
                }
                if p.msg == Msg::Newkeys {
                    self.keys_in = true;
                    self.inv_in = 0;
                    self.newkeys_received += 1;
                    let reset = self.strict
                        && self.cfg.reset_seq
                        && (!self.cfg.reset_seq_first_only || self.newkeys_received == 1);
                    if reset {
                        self.recv_seq = 0;
                    }
                    self.initial_kex_done = true;
                    self.phase = Phase::Established;
                    return Ok(format!("newkeys(reset={reset})"));
                }
                self.phase = Phase::AwaitNewkeys;
                Ok("kex_method".into())
            }
            Phase::Established => match p.msg {
                Msg::Kexinit => {
                    // Re-exchange: markers MUST be ignored (PROTOCOL §1.9).
                    self.phase = Phase::AwaitKexMethod;
                    Ok("rekey_kexinit(markers_ignored)".into())
                }
                m if m.is_any_time() => Ok("ignored".into()),
                Msg::Newkeys | Msg::KexEcdhInit | Msg::KexEcdhReply => {
                    Err(Termination::OutOfSequence)
                }
                m => {
                    self.delivered.push((m, p.honest_index));
                    Ok("delivered".into())
                }
            },
        }
    }
}
