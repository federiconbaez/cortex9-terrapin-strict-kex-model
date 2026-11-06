use crate::model::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ServerToClient,
    ClientToServer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StreamItem {
    Plain(Msg),
    WithMarkers { msg: Msg, markers: Vec<String> },
}

impl StreamItem {
    pub fn msg(&self) -> Msg {
        match self {
            StreamItem::Plain(m) => *m,
            StreamItem::WithMarkers { msg, .. } => *msg,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AttackOp {
    /// Insert a packet on the wire before honest packet `index`.
    InjectBefore {
        index: usize,
        msg: Msg,
        #[serde(default)]
        forged_encrypted: bool,
    },
    /// Remove honest packet `index` from the wire.
    Drop { index: usize },
    /// Remove strict-KEX markers from honest KEXINIT `index` (forward dir).
    StripMarkers { index: usize },
    /// Remove strict-KEX markers from the receiver's own initial KEXINIT on
    /// its way to the sender (reverse direction).
    StripReverseMarkers,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub description: String,
    pub client: EndpointCfg,
    pub server: EndpointCfg,
    pub binding: CipherBinding,
    pub direction: Direction,
    /// Honest messages sent in the direction under test, starting with the
    /// sender's initial KEXINIT.
    pub stream: Vec<StreamItem>,
    #[serde(default)]
    pub attack: Vec<AttackOp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Completed, every honest upper-layer message delivered, nothing extra.
    Intact,
    /// Completed but at least one honest upper-layer message was lost.
    SilentTruncation,
    /// Completed but delivered contents differ in another way.
    SilentModification,
    /// Connection terminated while the attacker had acted.
    Detected,
    /// Connection terminated with no attacker activity.
    FalseAbort,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub scenario: String,
    pub sender_strict: bool,
    pub receiver_strict: bool,
    pub termination: Option<Termination>,
    pub terminated_at_wire_index: Option<usize>,
    pub honest_upper: Vec<Msg>,
    pub delivered_upper: Vec<Msg>,
    pub lost_honest_indices: Vec<usize>,
    pub verdict: Verdict,
    pub trace: Vec<TraceStep>,
}

fn initial_markers(role: Role, cfg: &EndpointCfg) -> Vec<String> {
    if cfg.supports_strict {
        vec![role.own_marker().to_string()]
    } else {
        vec![]
    }
}

pub fn run(sc: &Scenario) -> Outcome {
    let (srole, rrole, scfg, rcfg) = match sc.direction {
        Direction::ServerToClient => (Role::Server, Role::Client, sc.server, sc.client),
        Direction::ClientToServer => (Role::Client, Role::Server, sc.client, sc.server),
    };
    let mut tx = Sender::new(srole, scfg, sc.binding);
    let mut rx = Receiver::new(rrole, rcfg, sc.binding);

    // Reverse direction: only the receiver's initial KEXINIT matters here.
    let strip_rev = sc
        .attack
        .iter()
        .any(|o| matches!(o, AttackOp::StripReverseMarkers));
    let mut rev_markers = initial_markers(rrole, &rcfg);
    if strip_rev && !rev_markers.is_empty() {
        rev_markers.clear();
        rx.own_kexinit_intact_at_peer = false;
    }
    tx.learn_peer_initial_kexinit(&rev_markers);

    // Honest sender produces packets.
    let mut honest: Vec<WirePacket> = Vec::new();
    let mut kexinit_seen = 0usize;
    for (i, item) in sc.stream.iter().enumerate() {
        let m = item.msg();
        let markers = match item {
            StreamItem::WithMarkers { markers, .. } => markers.clone(),
            StreamItem::Plain(Msg::Kexinit) if kexinit_seen == 0 => initial_markers(srole, &scfg),
            _ => vec![],
        };
        if m == Msg::Kexinit {
            kexinit_seen += 1;
        }
        honest.push(tx.send(m, markers, i));
    }

    // Attacker rewrites the wire.
    let mut wire: Vec<WirePacket> = Vec::new();
    for (i, p) in honest.iter().enumerate() {
        for op in &sc.attack {
            if let AttackOp::InjectBefore {
                index,
                msg,
                forged_encrypted,
            } = op
                && *index == i
            {
                wire.push(WirePacket {
                    msg: *msg,
                    tag: if *forged_encrypted {
                        Tag::Forged
                    } else {
                        Tag::None
                    },
                    markers: vec![],
                    honest_index: None,
                    tampered: false,
                });
            }
        }
        if sc
            .attack
            .iter()
            .any(|o| matches!(o, AttackOp::Drop { index } if *index == i))
        {
            continue;
        }
        let mut q = p.clone();
        if sc
            .attack
            .iter()
            .any(|o| matches!(o, AttackOp::StripMarkers { index } if *index == i))
            && !q.markers.is_empty()
        {
            q.markers.clear();
            q.tampered = true;
        }
        wire.push(q);
    }

    let mut trace = Vec::new();
    let mut termination = None;
    let mut term_at = None;
    for (wi, p) in wire.iter().enumerate() {
        let before = rx.recv_seq;
        let phase_before = rx.phase;
        let res = rx.receive(p);
        let action = match &res {
            Ok(a) => a.clone(),
            Err(t) => format!("terminate:{t:?}"),
        };
        trace.push(TraceStep {
            wire_index: wi,
            msg: p.msg,
            honest_index: p.honest_index,
            tag: p.tag,
            recv_seq_before: before,
            recv_seq_after: rx.recv_seq,
            phase_before,
            phase_after: rx.phase,
            strict: rx.strict,
            action,
        });
        if let Err(t) = res {
            termination = Some(t);
            term_at = Some(wi);
            break;
        }
    }

    // In the client->server direction the server cannot see that its own
    // KEXINIT was altered; the client detects it when verifying the host
    // signature over H (RFC 4253 §8). Account for that peer-side detection.
    if termination.is_none()
        && sc.direction == Direction::ClientToServer
        && (rx.peer_kexinit_tampered || !rx.own_kexinit_intact_at_peer)
    {
        termination = Some(Termination::ExchangeHashMismatch);
    }

    let honest_upper_idx: Vec<usize> = sc
        .stream
        .iter()
        .enumerate()
        .filter(|(_, it)| it.msg().is_upper_layer())
        .map(|(i, _)| i)
        .collect();
    let honest_upper: Vec<Msg> = honest_upper_idx
        .iter()
        .map(|&i| sc.stream[i].msg())
        .collect();
    let delivered_upper: Vec<Msg> = rx.delivered.iter().map(|(m, _)| *m).collect();
    let delivered_idx: Vec<Option<usize>> = rx.delivered.iter().map(|(_, i)| *i).collect();
    let lost: Vec<usize> = honest_upper_idx
        .iter()
        .copied()
        .filter(|i| !delivered_idx.contains(&Some(*i)))
        .collect();

    let attacker_active = !sc.attack.is_empty();
    let verdict = if termination.is_some() {
        if attacker_active {
            Verdict::Detected
        } else {
            Verdict::FalseAbort
        }
    } else if !lost.is_empty() {
        Verdict::SilentTruncation
    } else if delivered_idx.iter().any(|i| i.is_none()) || delivered_upper != honest_upper {
        Verdict::SilentModification
    } else {
        Verdict::Intact
    };

    Outcome {
        scenario: sc.name.clone(),
        sender_strict: tx.strict,
        receiver_strict: rx.strict,
        termination,
        terminated_at_wire_index: term_at,
        honest_upper,
        delivered_upper,
        lost_honest_indices: lost,
        verdict,
        trace,
    }
}
