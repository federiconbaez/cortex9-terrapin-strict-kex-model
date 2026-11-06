use cortex9_terrapin_strict_kex_model::*;
use std::collections::BTreeMap;
use std::fs;

#[derive(serde::Deserialize)]
struct Expect {
    verdict: String,
    termination: Option<String>,
}

fn load(name: &str) -> Scenario {
    let p = format!(
        "{}/fixtures/scenarios/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn every_fixture_matches_expected_file() {
    let exp: BTreeMap<String, Expect> = serde_json::from_str(
        &fs::read_to_string(format!(
            "{}/fixtures/expected.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let dir = format!("{}/fixtures/scenarios", env!("CARGO_MANIFEST_DIR"));
    let mut seen = 0;
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_stem().unwrap().to_str().unwrap().to_string();
        let o = run(&load(&name));
        let want = exp
            .get(&name)
            .unwrap_or_else(|| panic!("no expectation for {name}"));
        let got_v = serde_json::to_value(o.verdict)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let got_t = o.termination.as_ref().map(|t| format!("{t:?}"));
        assert_eq!(got_v, want.verdict, "{name} verdict");
        assert_eq!(got_t, want.termination, "{name} termination");
        seen += 1;
    }
    assert_eq!(seen, exp.len(), "fixtures and expectations out of sync");
}

#[test]
fn rekey_resets_sequence_at_every_newkeys_in_strict() {
    let o = run(&load("03_benign_strict_rekey"));
    let resets: Vec<_> = o
        .trace
        .iter()
        .filter(|s| s.action == "newkeys(reset=true)")
        .collect();
    assert_eq!(resets.len(), 2);
    for r in resets {
        assert_eq!(r.recv_seq_after, 0);
    }
}

#[test]
fn rekey_markers_do_not_enable_strict() {
    let o = run(&load("15_rekey_markers_ignored"));
    assert!(!o.receiver_strict);
    assert!(o.trace.iter().all(|s| !s.strict));
    let resets = o
        .trace
        .iter()
        .filter(|s| s.action == "newkeys(reset=true)")
        .count();
    assert_eq!(resets, 0);
}

#[test]
fn legacy_sequence_numbers_never_reset() {
    let mut sc = load("03_benign_strict_rekey");
    sc.client = EndpointCfg::legacy();
    sc.server = EndpointCfg::legacy();
    let o = run(&sc);
    assert_eq!(o.verdict, Verdict::Intact);
    let seqs: Vec<u32> = o.trace.iter().map(|s| s.recv_seq_before).collect();
    let want: Vec<u32> = (0..seqs.len() as u32).collect();
    assert_eq!(
        seqs, want,
        "RFC 4253 6.4: incremented after every packet, never reset"
    );
}

#[test]
fn each_defense_is_necessary_somewhere() {
    // (a) alone stops the injection; (b) alone stops it via mismatch; with
    // neither, the edit succeeds even though strict was negotiated.
    let mut sc = load("06_terrapin_strict_full");
    let none = EndpointCfg {
        reject_unexpected: false,
        reset_seq: false,
        ..EndpointCfg::strict()
    };
    sc.client = none;
    sc.server = none;
    let o = run(&sc);
    assert!(o.receiver_strict && o.sender_strict);
    assert_eq!(o.verdict, Verdict::SilentTruncation);
}

#[test]
fn sequence_counter_wraps_at_u32() {
    let mut rx = Receiver::new(Role::Client, EndpointCfg::legacy(), CipherBinding::SeqBound);
    rx.recv_seq = u32::MAX;
    let p = WirePacket {
        msg: Msg::Ignore,
        tag: Tag::None,
        markers: vec![],
        honest_index: None,
        tampered: false,
    };
    rx.receive(&p).unwrap();
    assert_eq!(rx.recv_seq, 0);
}

#[test]
fn plaintext_after_newkeys_is_rejected() {
    let mut rx = Receiver::new(Role::Client, EndpointCfg::legacy(), CipherBinding::SeqBound);
    rx.keys_in = true;
    rx.phase = Phase::Established;
    let p = WirePacket {
        msg: Msg::Ignore,
        tag: Tag::None,
        markers: vec![],
        honest_index: None,
        tampered: false,
    };
    assert_eq!(rx.receive(&p), Err(Termination::IntegrityFailure));
}

#[test]
fn strict_requires_peer_marker_not_own() {
    let mut tx = Sender::new(Role::Server, EndpointCfg::strict(), CipherBinding::SeqBound);
    tx.learn_peer_initial_kexinit(&[MARKER_SERVER.to_string()]);
    assert!(!tx.strict, "own marker echoed back must not enable strict");
    tx.learn_peer_initial_kexinit(&[MARKER_CLIENT.to_string()]);
    assert!(tx.strict);
}
