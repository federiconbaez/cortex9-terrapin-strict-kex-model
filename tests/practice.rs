//! Checks the claims made in PRACTICE.md so the guide cannot drift from the code.
use cortex9_terrapin_strict_kex_model::*;
use std::fs;

fn base() -> Scenario {
    let p = format!(
        "{}/fixtures/scenarios/04_terrapin_legacy_seqbound.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn ops(v: serde_json::Value) -> Vec<AttackOp> {
    serde_json::from_value(v).unwrap()
}

#[test]
fn ex2_two_injected_two_dropped_is_silent() {
    let mut sc = base();
    sc.attack = ops(serde_json::json!([
        {"op":"inject_before","index":1,"msg":"Ignore"},
        {"op":"inject_before","index":1,"msg":"Debug"},
        {"op":"drop","index":3},{"op":"drop","index":4}]));
    let o = run(&sc);
    assert_eq!(o.verdict, Verdict::SilentTruncation);
    assert_eq!(o.lost_honest_indices, vec![3, 4]);
}

#[test]
fn ex2_unbalanced_counts_are_detected() {
    let mut sc = base();
    sc.attack = ops(serde_json::json!([
        {"op":"inject_before","index":1,"msg":"Ignore"},
        {"op":"inject_before","index":1,"msg":"Ignore"},
        {"op":"drop","index":3}]));
    assert_eq!(run(&sc).verdict, Verdict::Detected);
}

#[test]
fn ex3_drop_must_be_first_encrypted_packets() {
    let mut sc = base();
    sc.attack = ops(serde_json::json!([
        {"op":"inject_before","index":1,"msg":"Ignore"},
        {"op":"drop","index":5}]));
    assert_eq!(run(&sc).verdict, Verdict::Detected);
}

#[test]
fn ex3_injection_point_anywhere_before_newkeys() {
    let mut sc = base();
    sc.attack = ops(serde_json::json!([
        {"op":"inject_before","index":2,"msg":"Ignore"},
        {"op":"drop","index":3}]));
    assert_eq!(run(&sc).verdict, Verdict::SilentTruncation);
}

#[test]
fn ex4_debug_is_unexpected_under_strict() {
    let mut sc = base();
    sc.client = EndpointCfg::strict();
    sc.server = EndpointCfg::strict();
    sc.attack = ops(serde_json::json!([
        {"op":"inject_before","index":2,"msg":"Debug"},
        {"op":"drop","index":3}]));
    let o = run(&sc);
    assert_eq!(
        o.termination,
        Some(Termination::StrictUnexpectedDuringInitialKex)
    );
}
