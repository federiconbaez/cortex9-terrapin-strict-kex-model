# cortex9-terrapin-strict-kex-model

[Español](README.es.md) · [CI](https://github.com/federiconbaez/cortex9-terrapin-strict-kex-model/actions/workflows/ci.yml)

An abstract, executable state model of the SSH transport sequence-number
binding and the two OpenSSH "strict KEX" countermeasures, used to reason about
the Terrapin prefix-truncation attack (CVE-2023-48795).

**This is a model, not a reproduction of CVE-2023-48795.** There are no
sockets, no real key exchange, no real ciphers or MACs, and it cannot be
pointed at any host. See [LIMITATIONS.md](LIMITATIONS.md).

## What is modelled

- A per-direction sender and receiver, each with a `uint32` packet sequence
  number that starts at 0, increments after every packet and wraps at 2^32
  (RFC 4253 §6.4).
- Two ciphertext bindings:
  - `SeqBound`: after NEWKEYS, a packet verifies only if the sender's sequence
    number equals the receiver's (stands in for ChaCha20-Poly1305 / EtM MACs
    keyed on the implicit sequence number).
  - `InvocationCounter`: a per-key counter set to 0 at NEWKEYS and incremented
    per encrypted packet (stands in for AES-GCM, RFC 5647 §7.1).
- Strict-KEX negotiation: each side appends its own marker
  (`kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com`) to the
  **initial** KEXINIT only; strict mode is on for an endpoint only when it sees
  the **peer's** marker in the peer's **initial** KEXINIT. Markers in later
  KEXINITs are ignored.
- Countermeasure (a): during the initial KEX, terminate on any unexpected or
  out-of-sequence packet, including IGNORE/DEBUG, and if the first packet is not
  KEXINIT.
- Countermeasure (b): reset the sequence number to 0 after sending or receiving
  NEWKEYS, at **every** NEWKEYS.
- Each countermeasure can be switched off independently, and a defect variant
  (`reset_seq_first_only`) resets only at the first NEWKEYS.
- KEXINIT tampering: modifying a KEXINIT (for example stripping a marker) is
  detected at the key-exchange reply, abstracting the fact that both KEXINIT
  payloads are inputs to the exchange hash H (RFC 4253 §8).

Verdicts are **computed** from the receiver's state transitions and the set of
honest upper-layer packets that were not delivered: `intact`,
`silent_truncation`, `silent_modification`, `detected` (attack present and
connection terminated) and `false_abort` (no attacker, connection terminated).
Nothing in the model reads the expected outcome.

## Layout

| Path | Content |
|---|---|
| `src/model.rs` | Messages, endpoint configuration, `Sender`, `Receiver`, terminations |
| `src/scenario.rs` | Scenario format, attacker wire edits, verdict computation |
| `src/bin/terrapin-model.rs` | CLI |
| `fixtures/scenarios/*.json` | 22 scenarios (inputs only) |
| `fixtures/expected.json` | Expected verdicts, kept separate; read only by tests |
| `fixtures/sweep/*.json` | Base scenarios for the counterfactual sweep |
| `tests/fixtures.rs` | Integration and unit tests |
| `tests/practice.rs` | Checks the claims made in PRACTICE.md |
| `PRACTICE.md` | Graded offline exercises (ES, EN summary) |
| `results/` | Generated CSV/JSON and `SHA256SUMS` |

## Usage

```sh
cargo test
cargo run --release --bin terrapin-model -- run fixtures/scenarios/04_terrapin_legacy_seqbound.json
cargo run --release --bin terrapin-model -- matrix fixtures/scenarios fixtures/sweep results
(cd results && sha256sum -c SHA256SUMS)
```

## Results (generated, `results/scenarios.csv`)

| Scenario | Verdict | Termination |
|---|---|---|
| 01_benign_legacy | intact | – |
| 02_benign_strict | intact | – |
| 03_benign_strict_rekey | intact | – |
| 04_terrapin_legacy_seqbound | silent_truncation (EXT_INFO lost) | – |
| 05_terrapin_legacy_invocation_counter | detected | IntegrityFailure |
| 06_terrapin_strict_full | detected | StrictUnexpectedDuringInitialKex |
| 07_terrapin_strict_a_only | detected | StrictUnexpectedDuringInitialKex |
| 08_terrapin_strict_b_only | detected | IntegrityFailure |
| 09_terrapin_server_only_supports | silent_truncation | – |
| 10_terrapin_client_only_supports | silent_truncation | – |
| 11_strip_forward_markers | detected | ExchangeHashMismatch |
| 12_strip_reverse_markers | detected | StrictUnexpectedDuringInitialKex |
| 13_strict_ignore_before_kexinit | detected | StrictFirstPacketNotKexinit |
| 14_legacy_ignore_before_kexinit | detected | IntegrityFailure |
| 15_rekey_markers_ignored | silent_truncation | – |
| 16_reset_first_only_receiver | false_abort | IntegrityFailure |
| 17_reset_first_only_both | intact | – |
| 18_forged_encrypted_injection | detected | IntegrityFailure |
| 19_terrapin_c2s_legacy | silent_truncation | – |
| 20_terrapin_c2s_strict | detected | StrictUnexpectedDuringInitialKex |
| 21_drop_without_inject_legacy | detected | IntegrityFailure |
| 22_injected_kex_message_strict | detected | StrictUnexpectedDuringInitialKex |

Counterfactual sweep (`results/sweep.csv`, 100 rows = 2 bases × 5 client
configs × 5 server configs × 2 bindings):

- Attack base, `SeqBound`: 14 detected, 11 silent_truncation. Truncation
  happens in the 9 pairs where at least one side is `legacy` (strict not
  negotiated), and in the 2 pairs where the receiving client has neither
  countermeasure and the sending server does not reset either
  (`strict_a_only`, `strict_no_defense`). When the server resets and that
  client does not, the counters diverge and the edit is detected as an
  integrity failure.
- Attack base, `InvocationCounter`: 25 of 25 detected.
- Benign base with one re-exchange, `SeqBound`: 17 intact, 8 false_abort. The
  8 aborts are **deliberately asymmetric, counterfactual configurations**
  built for this sweep: one endpoint has countermeasure (b) switched off
  (`strict_a_only` or `strict_no_defense`) while the other keeps it. PROTOCOL
  requires both endpoints that negotiate strict KEX to apply (b) at every
  NEWKEYS, so these pairs do not describe a conforming implementation. They
  are **not** a defect of strict KEX as specified; they show why (b) has to
  be applied on both sides. Every symmetric configuration is intact.
- Benign base, `InvocationCounter`: 25 of 25 intact.

These counts describe this model only. They are not measurements of any SSH
implementation.

Built and tested locally with rustc 1.99.1 / cargo 1.99.1.

## Sources and limitations

See [SOURCES.md](SOURCES.md) and [LIMITATIONS.md](LIMITATIONS.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
