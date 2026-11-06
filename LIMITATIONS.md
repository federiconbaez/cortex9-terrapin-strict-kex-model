# Limitations

- **Not a reproduction.** No SSH implementation is executed or tested. No
  network I/O, no real KEX, ciphers, MACs or signatures.
- **Cipher bindings are abstractions.** `SeqBound` treats verification as
  "sender seq == receiver seq and the packet was produced by the honest
  sender". `InvocationCounter` treats it as "per-key counters match". Real
  ChaCha20-Poly1305 and EtM details (for example the length field
  encryption, block boundaries, and the CBC-EtM variant discussed in the
  Terrapin paper) are not modelled.
- **Exchange hash is a flag.** KEXINIT tampering is detected at the
  key-exchange reply via a `tampered` flag instead of computing H. In
  fixture 12 the client first rejects the injected IGNORE under (a); a real
  connection could fail at either point.
- **One direction at a time.** Each scenario follows one direction
  (server→client or client→server). In the client→server direction, KEXINIT
  tampering is treated as detected by the peer.
- **Fixed message set.** Only the message types in `src/model.rs::Msg` exist.
  Message contents (algorithm lists, key material) are not modelled beyond
  the strict markers.
- **Sweep counts are model facts.** The numbers in README and
  `results/sweep.csv` describe this model under these fixtures, not field
  measurements.
- **Defect variants are hypothetical.** `reset_seq_first_only` and disabling
  (a) or (b) are counterfactuals for testing the model; they are not claims
  about any shipped implementation.
- **Fixture 17** (both sides reset only at the first NEWKEYS) is `intact`:
  a consistent but non-compliant pair is not caught by a benign-only check.
- CI is defined in `.github/workflows/ci.yml` but has only been run locally
  with the same commands (rustc 1.99.1), not on a hosted runner.
