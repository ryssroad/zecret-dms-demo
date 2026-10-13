# zecret-dms-demo

A reviewable, offline protocol-core demonstration for a private dead man's switch built around Zcash memo transport. This is an early research prototype, not a complete DMS or a system for protecting real secrets.

## What is implemented

- Signed records with strict Ed25519 validation and domain-separated hashes.
- Fixed-size XChaCha20-Poly1305 envelopes with binary and Base64 memo representations.
- Canonical PolicyV1 and SetupV1 serialization and validation.
- A deterministic session state machine: heartbeat, panic/duress, cancellation, key rotation, recovery generations, equivocation, confirmation-height calculation, and fixed release deadlines.
- Rust unit, integration and property tests, public deterministic fixtures, and a separate Python vector checker.

The state machine consumes already parsed records in canonical block order. It does not fetch or validate a chain. A `Released` state is a decision in memory; it does not deliver any secret shares.

## What remains to be built and demonstrated

Owner, guardian and recipient applications; authenticated setup and actual readiness acknowledgements; threshold sharing, delivery and reconstruction; a complete chain scanner with completeness checks; durable state and reorg handling; irreversible delivery records; gateways and user workflows. Network transport, relay and wallet code are deliberately outside this small demo.

Snapshot/replay tests exercise in-memory state, not crash-safe storage or a running guardian. Test success is not evidence of end-to-end release, production security, operator independence or censorship resistance. No independent human cryptography/protocol audit is claimed.

## Layout

| Path | Content |
| --- | --- |
| `crates/zecret-core/` | Protocol implementation and Rust tests |
| `docs/envelope-v0.md` | Envelope format and cryptographic profile |
| `docs/policy-v1.md` | Policy and setup formats |
| `docs/session-v0.md` | Transition and timing rules |
| `docs/test-vectors/` | Public fixtures; all embedded test secrets are intentionally public |
| `scripts/verify_vectors.py` | Separate Python validation of the fixtures |
| `docs/verification.md` | Checks performed on this prepared tree and their limits |
| `docs/publication-checklist.md` | Publication scope and review record |
| `THIRD_PARTY.md` | Dependency license inventory and review scope |
| `THIRD_PARTY_NOTICES.txt` | Preserved third-party license texts and notices |

Specifications are currently in Russian. Their references to guardian/network behavior describe integration requirements, not additional implemented components. Review issue identifiers retained in the specifications are historical labels, not claims of an external audit.

## Offline checks

With Rust 1.96.0 and the locked dependencies already installed and cached:

```sh
cargo +1.96.0 test --workspace --locked --offline
cargo +1.96.0 fmt --all --check
```

Clippy also requires its component to be already installed. The recorded lint check used the installed `stable` toolchain (Rust 1.98.0), because Clippy was unavailable for the pinned 1.96.0 toolchain:

```sh
cargo +stable clippy --workspace --all-targets --locked --offline -- -D warnings
```

The optional vector checker requires an already installed Python `cryptography` package:

```sh
python3 scripts/verify_vectors.py
```

These commands do not require a node, wallet, network account or API. On a machine without the toolchain or cached dependencies, offline verification cannot proceed; dependency installation is a separate action. Never reuse test keys, seeds or nonces for real data.

## Research goals

Future work includes an independent human audit of the cryptography and protocol; trials with independent guardian operators running their own full Zcash nodes in different jurisdictions; and integration, real-network, gateway and user testing. These are goals for funding, not completed security claims.

## License and publication scope

Original project code and documentation: [MIT](LICENSE), copyright 2026 Denis Shevchenko. Dependencies keep their own terms; see [THIRD_PARTY.md](THIRD_PARTY.md) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

This repository starts with a fresh history containing only the cleaned protocol-core demo. Operational history and infrastructure details are excluded. Development and review used AI assistance; the offline tests and separate vector checker do not replace independent human auditing.
