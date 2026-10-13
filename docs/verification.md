# Verification of the prepared demo

The initial offline checks were run locally on this isolated tree on an `aarch64-apple-darwin` host. During those checks no dependency/tool installation, network experiment, node, wallet, API or repository publication was performed. Subsequent publication preparation used GitHub and license-metadata APIs as authorized; it did not perform blockchain experiments. Cargo was explicitly offline. Build output was placed outside this tree. Raw logs containing machine paths are not included.

## Results

| Check | Result |
| --- | --- |
| `cargo +1.96.0 test --workspace --locked --offline` | Passed: 74 tests, 0 failures, 0 ignored; 0 doctests |
| Unit tests | 8 passed |
| Ed25519 vector tests | 3 passed |
| Envelope tests | 17 passed |
| Policy/setup tests | 13 passed |
| Session tests | 33 passed |
| `cargo +1.96.0 fmt --all --check` | Passed |
| `cargo +1.96.0 clippy ...` | Could not run: Clippy component absent; no installation attempted |
| `cargo +stable clippy --workspace --all-targets --locked --offline -- -D warnings` | Passed, no warnings; installed stable Rust 1.98.0 |
| `python3 scripts/verify_vectors.py` | Passed: five envelope cases, six Ed25519 profile cases, PolicyV1/SetupV1 vector |
| Python checker dependency | Already installed `cryptography` 49.0.0 |
| Host-filtered offline Cargo metadata | Passed; 83 third-party package license declarations inventoried |
| All-platform offline Cargo metadata | Incomplete: cached `wasip2 1.0.4+wasi-0.2.12` source unavailable; offline mode prevented downloading |
| Secret/identity/address heuristic scan | Only an intentional public test-fixture candidate; no other patterns detected |
| Ignore-rule checks | All 16 sensitive/runtime sample paths ignored; no included demo file accidentally ignored |
| Local Markdown links | No broken local Markdown links detected |
| Tree structure | No `.git`, symlinks, vendored dependencies, working credentials or build artifacts included |
| Original source integrity | All original tracked files matched the pre-copy snapshot; original working tree remained clean |

The lockfile contains 97 packages, including the demo crate and target-specific dependencies. All retained third-party name/version/source/checksum entries were preserved from the source lockfile; only unused workspace dependencies were removed.

## Scope and limitations

The heuristic scan reads all prepared files and reports only finding types and paths. Rules cover common provider tokens, private-key markers, credentials embedded in URLs, literal secret assignments, Zcash viewing/spending key encodings, payment addresses, email addresses, original account references and absolute home-directory paths. The intentional match is in `docs/test-vectors/envelope-v0.json`. Public fixtures include deterministic seeds, keys and nonces and must never protect real data. No real secret file was manually opened or copied.

No dedicated secret-scanning tool was available. These pattern checks do not recognize every secret format, arbitrary encoded credentials or every mnemonic phrase, and do not prove absence of secrets. The initial prepared tree had no Git history. Publication uses a fresh initial commit; staged contents are scanned again before committing.

The Rust implementation and tests were not rewritten for the demo. Adding the MIT manifest field during publication preparation did not change protocol behavior. Only a development-server reference in a Rust documentation comment was removed; workspace configuration and documentation were adapted for the smaller scope. Normative protocol rules were retained.

The session tests exercise synthetic records and in-memory snapshots. They do not validate chain-data completeness, disk recovery after a crash, actual secret-share delivery, independent operators or full DMS behavior. The separate Python checker is another implementation check, not an independent human audit. No mainnet/testnet claim is established by these offline checks.

Subsequent license review covered all 96 locked Cargo packages using cached metadata plus the official crates.io metadata and release license files for the missing WASI package. No dependency source was installed or vendored. MIT was chosen for original code; required third-party notices are preserved. See THIRD_PARTY.md and the publication record for the authorized fresh-history publication. The offline all-platform build limitation above remains unchanged.
