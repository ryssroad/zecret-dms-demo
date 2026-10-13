# Publication scope and review record

Repository: `ryssroad/zecret-dms-demo`. The project owner authorized public publication of the cleaned demo, selected the public author name Denis Shevchenko, requested GitHub noreply, and delegated the license choice. MIT was selected for original project code and documentation after the source/dependency review described in THIRD_PARTY.md.

The initial commit uses a fresh history and repository-local identity. The GitHub account was checked through existing authentication, and its ID-based noreply was derived from the confirmed account data using GitHub's documented format. No personal email, old Git history, global Git configuration change, new credential or integration is needed.

Included: the implemented protocol core, its tests and public fixtures, a separate vector checker, editorially cleaned specifications, license/notice materials and verification notes. No protocol behavior was rewritten to make the demo pass. The only Rust-source cleanup removed a development-server reference from a documentation comment.

Excluded: original operational history and reports; deployment, server and backup details; live addresses and transaction identifiers; relay, wallet and scanner code; role CLI placeholders; working credentials and environment files; logs and build artifacts.

All 96 locked Cargo dependency license declarations were reviewed; third-party license and attribution notices are preserved separately. Dependencies are not relicensed. Future dependency changes, vendoring or binary releases need a fresh review.

Independent human cryptography/protocol auditing and the complete DMS workflow remain future work. Publication and offline tests establish neither production safety nor independent guardian operation.
