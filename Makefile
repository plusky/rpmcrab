# ==========================================================================
# Local gate. CI additionally runs typos, codeql, dependency-review and the
# parity corpus. Keep this fast and deterministic; `--locked` everywhere.
# ==========================================================================

.PHONY: check fmt clippy test deny layer gen doc doctest

# The local gate: everything a change must pass before review.
check: fmt clippy test deny layer

fmt:
	cargo fmt --all -- --check

# The second clippy line is NOT optional: `--all-targets` silently skips the
# feature-gated `rpmcrab-gen` bin, so it must be built explicitly with the
# `gen` feature on.
clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo clippy --workspace --all-targets --features gen --locked -- -D warnings

test:
	cargo test --workspace --all-targets --locked

deny:
	cargo deny check

# Architectural layering: `rpmcrab-core` must not depend on CLI concerns.
layer:
	bash scripts/check-rust-layering.sh

# Regenerate man pages and shell completions into crates/rpmcrab/{man,completions}.
gen:
	rm -rf crates/rpmcrab/man crates/rpmcrab/completions
	cargo run --locked -p rpmcrab --features gen --bin rpmcrab-gen -- crates/rpmcrab

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked

doctest:
	cargo test --workspace --doc --locked
