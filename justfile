# List available recipes
default:
    @just --list

# Run all checks (format, lint, test, TypeScript)
check: fmt lint test test-js

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run Rust tests
test *args:
    cargo test --workspace {{args}}

# Run Rust tests with verbose output
test-v *args:
    cargo test --workspace {{args}} -- --nocapture

# Run TypeScript type check
typecheck-js:
    cd crates/less-db-wasm/js && npx tsc --noEmit

# Run JS/WASM tests (vitest)
test-js: typecheck-js
    cd crates/less-db-wasm/js && npx vitest run

# Run benchmarks
bench *args:
    cargo bench --workspace {{args}}

# Build all targets
build:
    cargo build --workspace

# Build release
build-release:
    cargo build --workspace --release

# Clean build artifacts
clean:
    cargo clean
