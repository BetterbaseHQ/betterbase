# List available recipes
default:
    @just --list

# Run all checks (format, lint, test)
check: fmt lint test

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy -p less-crypto --all-targets -- -D warnings
    cargo clippy -p less-discovery --all-targets -- -D warnings
    cargo clippy -p less-auth --all-targets -- -D warnings
    cargo clippy -p less-sync-core --all-targets -- -D warnings
    cargo clippy -p less-platform-wasm --target wasm32-unknown-unknown -- -D warnings -A deprecated

# Run Rust tests
test *args:
    cargo test --workspace --exclude less-platform-wasm {{args}}

# Run Rust tests with verbose output
test-v *args:
    cargo test --workspace --exclude less-platform-wasm {{args}} -- --nocapture

# Run JS/WASM quality checks
check-js:
    cd crates/less-platform-wasm/js && pnpm install && pnpm check

# Build all targets
build:
    cargo build --workspace --exclude less-platform-wasm
    cargo build -p less-platform-wasm --target wasm32-unknown-unknown

# Build release
build-release:
    cargo build --workspace --exclude less-platform-wasm --release
    cargo build -p less-platform-wasm --target wasm32-unknown-unknown --release

# Clean build artifacts
clean:
    cargo clean
