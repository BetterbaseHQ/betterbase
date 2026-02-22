# List available recipes
default:
    @just --list

# Run all checks (format, lint, test, JS)
check: fmt lint test check-js

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
# -A deprecated: aes-gcm's generic-array dependency triggers upstream deprecation warnings
lint:
    cargo clippy -p less-crypto --all-targets -- -D warnings -A deprecated
    cargo clippy -p less-discovery --all-targets -- -D warnings
    cargo clippy -p less-auth --all-targets -- -D warnings -A deprecated
    cargo clippy -p less-sync-core --all-targets -- -D warnings -A deprecated
    cargo clippy -p less-platform-wasm --target wasm32-unknown-unknown -- -D warnings -A deprecated

# Run Rust tests (pure crates only; less-platform-wasm tests run via test-browser)
test *args:
    cargo test --workspace --exclude less-platform-wasm {{args}}

# Run Rust tests with verbose output
test-v *args:
    cargo test --workspace --exclude less-platform-wasm {{args}} -- --nocapture

# Run JS/WASM quality checks (typecheck + vitest + browser tests)
check-js:
    cd crates/less-platform-wasm/js && pnpm install && pnpm check

# Run Rust benchmarks
bench *args:
    cargo bench --workspace {{args}}

# Run browser integration tests (real WASM + real browser APIs)
test-browser:
    cd crates/less-platform-wasm/js && pnpm vitest run --config vitest.browser.config.ts

# Run browser benchmarks
bench-browser:
    cd crates/less-platform-wasm/js && pnpm vitest bench --config vitest.bench.config.ts

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
