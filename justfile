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
    cargo clippy -p betterbase-crypto --all-targets -- -D warnings -A deprecated
    cargo clippy -p betterbase-discovery --all-targets -- -D warnings
    cargo clippy -p betterbase-auth --all-targets -- -D warnings -A deprecated
    cargo clippy -p betterbase-sync-core --all-targets -- -D warnings -A deprecated
    cargo clippy -p betterbase-db --all-targets -- -D warnings
    cargo clippy -p betterbase-wasm --target wasm32-unknown-unknown -- -D warnings -A deprecated
    cargo clippy -p betterbase-db-wasm --target wasm32-unknown-unknown -- -D warnings

# Run Rust tests (pure crates only; WASM crates run via test-browser)
test *args:
    cargo test --workspace --exclude betterbase-wasm --exclude betterbase-db-wasm {{args}}

# Run Rust tests with verbose output
test-v *args:
    cargo test --workspace --exclude betterbase-wasm --exclude betterbase-db-wasm {{args}} -- --nocapture

# Run JS/WASM quality checks (typecheck + vitest + browser tests)
check-js:
    cd js && pnpm install && pnpm check

# Run Rust benchmarks
bench *args:
    cargo bench --workspace {{args}}

# Run browser integration tests (real WASM + real browser APIs)
test-browser:
    cd js && pnpm vitest run --config vitest.browser.config.ts

# Run browser benchmarks
bench-browser:
    cd js && pnpm vitest bench --config vitest.bench.config.ts

# Build all targets
build:
    cargo build --workspace --exclude betterbase-wasm --exclude betterbase-db-wasm
    cargo build -p betterbase-wasm --target wasm32-unknown-unknown
    cargo build -p betterbase-db-wasm --target wasm32-unknown-unknown

# Build release
build-release:
    cargo build --workspace --exclude betterbase-wasm --exclude betterbase-db-wasm --release
    cargo build -p betterbase-wasm --target wasm32-unknown-unknown --release
    cargo build -p betterbase-db-wasm --target wasm32-unknown-unknown --release

# Clean build artifacts
clean:
    cargo clean
