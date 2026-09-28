//! Generate session-key separation conformance vectors.
//!
//! Deterministic: fixed 32-byte roots, real HKDF-SHA256 with the frozen salt
//! and info constants. The committed file is run by the Rust unit tests
//! (`session_keys::tests::conformance_vectors`) and the browser tests (real
//! wasm `deriveSessionKeys`), pinning both to the same bytes.
//!
//! Bytes are encoded as lowercase hex.
//!
//! Run: cargo run -p betterbase-auth --example generate_session_key_vectors

use betterbase_auth::derive_session_keys;
use serde_json::json;
use std::io::Write;

fn main() {
    // Fixed roots, reproducible in any language.
    let root_a = [0x42u8; 32];
    let root_b = core::array::from_fn(|i| i as u8);

    let root_c = [0u8; 32];
    // Fixed high-entropy root (random-looking, committed for reproducibility).
    let root_d: [u8; 32] =
        hex::decode("7f3a9c1e5b8d2046f0e6a3c719bd4f82d5e01c6a478b93fd2e7c50a1b6d48f3e")
            .expect("32 bytes")
            .try_into()
            .expect("32 bytes");

    let mut cases = Vec::new();
    for (name, root) in [
        ("root A (0x42 repeated)", &root_a),
        ("root B (0x00..0x1f sequential)", &root_b),
        ("root C (all zeros)", &root_c),
        ("root D (high entropy fixed)", &root_d),
    ] {
        let keys = derive_session_keys(root).expect("derivation succeeds");
        cases.push(json!({
            "name": name,
            "root": hex::encode(root),
            "expect": {
                "encryption_key": hex::encode(keys.encryption_key),
                "epoch_root_key": hex::encode(keys.epoch_root_key),
            },
        }));
    }

    // Error strings are derived from the actual error, so regenerating after
    // an AuthError wording change updates the vectors automatically.
    let error_cases: [(&str, &str); 3] = [
        ("empty root", ""),
        ("short root (16 bytes)", &hex::encode([0u8; 16])),
        ("long root (33 bytes)", &hex::encode([0u8; 33])),
    ];
    let errors = error_cases
        .iter()
        .map(|(name, root_hex)| {
            let root = hex::decode(root_hex).expect("hex decodes");
            let expect = derive_session_keys(&root)
                .expect_err("must fail")
                .to_string();
            json!({
                "name": name,
                "root": root_hex,
                "expect": expect,
            })
        })
        .collect::<Vec<_>>();

    let doc = json!({
        "version": 1,
        "description": "Session key-separation conformance vectors (betterbase-auth::derive_session_keys). \
            HKDF-SHA256(ikm=root, salt=betterbase:key-separation:v1, info=betterbase:encrypt:v1 or \
            betterbase:epoch-root:v1) -> 32-byte key each. Frozen v1 protocol constants — changing \
            them orphans every derived key.",
        "cases": cases,
        "errors": errors,
    });

    let out =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/session-keys.json");
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).expect("create output"));
    serde_json::to_writer_pretty(&mut file, &doc).expect("serialize");
    file.write_all(b"\n").expect("write newline");
    println!("wrote {}", out.display());
}
