//! One-off: write `testvectors/reference_attestation_vk.bin` (32 B Ed25519 VK).
//! Run: `cargo run --example dump_reference_attestation_vk --features test-support`

fn main() {
    let vk = enclave_protocol::reference_test_attestation_trust()
        .attestation_verifying_key
        .to_bytes();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testvectors/reference_attestation_vk.bin");
    std::fs::write(&path, vk).expect("write vk");
    println!("wrote {} ({} bytes)", path.display(), vk.len());
}
