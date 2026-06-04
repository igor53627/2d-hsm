//! Write `testvectors/lab_prod_enclave.sealed` for lab prod NixOS guest (TASK-5 Phase 2).
//! Run: `cargo run --example generate_lab_prod_sealed --features pq-seal-provisioning,ml-dsa-65`

fn main() {
    use enclave_protocol::boot_lab_pq_seal::LAB_PROD_MEASUREMENT;
    use enclave_protocol::{
        pq_seal_v1_measurement_digest, seal_mldsa65_keypair_v1_with_root,
        set_pq_seal_v1_provisioning_root,
    };

    let root = include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
    let sk = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
    let pk = include_bytes!("../testvectors/mldsa65_reference_pk.bin");
    set_pq_seal_v1_provisioning_root(*root).expect("set root");
    let blob =
        seal_mldsa65_keypair_v1_with_root(sk, pk, LAB_PROD_MEASUREMENT, root).expect("seal");
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/lab_prod_enclave.sealed");
    std::fs::write(&path, &blob).expect("write sealed");
    let digest = pq_seal_v1_measurement_digest(LAB_PROD_MEASUREMENT);
    println!(
        "wrote {} ({} bytes) meas_digest={}",
        path.display(),
        blob.len(),
        hex::encode(digest)
    );
}