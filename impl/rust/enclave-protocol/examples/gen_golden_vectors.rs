//! Golden vector generator for 2D ML-DSA-65 NIF cross-check.
//!
//! Run:
//! ```sh
//! cargo run --example gen_golden_vectors \
//!   --features ml-dsa-65,pq-seal-provisioning,reference-test-key
//! ```

use enclave_protocol::{compute_canonical_ticket_hash, AuthorizationTicketPayload};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use std::fs;
use std::path::Path;

fn main() {
    let (pk, sk) = mldsa65::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();
    assert_eq!(pk_bytes.len(), 1952);
    assert_eq!(sk_bytes.len(), 4032);

    let sign = |msg: &[u8; 32]| -> Vec<u8> {
        let sk_obj = mldsa65::SecretKey::from_bytes(&sk_bytes).unwrap();
        mldsa65::detached_sign(msg, &sk_obj).as_bytes().to_vec()
    };
    let verify = |msg: &[u8; 32], sig: &[u8]| -> bool {
        let pk_obj = mldsa65::PublicKey::from_bytes(&pk_bytes).unwrap();
        let sig_obj = mldsa65::DetachedSignature::from_bytes(sig).unwrap();
        mldsa65::verify_detached_signature(&sig_obj, msg, &pk_obj).is_ok()
    };

    let out_dir = Path::new("testvectors/mldsa65_crosscheck");
    fs::create_dir_all(out_dir).unwrap();
    fs::write(out_dir.join("pubkey.bin"), &pk_bytes).unwrap();
    eprintln!("pubkey: {} bytes", pk_bytes.len());

    let (pk2, _sk2) = mldsa65::keypair();
    let pk2_bytes = pk2.as_bytes().to_vec();
    fs::write(out_dir.join("pubkey_wrong.bin"), &pk2_bytes).unwrap();

    // POSITIVE vectors
    let payloads: &[(&str, AuthorizationTicketPayload)] = &[
        ("recovery", AuthorizationTicketPayload {
            ticket_type: 0, nonce: 1, context_hash: [0xAB; 32],
            activation_height: 1000, new_measurement: vec![0x55; 48],
            pq_pubkey: pk_bytes.clone(), fork_spec_hash: None, new_header_version: None,
        }),
        ("hardfork", AuthorizationTicketPayload {
            ticket_type: 1, nonce: 42, context_hash: [0xCD; 32],
            activation_height: 5000, new_measurement: vec![0x77; 48],
            pq_pubkey: pk_bytes.clone(),
            fork_spec_hash: Some([0xEE; 32]), new_header_version: Some(2),
        }),
        ("recovery2", AuthorizationTicketPayload {
            ticket_type: 0, nonce: 999999, context_hash: [0x11; 32],
            activation_height: 0, new_measurement: vec![],
            pq_pubkey: pk_bytes.clone(), fork_spec_hash: None, new_header_version: None,
        }),
    ];

    for (name, payload) in payloads {
        let hash = compute_canonical_ticket_hash(payload);
        let sig = sign(&hash);
        assert_eq!(sig.len(), 3309);
        assert!(verify(&hash, &sig));
        write_vec(out_dir, &format!("pos_{name}"), &hash, &sig);
        eprintln!("pos_{name}: type={} nonce={} → MUST verify", payload.ticket_type, payload.nonce);
    }

    // NEGATIVE: (a) flipped byte
    {
        let hash = compute_canonical_ticket_hash(&payloads[0].1);
        let mut bad_sig = sign(&hash);
        bad_sig[100] ^= 0xFF;
        assert!(!verify(&hash, &bad_sig));
        write_vec(out_dir, "neg_flipped_byte", &hash, &bad_sig);
        eprintln!("neg_flipped_byte → MUST reject");
    }
    // NEGATIVE: (b) wrong message
    {
        let hash_a = compute_canonical_ticket_hash(&payloads[0].1);
        let hash_b = compute_canonical_ticket_hash(&payloads[1].1);
        let sig_a = sign(&hash_a);
        assert!(!verify(&hash_b, &sig_a));
        write_vec(out_dir, "neg_wrong_message", &hash_b, &sig_a);
        eprintln!("neg_wrong_message → MUST reject");
    }
    // NEGATIVE: (c) wrong pubkey
    {
        let hash = compute_canonical_ticket_hash(&payloads[0].1);
        let sig = sign(&hash);
        let pk2_obj = mldsa65::PublicKey::from_bytes(&pk2_bytes).unwrap();
        let sig_obj = mldsa65::DetachedSignature::from_bytes(&sig).unwrap();
        assert!(mldsa65::verify_detached_signature(&sig_obj, &hash, &pk2_obj).is_err());
        write_vec(out_dir, "neg_wrong_pubkey", &hash, &sig);
        eprintln!("neg_wrong_pubkey → MUST reject (use pubkey_wrong.bin)");
    }

    eprintln!("\nDone. Files in testvectors/mldsa65_crosscheck/");
}

fn write_vec(dir: &Path, name: &str, hash: &[u8; 32], sig: &[u8]) {
    fs::write(dir.join(format!("{name}_ticket_hash.bin")), hash).unwrap();
    fs::write(dir.join(format!("{name}_signature.bin")), sig).unwrap();
}
