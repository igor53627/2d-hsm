//! Relying-party reference verifier for SEV-SNP attestation.
//!
//! Implements `backlog/docs/snp-attestation-verifier-policy.md` §2 step 2 — the part the cheap
//! structural checker `enclave_protocol::snp_verify::prevalidate_report` deliberately leaves out:
//! the cryptographic chain from the ATTESTATION_REPORT up to the **pinned AMD root**.
//!
//! Two signature algorithms are involved:
//!   - the report is signed by the **VCEK** with **ECDSA-P384 / SHA-384** (`verify_report_signature`);
//!   - the VCEK→ASK→ARK *certificate* chain is signed with **RSA-4096 RSASSA-PSS / SHA-384**
//!     (`verify_cert_chain`), and the ARK is pinned out of band.
//!
//! This is the relying party's job (Block Producer host / on-chain consumer) and is intentionally
//! NOT in the enclave crate (`#![forbid(unsafe_code)]`): it needs ECDSA + RSA + X.509.

use thiserror::Error;

/// SEV-SNP ATTESTATION_REPORT v2/v5 size (bytes).
pub const REPORT_LEN: usize = 1184;
/// The report is signed over `report[0..SIG_OFFSET]`; the signature itself sits at `SIG_OFFSET`.
const SIG_OFFSET: usize = 0x2A0;
/// AMD reserves 72 bytes per ECDSA component; P-384 uses the low 48 (the rest is zero).
const SIG_COMPONENT_LEN: usize = 72;
const P384_SCALAR_LEN: usize = 48;
const CHIP_ID_OFFSET: usize = 0x1A0;
const CHIP_ID_LEN: usize = 64;
const REPORTED_TCB_OFFSET: usize = 0x180;
const REPORTED_TCB_LEN: usize = 8;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("report too short: {0} < {REPORT_LEN}")]
    ShortReport(usize),
    #[error("malformed ECDSA signature in report")]
    BadReportSignatureEncoding,
    #[error("report signature does not verify against the VCEK")]
    ReportSignature,
    #[error("could not parse certificate ({0})")]
    CertParse(&'static str),
    #[error("unsupported certificate signature algorithm: {0}")]
    UnsupportedSigAlg(String),
    #[error("certificate signature does not verify against its issuer ({0})")]
    CertSignature(&'static str),
    #[error("ARK is not self-signed")]
    ArkNotSelfSigned,
    #[error("ARK does not match the pinned AMD root")]
    ArkPinMismatch,
    #[error("certificate name chain broken ({0})")]
    NameChain(&'static str),
    #[error("VCEK/report binding failed ({0})")]
    TcbBinding(&'static str),
    #[error(transparent)]
    Prevalidate(#[from] enclave_protocol::ProtocolError),
}

/// Verify the report's ECDSA-P384/SHA-384 signature with the VCEK verifying key.
///
/// AMD stores the signature components **little-endian** in 72-byte fields at `SIG_OFFSET`
/// (`r` then `s`); P-384 uses the low 48 bytes. We byte-reverse to the big-endian the `p384` crate
/// expects, then verify the prehash (SHA-384 over the signed body).
pub fn verify_report_signature(
    report: &[u8],
    vcek: &p384::ecdsa::VerifyingKey,
) -> Result<(), VerifyError> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use p384::ecdsa::Signature;
    use sha2::{Digest, Sha384};

    if report.len() < REPORT_LEN {
        return Err(VerifyError::ShortReport(report.len()));
    }
    let mut sig_be = [0u8; 2 * P384_SCALAR_LEN];
    // r
    sig_be[..P384_SCALAR_LEN].copy_from_slice(&report[SIG_OFFSET..SIG_OFFSET + P384_SCALAR_LEN]);
    sig_be[..P384_SCALAR_LEN].reverse();
    // s
    sig_be[P384_SCALAR_LEN..].copy_from_slice(
        &report[SIG_OFFSET + SIG_COMPONENT_LEN..SIG_OFFSET + SIG_COMPONENT_LEN + P384_SCALAR_LEN],
    );
    sig_be[P384_SCALAR_LEN..].reverse();

    let sig =
        Signature::from_slice(&sig_be).map_err(|_| VerifyError::BadReportSignatureEncoding)?;
    let digest = Sha384::digest(&report[..SIG_OFFSET]);
    vcek.verify_prehash(&digest, &sig)
        .map_err(|_| VerifyError::ReportSignature)
}

/// The 64-byte `chip_id` from the report (offset `0x1A0`).
pub fn report_chip_id(report: &[u8]) -> Result<[u8; CHIP_ID_LEN], VerifyError> {
    if report.len() < REPORT_LEN {
        return Err(VerifyError::ShortReport(report.len()));
    }
    let mut id = [0u8; CHIP_ID_LEN];
    id.copy_from_slice(&report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_LEN]);
    Ok(id)
}

/// The 8-byte `reported_tcb` from the report (offset `0x180`).
pub fn report_reported_tcb(report: &[u8]) -> Result<[u8; REPORTED_TCB_LEN], VerifyError> {
    if report.len() < REPORT_LEN {
        return Err(VerifyError::ShortReport(report.len()));
    }
    let mut tcb = [0u8; REPORTED_TCB_LEN];
    tcb.copy_from_slice(&report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + REPORTED_TCB_LEN]);
    Ok(tcb)
}

// ---------------------------------------------------------------------------------------------
// Certificate chain: VCEK ← ASK ← ARK, to the pinned AMD root.
// ---------------------------------------------------------------------------------------------

use const_oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// RSASSA-PSS (AMD ARK/ASK cert signatures).
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
/// ecdsa-with-SHA384 — accepted only in the synthetic test chain (AMD's real chain is RSA-PSS).
#[cfg(test)]
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Parse a PEM bundle (e.g. the AMD KDS `cert_chain`: ASK then ARK) into certificates.
pub fn parse_cert_chain_pem(pem: &[u8]) -> Result<Vec<Certificate>, VerifyError> {
    Certificate::load_pem_chain(pem).map_err(|_| VerifyError::CertParse("pem chain"))
}

/// Parse a single DER certificate (e.g. a VCEK from KDS).
pub fn parse_cert_der(der: &[u8]) -> Result<Certificate, VerifyError> {
    Certificate::from_der(der).map_err(|_| VerifyError::CertParse("der cert"))
}

/// Extract the ECDSA-P384 verifying key from a certificate's SubjectPublicKeyInfo (the VCEK key).
pub fn cert_p384_key(cert: &Certificate) -> Result<p384::ecdsa::VerifyingKey, VerifyError> {
    use spki::DecodePublicKey;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerifyError::CertParse("spki der"))?;
    p384::ecdsa::VerifyingKey::from_public_key_der(&spki)
        .map_err(|_| VerifyError::CertParse("ec spki"))
}

/// Verify that `cert` is signed by `issuer`. Dispatches on `cert`'s signature algorithm:
/// RSASSA-PSS/SHA-384 (AMD ARK/ASK) or ECDSA-P384/SHA-384 (synthetic test chain).
fn verify_cert_signed_by(
    cert: &Certificate,
    issuer: &Certificate,
    ctx: &'static str,
) -> Result<(), VerifyError> {
    use sha2::{Digest, Sha384};
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| VerifyError::CertParse("tbs der"))?;
    let sig = cert
        .signature
        .as_bytes()
        .ok_or(VerifyError::CertParse("signature bitstring"))?;
    let issuer_spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerifyError::CertParse("issuer spki"))?;
    let alg = cert.signature_algorithm.oid;

    // Production accepts ONLY AMD's algorithm: RSA-4096 RSASSA-PSS / SHA-384 / MGF1-SHA-384 / salt 48.
    // (A cert declaring different PSS params simply fails to verify here — safe.) Anything else is
    // rejected; ECDSA cert signatures exist only for the synthetic test chain below (AMD is RSA-only).
    if alg == OID_RSASSA_PSS {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::{Pss, RsaPublicKey};
        let pk = RsaPublicKey::from_public_key_der(&issuer_spki)
            .map_err(|_| VerifyError::CertParse("rsa spki"))?;
        let digest = Sha384::digest(&tbs);
        return pk
            .verify(Pss::new::<Sha384>(), &digest, sig)
            .map_err(|_| VerifyError::CertSignature(ctx));
    }
    // Test-only: the synthetic chain (synthetic_chain_tests) is ECDSA-P384, since x509-cert 0.2's
    // builder cannot produce randomized RSA-PSS signatures. Compiled out of the shipped verifier so
    // production rejects non-RSA-PSS cert signatures.
    #[cfg(test)]
    if alg == OID_ECDSA_SHA384 {
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        use p384::ecdsa::Signature;
        use spki::DecodePublicKey;
        let vk = p384::ecdsa::VerifyingKey::from_public_key_der(&issuer_spki)
            .map_err(|_| VerifyError::CertParse("ec issuer spki"))?;
        let sig = Signature::from_der(sig).map_err(|_| VerifyError::CertParse("ec cert sig"))?;
        let digest = Sha384::digest(&tbs);
        return vk
            .verify_prehash(&digest, &sig)
            .map_err(|_| VerifyError::CertSignature(ctx));
    }
    Err(VerifyError::UnsupportedSigAlg(alg.to_string()))
}

fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
        && verify_cert_signed_by(cert, cert, "ark-self").is_ok()
}

/// Verify the VCEK → ASK → ARK chain up to the pinned AMD root.
///
/// `chain` is the KDS `cert_chain` (ASK + ARK in any order). The ARK is identified as the
/// self-signed certificate and pinned: its SubjectPublicKeyInfo DER must equal `pinned_ark_spki`
/// (the out-of-band AMD root key — never trust the ARK delivered in the chain on its own).
pub fn verify_cert_chain(
    vcek: &Certificate,
    chain: &[Certificate],
    pinned_ark_spki: &[u8],
) -> Result<(), VerifyError> {
    let ark = chain
        .iter()
        .find(|c| is_self_signed(c))
        .ok_or(VerifyError::ArkNotSelfSigned)?;
    let ark_spki = ark
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerifyError::CertParse("ark spki"))?;
    if ark_spki != pinned_ark_spki {
        return Err(VerifyError::ArkPinMismatch);
    }
    // ASK = the chain cert that ISSUED the VCEK, matched by DN (not merely "not the ARK"), so an
    // extra/duplicate cert in the bundle can't be mis-selected. Then enforce name-chaining up to the
    // ARK (RFC 5280 §6.1 issuer/subject linkage) before checking signatures — defense in depth on top
    // of the pin + signature checks.
    let ask = chain
        .iter()
        .find(|c| c.tbs_certificate.subject == vcek.tbs_certificate.issuer)
        .ok_or(VerifyError::NameChain(
            "no chain cert matches the VCEK issuer",
        ))?;
    if ask.tbs_certificate.issuer != ark.tbs_certificate.subject {
        return Err(VerifyError::NameChain("ASK issuer != ARK subject"));
    }
    verify_cert_signed_by(ask, ark, "ask<-ark")?;
    verify_cert_signed_by(vcek, ask, "vcek<-ask")?;
    Ok(())
}

/// The pinned AMD root: the SubjectPublicKeyInfo DER of the ARK in `pinned_chain_pem`.
pub fn pinned_ark_spki(pinned_chain_pem: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let chain = parse_cert_chain_pem(pinned_chain_pem)?;
    let ark = chain
        .iter()
        .find(|c| is_self_signed(c))
        .ok_or(VerifyError::ArkNotSelfSigned)?;
    ark.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerifyError::CertParse("ark spki"))
}

// ---------------------------------------------------------------------------------------------
// VCEK ↔ report chip binding (policy §2 step 2, last bullet).
// ---------------------------------------------------------------------------------------------

/// AMD VCEK `HWID` extension OID — the 64-byte chip identifier the VCEK was issued for.
const AMD_VCEK_HWID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");

/// Extract the 64-byte HWID from a VCEK HWID extension's `extn_value`, tolerant of the two encodings
/// seen in practice: the raw 64 bytes, or a DER OCTET STRING wrapping them (AMD's DER has known
/// quirks; cf. go-sev-guest). Validated synthetically — a real-VCEK cross-check is a follow-up (no
/// KDS-resolvable chip on the lab box; see policy §4).
fn parse_amd_hwid(extn_value: &[u8]) -> Result<[u8; 64], VerifyError> {
    let raw: &[u8] = if extn_value.len() == 64 {
        extn_value
    } else {
        // Fall back to a DER OCTET STRING wrapper.
        return x509_cert::der::asn1::OctetString::from_der(extn_value)
            .ok()
            .and_then(|os| <[u8; 64]>::try_from(os.as_bytes()).ok())
            .ok_or(VerifyError::TcbBinding(
                "VCEK HWID is neither 64 raw bytes nor an OCTET STRING of 64 bytes",
            ));
    };
    <[u8; 64]>::try_from(raw).map_err(|_| VerifyError::TcbBinding("VCEK HWID is not 64 bytes"))
}

/// Bind the VCEK to the report's chip: the VCEK's HWID extension must equal the report's `chip_id`.
/// Without this, a genuine VCEK from a *different* chip could be paired with a report (mix-and-match).
pub fn verify_vcek_chip_binding(vcek: &Certificate, report: &[u8]) -> Result<(), VerifyError> {
    let ext = vcek
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == AMD_VCEK_HWID_OID)
        .ok_or(VerifyError::TcbBinding("VCEK has no AMD HWID extension"))?;
    let hwid = parse_amd_hwid(ext.extn_value.as_bytes())?;
    if hwid != report_chip_id(report)? {
        return Err(VerifyError::TcbBinding("VCEK HWID != report chip_id"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Full attestation verification (policy §2): structural prevalidate + report sig + cert chain.
// ---------------------------------------------------------------------------------------------

/// Verify a complete SEV-SNP attestation per the policy:
///  1. structural prevalidate (version/len, optional `pq_pubkey` binding, measurement allowlist) —
///     reused from `enclave_protocol::snp_verify::prevalidate_report`;
///  2. the VCEK → ASK → ARK cert chain to the pinned AMD root;
///  3. the report's ECDSA-P384 signature against the (now chain-trusted) VCEK.
///
/// Returns the 48-byte launch measurement (read from the *signed* report) on success.
#[allow(clippy::too_many_arguments)]
pub fn verify_attestation(
    report: &[u8],
    vcek: &Certificate,
    chain: &[Certificate],
    pinned_ark_spki: &[u8],
    expected_pq_pubkey: Option<&[u8]>,
    allowed_measurements: &[[u8; 48]],
) -> Result<[u8; 48], VerifyError> {
    // 1. cheap structural + binding + allowlist checks (shared with the enclave-side reference).
    let pre = enclave_protocol::snp_verify::prevalidate_report(
        report,
        expected_pq_pubkey,
        allowed_measurements,
    )?;
    // 2. chain to the pinned AMD root, then 3. the report signature against the VCEK.
    verify_cert_chain(vcek, chain, pinned_ark_spki)?;
    let vcek_key = cert_p384_key(vcek)?;
    verify_report_signature(report, &vcek_key)?;
    // 4. bind the VCEK to this chip (its HWID extension == the report's chip_id).
    verify_vcek_chip_binding(vcek, report)?;
    Ok(pre.measurement)
}

#[cfg(test)]
mod golden_report_tests {
    use super::*;

    // Real SEV-SNP report captured on aya (EPYC 9375F). Its VCEK is not KDS-resolvable (masked
    // chip_id), so it exercises field extraction + prevalidate, not the full chain (see policy §4).
    const GOLDEN: &[u8] = include_bytes!("../testvectors/snp_report_golden_v5.bin");

    #[test]
    fn extracts_chip_id_and_reported_tcb() {
        assert_eq!(GOLDEN.len(), REPORT_LEN);
        let tcb = report_reported_tcb(GOLDEN).unwrap();
        assert_eq!(tcb, [0x01, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x52]);
        let chip = report_chip_id(GOLDEN).unwrap();
        assert_eq!(
            &chip[..8],
            &[0x29, 0x84, 0x97, 0xcf, 0x35, 0x40, 0x1d, 0xf2]
        );
    }

    #[test]
    fn short_report_field_reads_rejected() {
        assert!(matches!(
            report_reported_tcb(&GOLDEN[..REPORT_LEN - 1]),
            Err(VerifyError::ShortReport(_))
        ));
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    const AMD_GENOA_CHAIN: &[u8] = include_bytes!("../testvectors/amd_genoa_cert_chain.pem");
    // aya is a Turin (Zen 5, CPU family 26) EPYC 9375F — its product root is Turin, not Genoa.
    const AMD_TURIN_CHAIN: &[u8] = include_bytes!("../testvectors/amd_turin_cert_chain.pem");

    #[test]
    fn amd_turin_chain_verifies_to_pinned_root() {
        // Real AMD Turin ARK/ASK (from KDS) — second product root, exercises the RSA-PSS path.
        let chain = parse_cert_chain_pem(AMD_TURIN_CHAIN).unwrap();
        assert_eq!(chain.len(), 2);
        let ark = chain
            .iter()
            .find(|c| is_self_signed(c))
            .expect("Turin ARK self-signed (RSA-PSS)");
        let ask = chain
            .iter()
            .find(|c| c.tbs_certificate.subject != ark.tbs_certificate.subject)
            .unwrap();
        verify_cert_signed_by(ask, ark, "ask<-ark").expect("Turin ASK signed by ARK");
        // Distinct root from Genoa.
        assert_ne!(
            pinned_ark_spki(AMD_TURIN_CHAIN).unwrap(),
            pinned_ark_spki(AMD_GENOA_CHAIN).unwrap()
        );
    }

    #[test]
    fn amd_chain_parses_two_certs() {
        let chain = parse_cert_chain_pem(AMD_GENOA_CHAIN).unwrap();
        assert_eq!(chain.len(), 2, "AMD KDS cert_chain = ASK + ARK");
    }

    #[test]
    fn amd_ark_is_self_signed_rsa_pss() {
        let chain = parse_cert_chain_pem(AMD_GENOA_CHAIN).unwrap();
        let ark = chain.iter().find(|c| is_self_signed(c));
        assert!(
            ark.is_some(),
            "the AMD ARK must verify as self-signed (RSA-PSS)"
        );
    }

    #[test]
    fn amd_ask_signed_by_ark() {
        let chain = parse_cert_chain_pem(AMD_GENOA_CHAIN).unwrap();
        let ark = chain.iter().find(|c| is_self_signed(c)).unwrap();
        let ask = chain
            .iter()
            .find(|c| c.tbs_certificate.subject != ark.tbs_certificate.subject)
            .unwrap();
        verify_cert_signed_by(ask, ark, "ask<-ark").expect("real AMD ASK must be signed by ARK");
    }

    #[test]
    fn ark_pin_matches_itself_and_rejects_other() {
        let pin = pinned_ark_spki(AMD_GENOA_CHAIN).unwrap();
        // The pin equals the ARK's SPKI from the same bundle.
        let chain = parse_cert_chain_pem(AMD_GENOA_CHAIN).unwrap();
        let ark = chain.iter().find(|c| is_self_signed(c)).unwrap();
        let ark_spki = ark
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        assert_eq!(pin, ark_spki);
        // A bogus pin is rejected (use the ASK's SPKI as a stand-in "wrong root").
        let ask = chain
            .iter()
            .find(|c| c.tbs_certificate.subject != ark.tbs_certificate.subject)
            .unwrap();
        let wrong_pin = ask
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        // verify_cert_chain would need a vcek; here we assert the pin comparison directly.
        assert_ne!(wrong_pin, ark_spki);
    }
}

#[cfg(test)]
mod synthetic_chain_tests {
    //! Build a synthetic ECDSA-P384 ARK→ASK→VCEK chain + a report signed by the VCEK, and exercise
    //! the full chain-walk / pin / report-binding path end to end (AMD's real chain is RSA-PSS,
    //! covered by the committed AMD certs; this covers the orchestration + ECDSA cert leg + leaf).
    use super::*;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::{DerSignature, Signature, SigningKey};
    use sha2::{Digest, Sha384};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    fn key(seed: u8) -> SigningKey {
        let mut s = [0u8; 48];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        SigningKey::from_slice(&s).unwrap()
    }
    fn spki_of(sk: &SigningKey) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_key(*sk.verifying_key()).unwrap()
    }
    fn self_signed(sk: &SigningKey, cn: &str) -> Certificate {
        CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str(cn).unwrap(),
            spki_of(sk),
            sk,
        )
        .unwrap()
        .build::<DerSignature>()
        .unwrap()
    }
    fn signed_by(
        subject_sk: &SigningKey,
        cn: &str,
        issuer: &Certificate,
        issuer_sk: &SigningKey,
    ) -> Certificate {
        CertificateBuilder::new(
            Profile::SubCA {
                issuer: issuer.tbs_certificate.subject.clone(),
                path_len_constraint: None,
            },
            SerialNumber::from(2u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str(cn).unwrap(),
            spki_of(subject_sk),
            issuer_sk,
        )
        .unwrap()
        .build::<DerSignature>()
        .unwrap()
    }
    fn report_signed_by(sk: &SigningKey) -> [u8; REPORT_LEN] {
        let mut report = [0u8; REPORT_LEN];
        for (i, b) in report[..SIG_OFFSET].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let digest = Sha384::digest(&report[..SIG_OFFSET]);
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        let be = sig.to_bytes();
        let (mut r, mut s) = ([0u8; 48], [0u8; 48]);
        r.copy_from_slice(&be[..48]);
        r.reverse();
        s.copy_from_slice(&be[48..]);
        s.reverse();
        report[SIG_OFFSET..SIG_OFFSET + 48].copy_from_slice(&r);
        report[SIG_OFFSET + SIG_COMPONENT_LEN..SIG_OFFSET + SIG_COMPONENT_LEN + 48]
            .copy_from_slice(&s);
        report
    }

    #[test]
    fn full_chain_and_report_verify_end_to_end() {
        let (ark_sk, ask_sk, vcek_sk) = (key(10), key(40), key(90));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let vcek = signed_by(&vcek_sk, "CN=Test VCEK", &ask, &ask_sk);
        let ark_spki = ark
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        // Chain (ASK, ARK order, like AMD KDS) verifies up to the pinned ARK.
        verify_cert_chain(&vcek, &[ask.clone(), ark.clone()], &ark_spki)
            .expect("chain must verify");

        // The report signed by the VCEK verifies against the VCEK key extracted from its cert.
        let report = report_signed_by(&vcek_sk);
        let vcek_key = cert_p384_key(&vcek).unwrap();
        verify_report_signature(&report, &vcek_key).expect("report sig must verify");
    }

    #[test]
    fn wrong_pin_rejected() {
        let (ark_sk, ask_sk, vcek_sk) = (key(10), key(40), key(90));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let vcek = signed_by(&vcek_sk, "CN=Test VCEK", &ask, &ask_sk);
        let bogus = self_signed(&key(200), "CN=Evil ARK");
        let bogus_spki = bogus
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        assert!(matches!(
            verify_cert_chain(&vcek, &[ask, ark], &bogus_spki),
            Err(VerifyError::ArkPinMismatch)
        ));
    }

    #[test]
    fn missing_ask_rejected_by_name_chain() {
        // A chain with only the ARK (no cert matching the VCEK's issuer DN) is rejected at the
        // name-chain step, not silently mis-selected.
        let (ark_sk, ask_sk, vcek_sk) = (key(10), key(40), key(90));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let vcek = signed_by(&vcek_sk, "CN=Test VCEK", &ask, &ask_sk);
        let ark_spki = ark
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        assert!(matches!(
            verify_cert_chain(&vcek, &[ark], &ark_spki),
            Err(VerifyError::NameChain(_))
        ));
    }

    #[test]
    fn broken_intermediate_rejected() {
        // VCEK signed by a DIFFERENT key than the ASK in the chain → vcek<-ask leg fails.
        let (ark_sk, ask_sk) = (key(10), key(40));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let imposter_sk = key(123);
        let vcek = signed_by(&key(90), "CN=Test VCEK", &ask, &imposter_sk); // signed by wrong key
        let ark_spki = ark
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        assert!(matches!(
            verify_cert_chain(&vcek, &[ask, ark], &ark_spki),
            Err(VerifyError::CertSignature(_))
        ));
    }

    // A custom AMD HWID extension for building synthetic VCEKs (value = DER OCTET STRING of the id).
    struct HwidExt(x509_cert::der::asn1::OctetString);
    impl const_oid::AssociatedOid for HwidExt {
        const OID: ObjectIdentifier = AMD_VCEK_HWID_OID;
    }
    impl x509_cert::der::Encode for HwidExt {
        fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
            self.0.encoded_len()
        }
        fn encode(&self, writer: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
            self.0.encode(writer)
        }
    }
    impl x509_cert::ext::AsExtension for HwidExt {
        fn critical(&self, _subject: &Name, _extensions: &[x509_cert::ext::Extension]) -> bool {
            false
        }
    }
    fn vcek_with_hwid(
        subject_sk: &SigningKey,
        issuer: &Certificate,
        issuer_sk: &SigningKey,
        hwid: &[u8; 64],
    ) -> Certificate {
        let mut builder = CertificateBuilder::new(
            Profile::SubCA {
                issuer: issuer.tbs_certificate.subject.clone(),
                path_len_constraint: None,
            },
            SerialNumber::from(3u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str("CN=Test VCEK").unwrap(),
            spki_of(subject_sk),
            issuer_sk,
        )
        .unwrap();
        builder
            .add_extension(&HwidExt(
                x509_cert::der::asn1::OctetString::new(hwid.to_vec()).unwrap(),
            ))
            .unwrap();
        builder.build::<DerSignature>().unwrap()
    }

    #[test]
    fn hwid_parse_both_encodings() {
        let want = [0xABu8; 64];
        // Encoding A: raw 64 bytes.
        assert_eq!(parse_amd_hwid(&want).unwrap(), want);
        // Encoding B: DER OCTET STRING wrapper.
        let der = x509_cert::der::asn1::OctetString::new(want.to_vec())
            .unwrap()
            .to_der()
            .unwrap();
        assert_eq!(parse_amd_hwid(&der).unwrap(), want);
        // Wrong length rejected.
        assert!(parse_amd_hwid(&[0u8; 32]).is_err());
    }

    #[test]
    fn vcek_chip_binding_pass_and_mismatch() {
        let (ark_sk, ask_sk, vcek_sk) = (key(10), key(40), key(90));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let report = report_signed_by(&vcek_sk);
        let chip = report_chip_id(&report).unwrap();
        // VCEK whose HWID matches the report's chip_id → binding passes.
        verify_vcek_chip_binding(&vcek_with_hwid(&vcek_sk, &ask, &ask_sk, &chip), &report)
            .expect("matching HWID must bind");
        // VCEK whose HWID differs → rejected.
        let mut other = chip;
        other[0] ^= 0xff;
        assert!(matches!(
            verify_vcek_chip_binding(&vcek_with_hwid(&vcek_sk, &ask, &ask_sk, &other), &report),
            Err(VerifyError::TcbBinding(_))
        ));
    }

    #[test]
    fn vcek_without_hwid_rejected() {
        let (ark_sk, ask_sk, vcek_sk) = (key(10), key(40), key(90));
        let ark = self_signed(&ark_sk, "CN=Test ARK");
        let ask = signed_by(&ask_sk, "CN=Test ASK", &ark, &ark_sk);
        let vcek = signed_by(&vcek_sk, "CN=Test VCEK", &ask, &ask_sk); // no HWID extension
        assert!(matches!(
            verify_vcek_chip_binding(&vcek, &report_signed_by(&vcek_sk)),
            Err(VerifyError::TcbBinding(_))
        ));
    }
}

#[cfg(test)]
mod report_sig_tests {
    use super::*;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha384};

    // Deterministic P-384 key (fixed scalar) — no RNG, reproducible test.
    fn test_signing_key() -> SigningKey {
        let mut scalar = [0u8; 48];
        for (i, b) in scalar.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        SigningKey::from_slice(&scalar).expect("valid P-384 scalar")
    }

    // Build a report: arbitrary body in [0,0x2A0), signature stored AMD-style (LE r/s in 72B fields).
    fn signed_report(body_seed: u8, sk: &SigningKey) -> [u8; REPORT_LEN] {
        let mut report = [0u8; REPORT_LEN];
        for (i, b) in report[..SIG_OFFSET].iter_mut().enumerate() {
            *b = body_seed.wrapping_add(i as u8);
        }
        let digest = Sha384::digest(&report[..SIG_OFFSET]);
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let be = sig.to_bytes(); // 96B big-endian r||s
        let mut r_le = [0u8; 48];
        r_le.copy_from_slice(&be[..48]);
        r_le.reverse();
        let mut s_le = [0u8; 48];
        s_le.copy_from_slice(&be[48..]);
        s_le.reverse();
        report[SIG_OFFSET..SIG_OFFSET + 48].copy_from_slice(&r_le);
        report[SIG_OFFSET + SIG_COMPONENT_LEN..SIG_OFFSET + SIG_COMPONENT_LEN + 48]
            .copy_from_slice(&s_le);
        report
    }

    #[test]
    fn valid_report_signature_verifies() {
        let sk = test_signing_key();
        let vk = VerifyingKey::from(&sk);
        let report = signed_report(0xA5, &sk);
        verify_report_signature(&report, &vk).expect("genuine sig must verify");
    }

    #[test]
    fn tampered_body_fails() {
        let sk = test_signing_key();
        let vk = VerifyingKey::from(&sk);
        let mut report = signed_report(0xA5, &sk);
        report[0x90] ^= 0x01; // flip a measurement byte
        assert!(matches!(
            verify_report_signature(&report, &vk),
            Err(VerifyError::ReportSignature)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let sk = test_signing_key();
        let report = signed_report(0xA5, &sk);
        // A different key must reject.
        let mut other = [0u8; 48];
        other[47] = 9;
        let vk2 = VerifyingKey::from(&SigningKey::from_slice(&other).unwrap());
        assert!(matches!(
            verify_report_signature(&report, &vk2),
            Err(VerifyError::ReportSignature)
        ));
    }

    #[test]
    fn short_report_rejected() {
        let sk = test_signing_key();
        let vk = VerifyingKey::from(&sk);
        let report = signed_report(0xA5, &sk);
        assert!(matches!(
            verify_report_signature(&report[..REPORT_LEN - 1], &vk),
            Err(VerifyError::ShortReport(_))
        ));
    }
}
