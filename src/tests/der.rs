//! Port of test/der.test.ts: the PKCS#1 -> PKCS#8 wrapper, checked against keys
//! the `rsa` crate generated rather than against the byte layout it was
//! written to produce.
//!
//! GitHub hands out PKCS#1 ("BEGIN RSA PRIVATE KEY"). A subtly wrong DER
//! envelope yields a key that imports at one modulus size and fails at
//! another: an intermittent production auth failure rather than a build error.

use super::*;
use crate::github::{der_length, pem_body, pkcs1_to_pkcs8};
use rsa::pkcs1::EncodeRsaPrivateKey;

fn key_of(bits: usize) -> PrivateKey {
    PrivateKey::new(&mut getrandom::SysRng, bits).expect("generate key")
}

fn pkcs1_pem(k: &PrivateKey) -> String {
    pem("RSA PRIVATE KEY", k.to_pkcs1_der().unwrap().as_bytes())
}

fn pkcs8_pem(k: &PrivateKey) -> String {
    pem("PRIVATE KEY", &pkcs8_der(k))
}

#[test]
fn wrapper_output_is_byte_identical_to_real_pkcs8_at_2048_3072_and_4096() {
    for bits in [2048, 3072, 4096] {
        let k = key_of(bits);
        let (pkcs1, _) = pem_body(&pkcs1_pem(&k)).unwrap();
        let (real, _) = pem_body(&pkcs8_pem(&k)).unwrap();
        assert_eq!(pkcs1_to_pkcs8(&pkcs1), real, "RSA-{bits}");
    }
}

#[test]
fn the_wrapped_key_imports_and_signs_at_every_size() {
    use rsa::pkcs8::DecodePrivateKey;
    for bits in [2048, 3072, 4096] {
        let k = key_of(bits);
        let (pkcs1, _) = pem_body(&pkcs1_pem(&k)).unwrap();
        let imported = PrivateKey::from_pkcs8_der(&pkcs1_to_pkcs8(&pkcs1)).expect("import");
        let sig = imported.pkcs1v15_sign::<Sha256>(b"header.payload").unwrap();
        assert_eq!(sig.len(), bits / 8, "RSA-{bits}");
    }
}

#[test]
fn pem_body_distinguishes_pkcs1_from_pkcs8() {
    let k = key_of(2048);
    assert!(pem_body(&pkcs1_pem(&k)).unwrap().1);
    assert!(!pem_body(&pkcs8_pem(&k)).unwrap().1);
}

#[test]
fn pem_body_rejects_a_non_pem_value_rather_than_producing_a_junk_key() {
    let e = pem_body("not a pem at all").unwrap_err();
    assert!(e.message.contains("empty or not a PEM"), "{}", e.message);
    // Markers with nothing between them are also refused.
    assert!(pem_body("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----").is_err());
}

#[test]
fn der_length_uses_short_form_below_128_and_long_form_at_or_above_it() {
    // The long-form boundary is where a hand-rolled DER encoder usually
    // breaks, and every RSA key body of interest sits well past it.
    assert_eq!(der_length(0), vec![0]);
    assert_eq!(der_length(127), vec![127]);
    assert_eq!(der_length(128), vec![0x81, 128]);
    assert_eq!(der_length(255), vec![0x81, 255]);
    assert_eq!(der_length(256), vec![0x82, 1, 0]);
    assert_eq!(der_length(65535), vec![0x82, 255, 255]);
    assert_eq!(der_length(65536), vec![0x83, 1, 0, 0]);
}
