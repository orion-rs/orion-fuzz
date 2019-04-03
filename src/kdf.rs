#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate ring;
pub mod utils;

use orion::hazardous::constants::SHA512_OUTSIZE;
use orion::hazardous::kdf::hkdf;
use utils::{make_seeded_rng, ChaChaRng, RngCore};

fn fuzz_hkdf(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut ikm = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut ikm);

    let mut salt = vec![0u8; fuzzer_input.len() / 4];
    seeded_rng.fill_bytes(&mut salt);

    let mut orion_okm: Vec<u8> =
        if (fuzzer_input.len() / 2) > (255 * SHA512_OUTSIZE) || (fuzzer_input.len() / 2) < 1 {
            vec![0u8; 256]
        } else {
            vec![0u8; fuzzer_input.len() / 2]
        };

    let mut other_okm = orion_okm.clone();

    // Empty info will be the same as None.
    let info: Vec<u8> = if fuzzer_input.is_empty() {
        vec![0u8; 0]
    } else {
        vec![0u8; fuzzer_input[0] as usize]
    };

    // orion
    let orion_prk = hkdf::extract(&salt, &ikm).unwrap();
    hkdf::expand(&orion_prk, Some(&info), &mut orion_okm).unwrap();

    // ring
    let other_salt = ring::hmac::SigningKey::new(&ring::digest::SHA512, &salt);
    let other_prk = ring::hkdf::extract(&other_salt, &ikm);
    ring::hkdf::expand(&other_prk, &info, &mut other_okm[..]);

    // We cannot compare PRKs because ring's SigningKey does not offer
    // access to internal bytes.
    assert_eq!(orion_okm, other_okm);
    // Test extract-then-expand combination
    hkdf::derive_key(&salt, &ikm, Some(&info), &mut orion_okm).unwrap();
    ring::hkdf::extract_and_expand(&other_salt, &ikm, &info, &mut other_okm);
    assert_eq!(orion_okm, other_okm);
    
    // Verify the OKM of both orion and ring
    let mut orion_verify_itself_out = orion_okm.clone();
    let mut orion_verify_other_out = orion_okm.clone();
    assert!(hkdf::verify(&orion_okm, &salt, &ikm, Some(&info), &mut orion_verify_itself_out).unwrap());
    assert!(hkdf::verify(&other_okm, &salt, &ikm, Some(&info), &mut orion_verify_other_out).unwrap());
}

fn fuzz_pbkdf2(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {






}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::kdf::hkdf`
            fuzz_hkdf(data, &mut seeded_rng);
            // Test `orion::hazardous::kdf::pbkdf2`
            // fuzz_pbkdf2(data, &mut seeded_rng);
        });
    }
}
