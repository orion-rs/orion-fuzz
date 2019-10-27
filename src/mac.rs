#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate ring;
extern crate sodiumoxide; // For Poly1305 // For HMAC
pub mod utils;

use orion::hazardous::hash::sha512::SHA512_BLOCKSIZE;
use orion::hazardous::mac::hmac;
use orion::hazardous::mac::poly1305;
use sodiumoxide::crypto::onetimeauth;
use utils::{make_seeded_rng, ChaChaRng, RngCore};

const POLY1305_BLOCKSIZE: usize = 16;

fn fuzz_hmac(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; fuzzer_input.len()];
    seeded_rng.fill_bytes(&mut key);

    // orion
    let orion_key = hmac::SecretKey::from_slice(&key).unwrap();
    let mut state = hmac::Hmac::new(&orion_key);
    state.update(fuzzer_input).unwrap();

    // ring
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &key);
    let mut context = ring::hmac::Context::with_key(&ring_key);
    context.update(fuzzer_input);

    let mut other_data: Vec<u8> = Vec::new();
    other_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
        state.update(b"").unwrap();
        context.update(b"");
        other_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
        state.update(b"Extra").unwrap();
        context.update(b"Extra");
        other_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
        state.update(&[0u8; 256]).unwrap();
        context.update(&[0u8; 256]);
        other_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = context.sign();
    let orion_tag = state.finalize().unwrap();

    let orion_one_shot = hmac::Hmac::hmac(&orion_key, &other_data).unwrap();
    let other_one_shot = ring::hmac::sign(&ring_key, &other_data);

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(orion_one_shot, orion_tag);
    assert_eq!(other_one_shot.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(other_one_shot.as_ref(), other_tag.as_ref());
}

fn fuzz_poly1305(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    // orion
    let orion_key = poly1305::OneTimeKey::from_slice(&key).unwrap();
    let mut state = poly1305::Poly1305::new(&orion_key);
    state.update(fuzzer_input).unwrap();

    // sodiumoxide
    let sodiumoxide_key = onetimeauth::poly1305::Key::from_slice(&key).unwrap();

    let mut other_data: Vec<u8> = Vec::new();
    other_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > POLY1305_BLOCKSIZE {
        state.update(b"").unwrap();
        other_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > POLY1305_BLOCKSIZE * 2 {
        state.update(b"Extra").unwrap();
        other_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > POLY1305_BLOCKSIZE * 3 {
        state.update(&[0u8; 256]).unwrap();
        other_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = onetimeauth::authenticate(&other_data, &sodiumoxide_key);
    let orion_tag = state.finalize().unwrap();

    let orion_one_shot = poly1305::Poly1305::poly1305(&orion_key, &other_data).unwrap();

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(orion_one_shot, orion_tag);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::mac::hmac`
            fuzz_hmac(data, &mut seeded_rng);
            // Test `orion::hazardous::mac::poly1305`
            fuzz_poly1305(data, &mut seeded_rng);
        });
    }
}
