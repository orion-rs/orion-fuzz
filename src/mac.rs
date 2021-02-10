#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate ring;
extern crate sodiumoxide;
pub mod utils;

use orion::hazardous::hash::sha2::sha512::SHA512_BLOCKSIZE;
use orion::hazardous::mac::hmac;
use orion::hazardous::mac::poly1305;
use sodiumoxide::crypto::onetimeauth;
use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, RngCore};

const POLY1305_BLOCKSIZE: usize = 16;


fn fuzz_hmac_sha256(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let key = rand_vec_in_range(seeded_rng, 0, 256);

    // orion
    let orion_key = hmac::sha256::SecretKey::from_slice(&key).unwrap();
    let mut orion_ctx = hmac::sha256::HmacSha256::new(&orion_key);
    orion_ctx.update(fuzzer_input).unwrap();

    // ring
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let mut other_ctx = ring::hmac::Context::with_key(&ring_key);
    other_ctx.update(fuzzer_input);

    let mut collected_data: Vec<u8> = Vec::new();
    collected_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
        orion_ctx.update(b"").unwrap();
        other_ctx.update(b"");
        collected_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
        orion_ctx.update(b"Extra").unwrap();
        other_ctx.update(b"Extra");
        collected_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
        orion_ctx.update(&[0u8; 256]).unwrap();
        other_ctx.update(&[0u8; 256]);
        collected_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = other_ctx.sign();
    let orion_tag = orion_ctx.finalize().unwrap();

    let orion_one_shot = hmac::sha256::HmacSha256::hmac(&orion_key, &collected_data).unwrap();
    let other_one_shot = ring::hmac::sign(&ring_key, &collected_data);

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(orion_one_shot, orion_tag);
    assert_eq!(other_one_shot.as_ref(), orion_tag.unprotected_as_bytes());
}


fn fuzz_hmac_sha384(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let key = rand_vec_in_range(seeded_rng, 0, 256);

    // orion
    let orion_key = hmac::sha384::SecretKey::from_slice(&key).unwrap();
    let mut orion_ctx = hmac::sha384::HmacSha384::new(&orion_key);
    orion_ctx.update(fuzzer_input).unwrap();

    // ring
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, &key);
    let mut other_ctx = ring::hmac::Context::with_key(&ring_key);
    other_ctx.update(fuzzer_input);

    let mut collected_data: Vec<u8> = Vec::new();
    collected_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
        orion_ctx.update(b"").unwrap();
        other_ctx.update(b"");
        collected_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
        orion_ctx.update(b"Extra").unwrap();
        other_ctx.update(b"Extra");
        collected_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
        orion_ctx.update(&[0u8; 256]).unwrap();
        other_ctx.update(&[0u8; 256]);
        collected_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = other_ctx.sign();
    let orion_tag = orion_ctx.finalize().unwrap();

    let orion_one_shot = hmac::sha384::HmacSha384::hmac(&orion_key, &collected_data).unwrap();
    let other_one_shot = ring::hmac::sign(&ring_key, &collected_data);

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(orion_one_shot, orion_tag);
    assert_eq!(other_one_shot.as_ref(), orion_tag.unprotected_as_bytes());
}


fn fuzz_hmac_sha512(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let key = rand_vec_in_range(seeded_rng, 0, 256);

    // orion
    let orion_key = hmac::sha512::SecretKey::from_slice(&key).unwrap();
    let mut orion_ctx = hmac::sha512::HmacSha512::new(&orion_key);
    orion_ctx.update(fuzzer_input).unwrap();

    // ring
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &key);
    let mut other_ctx = ring::hmac::Context::with_key(&ring_key);
    other_ctx.update(fuzzer_input);

    let mut collected_data: Vec<u8> = Vec::new();
    collected_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
        orion_ctx.update(b"").unwrap();
        other_ctx.update(b"");
        collected_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
        orion_ctx.update(b"Extra").unwrap();
        other_ctx.update(b"Extra");
        collected_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
        orion_ctx.update(&[0u8; 256]).unwrap();
        other_ctx.update(&[0u8; 256]);
        collected_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = other_ctx.sign();
    let orion_tag = orion_ctx.finalize().unwrap();

    let orion_one_shot = hmac::sha512::HmacSha512::hmac(&orion_key, &collected_data).unwrap();
    let other_one_shot = ring::hmac::sign(&ring_key, &collected_data);

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(orion_one_shot, orion_tag);
    assert_eq!(other_one_shot.as_ref(), orion_tag.unprotected_as_bytes());
}

fn fuzz_poly1305(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    // orion
    let orion_key = poly1305::OneTimeKey::from_slice(&key).unwrap();
    let mut orion_ctx = poly1305::Poly1305::new(&orion_key);
    orion_ctx.update(fuzzer_input).unwrap();

    // sodiumoxide, does not offer incremental interface.
    let sodiumoxide_key = onetimeauth::poly1305::Key::from_slice(&key).unwrap();

    let mut collected_data: Vec<u8> = Vec::new();
    collected_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > POLY1305_BLOCKSIZE {
        orion_ctx.update(b"").unwrap();
        collected_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > POLY1305_BLOCKSIZE * 2 {
        orion_ctx.update(b"Extra").unwrap();
        collected_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > POLY1305_BLOCKSIZE * 3 {
        orion_ctx.update(&[0u8; 256]).unwrap();
        collected_data.extend_from_slice(&[0u8; 256]);
    }

    let other_tag = onetimeauth::authenticate(&collected_data, &sodiumoxide_key);
    let orion_tag = orion_ctx.finalize().unwrap();
    let orion_one_shot = poly1305::Poly1305::poly1305(&orion_key, &collected_data).unwrap();

    assert_eq!(other_tag.as_ref(), orion_tag.unprotected_as_bytes());
    assert_eq!(other_tag.as_ref(), orion_one_shot.unprotected_as_bytes());
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::mac::hmac`
            fuzz_hmac_sha256(data, &mut seeded_rng);
            fuzz_hmac_sha384(data, &mut seeded_rng);
            fuzz_hmac_sha512(data, &mut seeded_rng);
            // Test `orion::hazardous::mac::poly1305`
            fuzz_poly1305(data, &mut seeded_rng);
        });
    }
}
