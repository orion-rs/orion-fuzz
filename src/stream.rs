pub mod utils;

use chacha::{ChaCha, KeyStream};
use honggfuzz::fuzz;
use orion::hazardous::stream::chacha20;
use orion::hazardous::stream::xchacha20;
use utils::*;

const CHACHA_BLOCKSIZE: usize = 64;

/// `orion::hazardous::stream::chacha20`
fn fuzz_chacha20(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = [0u8; chacha20::CHACHA_KEYSIZE];
    seeded_rng.fill_bytes(&mut key);

    let mut nonce = [0u8; chacha20::IETF_CHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut nonce);

    let plaintext = if fuzzer_input.is_empty() {
        &[0u8; 1]
    } else {
        fuzzer_input
    };

    // orion
    let orion_key = chacha20::SecretKey::from(key);
    let orion_nonce = chacha20::Nonce::from(nonce);
    let mut orion_ctx = chacha20::ChaCha20::new(&orion_key, &orion_nonce);
    let mut orion_ct = plaintext.to_vec();
    orion_ctx.xor_keystream_into(&mut orion_ct).unwrap();
    assert_eq!(orion_ctx.byte_position(), plaintext.len() as u64);
    assert_eq!(
        orion_ctx.keystream_remaining(),
        chacha20::MAX_KEYSTREAM_BYTES - plaintext.len() as u64
    );

    // chacha
    let mut chacha_ct = plaintext.to_vec();
    let mut stream_enc = ChaCha::new_ietf(&key, &nonce);
    let mut stream_dec = ChaCha::new_ietf(&key, &nonce);
    stream_enc.xor_read(&mut chacha_ct).unwrap();
    assert_eq!(orion_ct, chacha_ct);

    let mut chacha_pt = chacha_ct.clone();
    stream_dec.xor_read(&mut chacha_pt).unwrap();
    orion_ctx.set_position(0);
    orion_ctx.xor_keystream_into(&mut orion_ct).unwrap();
    assert_eq!(plaintext, orion_ct.as_slice());
    assert_eq!(orion_ct, chacha_pt);
}

/// `orion::hazardous::stream::xchacha20`
fn fuzz_xchacha20(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = [0u8; chacha20::CHACHA_KEYSIZE];
    seeded_rng.fill_bytes(&mut key);

    let mut nonce = [0u8; xchacha20::XCHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut nonce);

    let plaintext = if fuzzer_input.is_empty() {
        &[0u8; 1]
    } else {
        fuzzer_input
    };

    // orion
    let orion_key = xchacha20::SecretKey::from(key);
    let orion_nonce = xchacha20::Nonce::from(nonce);
    let mut orion_ctx = xchacha20::XChaCha20::new(&orion_key, &orion_nonce);
    let mut orion_ct = plaintext.to_vec();
    orion_ctx.xor_keystream_into(&mut orion_ct).unwrap();
    assert_eq!(orion_ctx.byte_position(), plaintext.len() as u64);
    assert_eq!(
        orion_ctx.keystream_remaining(),
        chacha20::MAX_KEYSTREAM_BYTES - plaintext.len() as u64
    );

    // chacha
    let mut chacha_ct = plaintext.to_vec();
    let mut stream_enc = ChaCha::new_xchacha20(&key, &nonce);
    let mut stream_dec = ChaCha::new_xchacha20(&key, &nonce);
    stream_enc.xor_read(&mut chacha_ct).unwrap();
    assert_eq!(orion_ct, chacha_ct);

    let mut chacha_pt = chacha_ct.clone();
    stream_dec.xor_read(&mut chacha_pt).unwrap();
    orion_ctx.set_position(0);
    orion_ctx.xor_keystream_into(&mut orion_ct).unwrap();
    assert_eq!(plaintext, orion_ct.as_slice());
    assert_eq!(orion_ct, chacha_pt);
}

// Test if an initial counter will overflow when processing input bytes.
fn check_counter_overflow(input: &[u8], initial_counter: u32) -> bool {
    // Instead of using division, floats, and ceil()
    // we just simulate an actual call to encrypt/decrypt

    let mut res = false;
    let mut counter = initial_counter;

    // Skip 1 as we'd always want to generate at least one.
    for _ in input.chunks(CHACHA_BLOCKSIZE).skip(1) {
        if counter.checked_add(1).is_none() {
            res = true;
            return res;
        } else {
            counter = counter.checked_add(1).unwrap();
        }
    }

    res
}

/// `orion::hazardous::stream::xchacha20` + `orion::hazardous::stream::chacha20`
/// Because there seem to be no crates that support different initial counters,
/// we need to test it separately here.
fn fuzz_stream_counters(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = [0u8; chacha20::CHACHA_KEYSIZE];
    seeded_rng.fill_bytes(&mut key);

    let mut nonce = [0u8; chacha20::IETF_CHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut nonce);

    let mut x_nonce = [0u8; xchacha20::XCHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut x_nonce);

    let random_counter: u32 = seeded_rng.next_u32();

    let plaintext = if fuzzer_input.is_empty() {
        &[0u8; 1]
    } else {
        fuzzer_input
    };

    // orion
    let orion_key = chacha20::SecretKey::from(key);
    let orion_nonce_ietf = chacha20::Nonce::from(nonce);
    let orion_nonce_x = xchacha20::Nonce::from(x_nonce);

    let mut chacha20_ctx = chacha20::ChaCha20::new(&orion_key, &orion_nonce_ietf);
    let mut xchacha20_ctx = xchacha20::XChaCha20::new(&orion_key, &orion_nonce_x);

    chacha20_ctx.set_position(random_counter);
    xchacha20_ctx.set_position(random_counter);

    let mut ct = plaintext.to_vec();
    let mut xct = plaintext.to_vec();
    let will_counter_overflow: bool = check_counter_overflow(plaintext, random_counter);

    // If either one fails, then both should fail.
    if will_counter_overflow {
        assert!(chacha20_ctx.xor_keystream_into(&mut ct).is_err());
        assert!(xchacha20_ctx.xor_keystream_into(&mut xct).is_err());
    } else {
        chacha20_ctx.xor_keystream_into(&mut ct).unwrap();
        xchacha20_ctx.xor_keystream_into(&mut xct).unwrap();

        if !chacha20_ctx.is_exhausted() && !xchacha20_ctx.is_exhausted() {
            // Reset
            chacha20_ctx.set_position(random_counter);
            xchacha20_ctx.set_position(random_counter);
            // Decrypt
            chacha20_ctx.xor_keystream_into(&mut ct).unwrap();
            xchacha20_ctx.xor_keystream_into(&mut xct).unwrap();
        } else {
            let mut chacha20_ctx = chacha20::ChaCha20::new(&orion_key, &orion_nonce_ietf);
            let mut xchacha20_ctx = xchacha20::XChaCha20::new(&orion_key, &orion_nonce_x);

            chacha20_ctx.set_position(random_counter);
            xchacha20_ctx.set_position(random_counter);

            chacha20_ctx.xor_keystream_into(&mut ct).unwrap();
            xchacha20_ctx.xor_keystream_into(&mut xct).unwrap();
        }

        assert_eq!(ct.as_slice(), plaintext);
        assert_eq!(xct.as_slice(), plaintext);
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::stream::chacha20`
            fuzz_chacha20(data, &mut seeded_rng);
            // Test `orion::hazardous::stream::xchacha20`
            fuzz_xchacha20(data, &mut seeded_rng);
            // `orion::hazardous::stream::xchacha20` + `orion::hazardous::stream::chacha20`
            fuzz_stream_counters(data, &mut seeded_rng);
        });
    }
}
