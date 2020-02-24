#[macro_use]
extern crate honggfuzz;
extern crate chacha;
extern crate orion;
pub mod utils;

use chacha::{ChaCha, KeyStream};
use orion::hazardous::stream::chacha20;
use orion::hazardous::stream::xchacha20;
use utils::{make_seeded_rng, ChaChaRng, RngCore};

const CHACHA_BLOCKSIZE: usize = 64;

/// `orion::hazardous::stream::chacha20`
fn fuzz_chacha20(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
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
    let orion_key = chacha20::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

    let mut orion_pt = vec![0u8; plaintext.len()];
    let mut orion_ct = vec![0u8; plaintext.len()];

    // Counter must be 0, as that is what the chacha crate uses.
    chacha20::encrypt(&orion_key, &orion_nonce, 0, &plaintext, &mut orion_ct).unwrap();
    chacha20::decrypt(&orion_key, &orion_nonce, 0, &orion_ct, &mut orion_pt).unwrap();
    assert_eq!(&orion_pt[..], plaintext);

    // chacha
    // The chacha crate does in-place encryption.
    let mut chacha_ct = plaintext.to_vec();
    // Different structs because they don't reset counter
    let mut stream_enc = ChaCha::new_ietf(&key, &nonce);
    let mut stream_dec = ChaCha::new_ietf(&key, &nonce);

    stream_enc
        .xor_read(&mut chacha_ct)
        .expect("hit end of stream far too soon");

    let mut chacha_pt = chacha_ct.clone();
    stream_dec
        .xor_read(&mut chacha_pt)
        .expect("hit end of stream far too soon");

    assert_eq!(plaintext, &chacha_pt[..]);
    assert_eq!(orion_ct, chacha_ct);
    assert_eq!(orion_pt, chacha_pt);
}

/// `orion::hazardous::stream::xchacha20`
fn fuzz_xchacha20(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
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
    let orion_key = xchacha20::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = xchacha20::Nonce::from_slice(&nonce).unwrap();

    let mut orion_pt = vec![0u8; plaintext.len()];
    let mut orion_ct = vec![0u8; plaintext.len()];

    // Counter must be 0, as that is what the chacha crate uses.
    xchacha20::encrypt(&orion_key, &orion_nonce, 0, &plaintext, &mut orion_ct).unwrap();
    xchacha20::decrypt(&orion_key, &orion_nonce, 0, &orion_ct, &mut orion_pt).unwrap();
    assert_eq!(&orion_pt[..], plaintext);

    // chacha
    // The chacha crate does in-place encryption.
    let mut chacha_ct = plaintext.to_vec();
    // Different structs because they don't reset counter
    let mut stream_enc = ChaCha::new_xchacha20(&key, &nonce);
    let mut stream_dec = ChaCha::new_xchacha20(&key, &nonce);

    stream_enc
        .xor_read(&mut chacha_ct)
        .expect("hit end of stream far too soon");

    let mut chacha_pt = chacha_ct.clone();
    stream_dec
        .xor_read(&mut chacha_pt)
        .expect("hit end of stream far too soon");

    assert_eq!(plaintext, &chacha_pt[..]);
    assert_eq!(orion_ct, chacha_ct);
    assert_eq!(orion_pt, chacha_pt);
}

// Test if an initial counter will overflow when processing input bytes.
fn check_counter_overflow(input: &[u8], initial_counter: u32) -> bool {
    // Instead of using division, floats, and ceil()
    // we just simulate an actual call to encrypt/decrypt

    let mut res = false;
    let mut counter = initial_counter;

    for _ in input.chunks(CHACHA_BLOCKSIZE) {
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
fn fuzz_stream_counters(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
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
    let orion_key = chacha20::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

    let x_orion_nonce = xchacha20::Nonce::from_slice(&x_nonce).unwrap();

    let mut orion_ct = vec![0u8; plaintext.len()];
    let mut x_orion_ct = vec![0u8; plaintext.len()];

    let will_counter_overflow: bool = check_counter_overflow(&plaintext, random_counter);

    // If either one fails, then both should fail.
    if will_counter_overflow {
        assert!(chacha20::encrypt(
            &orion_key,
            &orion_nonce,
            random_counter,
            &plaintext,
            &mut orion_ct
        )
        .is_err());
        assert!(xchacha20::encrypt(
            &orion_key,
            &x_orion_nonce,
            random_counter,
            &plaintext,
            &mut x_orion_ct
        )
        .is_err());
    } else {
        chacha20::encrypt(
            &orion_key,
            &orion_nonce,
            random_counter,
            &plaintext,
            &mut orion_ct,
        )
        .unwrap();
        xchacha20::encrypt(
            &orion_key,
            &x_orion_nonce,
            random_counter,
            &plaintext,
            &mut x_orion_ct,
        )
        .unwrap();

        let mut orion_pt = vec![0u8; plaintext.len()];
        let mut x_orion_pt = vec![0u8; plaintext.len()];

        chacha20::decrypt(
            &orion_key,
            &orion_nonce,
            random_counter,
            &orion_ct,
            &mut orion_pt,
        )
        .unwrap();
        xchacha20::decrypt(
            &orion_key,
            &x_orion_nonce,
            random_counter,
            &x_orion_ct,
            &mut x_orion_pt,
        )
        .unwrap();

        assert_eq!(&orion_pt[..], plaintext);
        assert_eq!(&x_orion_pt[..], plaintext);
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
