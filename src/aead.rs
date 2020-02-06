#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate sodiumoxide;
pub mod utils;

use orion::hazardous::aead::chacha20poly1305;
use orion::hazardous::aead::xchacha20poly1305;
use orion::hazardous::stream::{
    chacha20::{CHACHA_KEYSIZE, IETF_CHACHA_NONCESIZE},
    xchacha20::XCHACHA_NONCESIZE,
};
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, RngCore};

/// `orion::hazardous::aead::chacha20poly1305`
fn fuzz_chacha20_poly1305(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; CHACHA_KEYSIZE];
    seeded_rng.fill_bytes(&mut key);

    let mut nonce = vec![0u8; IETF_CHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut nonce);

    // `ad` will be both tested as Some and None as None is the same as [0u8; 0]
    let ad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = if fuzzer_input.is_empty() {
        &[0u8; 1]
    } else {
        fuzzer_input
    };

    // orion
    let mut ciphertext_with_tag_orion = vec![0u8; plaintext.len() + 16];
    let mut plaintext_out_orion = vec![0u8; plaintext.len()];

    let orion_key = chacha20poly1305::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = chacha20poly1305::Nonce::from_slice(&nonce).unwrap();

    chacha20poly1305::seal(
        &orion_key,
        &orion_nonce,
        &plaintext,
        Some(&ad),
        &mut ciphertext_with_tag_orion,
    )
    .unwrap();
    chacha20poly1305::open(
        &orion_key,
        &orion_nonce,
        &ciphertext_with_tag_orion,
        Some(&ad),
        &mut plaintext_out_orion,
    )
    .unwrap();

    // sodiumoxide
    let sodium_key = chacha20poly1305_ietf::Key::from_slice(&key).unwrap();
    let sodium_nonce = chacha20poly1305_ietf::Nonce::from_slice(&nonce).unwrap();

    let sodium_ct_with_tag =
        chacha20poly1305_ietf::seal(&plaintext, Some(&ad), &sodium_nonce, &sodium_key);
    let sodium_pt =
        chacha20poly1305_ietf::open(&sodium_ct_with_tag, Some(&ad), &sodium_nonce, &sodium_key)
            .unwrap();

    // First verify they produce same ciphertext/plaintext
    assert_eq!(sodium_ct_with_tag, ciphertext_with_tag_orion);
    assert_eq!(plaintext_out_orion, sodium_pt);
    // Let sodiumoxide decrypt orion ciperthext with tag and vice versa
    let sodium_orion_pt = chacha20poly1305_ietf::open(
        &ciphertext_with_tag_orion,
        Some(&ad),
        &sodium_nonce,
        &sodium_key,
    )
    .unwrap();

    chacha20poly1305::open(
        &orion_key,
        &orion_nonce,
        &sodium_ct_with_tag,
        Some(&ad),
        &mut plaintext_out_orion,
    )
    .unwrap();

    // Then compare the plaintexts after they have decrypted their switched ciphertexts
    assert_eq!(plaintext_out_orion, sodium_orion_pt);
}

/// `orion::hazardous::aead::xchacha20poly1305`
fn fuzz_xchacha20_poly1305(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; CHACHA_KEYSIZE];
    seeded_rng.fill_bytes(&mut key);

    let mut nonce = vec![0u8; XCHACHA_NONCESIZE];
    seeded_rng.fill_bytes(&mut nonce);

    // `ad` will be both tested as Some and None as None is the same as [0u8; 0]
    let ad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = if fuzzer_input.is_empty() {
        &[0u8; 1]
    } else {
        fuzzer_input
    };

    // orion
    let mut ciphertext_with_tag_orion: Vec<u8> = vec![0u8; plaintext.len() + 16];
    let mut plaintext_out_orion = vec![0u8; plaintext.len()];

    let orion_key = xchacha20poly1305::SecretKey::from_slice(&key).unwrap();
    let orion_nonce = xchacha20poly1305::Nonce::from_slice(&nonce).unwrap();

    xchacha20poly1305::seal(
        &orion_key,
        &orion_nonce,
        &plaintext,
        Some(&ad),
        &mut ciphertext_with_tag_orion,
    )
    .unwrap();
    xchacha20poly1305::open(
        &orion_key,
        &orion_nonce,
        &ciphertext_with_tag_orion,
        Some(&ad),
        &mut plaintext_out_orion,
    )
    .unwrap();

    // sodiumoxide
    let sodium_key = xchacha20poly1305_ietf::Key::from_slice(&key).unwrap();
    let sodium_nonce = xchacha20poly1305_ietf::Nonce::from_slice(&nonce).unwrap();

    let sodium_ct_with_tag =
        xchacha20poly1305_ietf::seal(&plaintext, Some(&ad), &sodium_nonce, &sodium_key);
    let sodium_pt =
        xchacha20poly1305_ietf::open(&sodium_ct_with_tag, Some(&ad), &sodium_nonce, &sodium_key)
            .unwrap();

    // First verify they produce same ciphertext/plaintext
    assert_eq!(sodium_ct_with_tag, ciphertext_with_tag_orion);
    assert_eq!(plaintext_out_orion, sodium_pt);
    // Let sodiumoxide decrypt orion ciperthext with tag and vice versa
    let sodium_orion_pt = xchacha20poly1305_ietf::open(
        &ciphertext_with_tag_orion,
        Some(&ad),
        &sodium_nonce,
        &sodium_key,
    )
    .unwrap();

    xchacha20poly1305::open(
        &orion_key,
        &orion_nonce,
        &sodium_ct_with_tag,
        Some(&ad),
        &mut plaintext_out_orion,
    )
    .unwrap();

    // Then compare the plaintexts after they have decrypted their switched ciphertexts
    assert_eq!(plaintext_out_orion, sodium_orion_pt);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::aead::chacha20poly1305`
            fuzz_chacha20_poly1305(data, &mut seeded_rng);
            // Test `orion::hazardous::aead::xchacha20poly1305`
            fuzz_xchacha20_poly1305(data, &mut seeded_rng);
        });
    }
}
