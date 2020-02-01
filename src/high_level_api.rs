#[macro_use]
extern crate honggfuzz;
extern crate orion;
pub mod utils;

use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, Rng, RngCore};

/// `orion::aead`
fn fuzz_aead(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = [0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    let aead_key = orion::aead::SecretKey::from_slice(&key).unwrap();

    if fuzzer_input.is_empty() {
        assert!(orion::aead::seal(&aead_key, &fuzzer_input).is_err());
    } else {
        let aead_ciphertext = orion::aead::seal(&aead_key, fuzzer_input).unwrap();
        let aead_decrypted = orion::aead::open(&aead_key, &aead_ciphertext).unwrap();
        assert_eq!(fuzzer_input, &aead_decrypted[..]);
    }
}

/// `orion::pwhash`
fn fuzz_pwhash(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut password = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut password);

    if password.is_empty() {
        assert!(orion::pwhash::Password::from_slice(&password).is_err());
    } else {
        let pwhash_password = orion::pwhash::Password::from_slice(&password).unwrap();
        let memory: u32 = seeded_rng.gen_range(0, 1024 + 1);
        let iterations: u32 = seeded_rng.gen_range(0, 10 + 1);

        if iterations < 3 || memory < 8 {
            assert!(orion::pwhash::hash_password(&pwhash_password, iterations, memory).is_err());
        } else {
            let password_hash =
                orion::pwhash::hash_password(&pwhash_password, iterations, memory).unwrap();
            assert!(orion::pwhash::hash_password_verify(
                &password_hash,
                &pwhash_password,
                iterations,
                memory
            )
            .is_ok());
        }
    }
}

/// `orion::kdf`
fn fuzz_kdf(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut password = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut password);

    let salt = rand_vec_in_range(seeded_rng, 0, 128);

    if password.is_empty() || salt.is_empty() {
        if password.is_empty() {
            assert!(orion::kdf::Password::from_slice(&password).is_err());
        } else if salt.is_empty() {
            assert!(orion::kdf::Salt::from_slice(&salt).is_err());
        }
    } else {
        let kdf_password = orion::kdf::Password::from_slice(&password).unwrap();
        let kdf_salt = orion::kdf::Salt::from_slice(&salt).unwrap();
        let memory: u32 = seeded_rng.gen_range(0, 1024 + 1);
        let iterations: u32 = seeded_rng.gen_range(0, 10 + 1);
        let length: u32 = seeded_rng.gen_range(0, 768);

        if iterations < 3 || length < 4 || memory < 8 || salt.len() < 8 {
            assert!(
                orion::kdf::derive_key(&kdf_password, &kdf_salt, iterations, memory, length)
                    .is_err()
            );
        } else {
            dbg!(password, salt, iterations, memory, length);
            let password_hash =
                orion::kdf::derive_key(&kdf_password, &kdf_salt, iterations, memory, length)
                    .unwrap();
            assert!(orion::kdf::derive_key_verify(
                &password_hash,
                &kdf_password,
                &kdf_salt,
                iterations,
                memory
            )
            .is_ok());
        }
    }
}

/// `orion::auth`
fn fuzz_auth(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut key);

    if key.is_empty() {
        assert!(orion::auth::SecretKey::from_slice(&key).is_err());
    } else {
        let auth_key = orion::auth::SecretKey::from_slice(&key).unwrap();
        if auth_key.len() < 32 || auth_key.len() > 64 {
            assert!(orion::auth::authenticate(&auth_key, fuzzer_input).is_err());
        } else {
            let tag = orion::auth::authenticate(&auth_key, fuzzer_input).unwrap();
            assert!(orion::auth::authenticate_verify(&tag, &auth_key, fuzzer_input).is_ok());
        }
    }
}

/// `orion::hash`
fn fuzz_hash(fuzzer_input: &[u8]) {
    orion::hash::digest(fuzzer_input).unwrap();
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::aead`
            fuzz_aead(data, &mut seeded_rng);
            // Test `orion::pwhash`
            fuzz_pwhash(data, &mut seeded_rng);
            // Test `orion::kdf`
            fuzz_kdf(data, &mut seeded_rng);
            // Test `orion::auth`
            fuzz_auth(data, &mut seeded_rng);
            // Test `orion::hash`
            fuzz_hash(data);
        });
    }
}
