#[macro_use]
extern crate honggfuzz;
extern crate orion;
pub mod utils;

use utils::{ChaChaRng, make_seeded_rng, RngCore};

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

        let iterations = if fuzzer_input.is_empty() {
            10000
        } else {
            ((fuzzer_input[0] as usize) * 100)
        };

        if iterations < 1 {
            assert!(orion::pwhash::hash_password(&pwhash_password, iterations).is_err());
        } else {
            let _password_hash = orion::pwhash::hash_password(&pwhash_password, iterations).unwrap();
        }
    }
}

/// `orion::kdf`
fn fuzz_kdf(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut password = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut password);

    let mut salt = vec![0u8; fuzzer_input.len() / 4];
    seeded_rng.fill_bytes(&mut salt);

    if password.is_empty() || salt.is_empty() {
        if password.is_empty() {
            assert!(orion::kdf::Password::from_slice(&password).is_err());
        } else if salt.is_empty() {
            assert!(orion::kdf::Salt::from_slice(&salt).is_err());
        }
    } else {
        let kdf_password = orion::kdf::Password::from_slice(&password).unwrap();
        let kdf_salt = orion::kdf::Salt::from_slice(&salt).unwrap();

        let iterations = if fuzzer_input.is_empty() {
            10000
        } else {
            ((fuzzer_input[0] as usize) * 100)
        };

        let length = if fuzzer_input.is_empty() {
            256
        } else {
            ((fuzzer_input[0] as usize) * 50)
        };

        if (iterations == 0) || (length == 0 || (length >= u32::max_value() as usize)) {
            assert!(orion::kdf::derive_key(&kdf_password, &kdf_salt, iterations, length).is_err());
        } else {
            let _password_hash =
                orion::kdf::derive_key(&kdf_password, &kdf_salt, iterations, length).unwrap();
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
        let tag = orion::auth::authenticate(&auth_key, fuzzer_input).unwrap();

        assert!(orion::auth::authenticate_verify(&tag, &auth_key, fuzzer_input).unwrap());
    }
}

/// `orion::hash`
fn fuzz_hash(fuzzer_input: &[u8]) {
    let _digest = orion::hash::digest(fuzzer_input).unwrap();
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
            // Test `orion::has`
            fuzz_hash(data);
        });
    }
}
