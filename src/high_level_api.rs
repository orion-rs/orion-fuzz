use honggfuzz::fuzz;
pub mod utils;

use utils::*;

// The tests in this module are not meant for differntial comparison
// and are not the ones to target seriously. These serve more of a double-check
// compared to basic functionality Orion's own test should already cover.

/// `orion::aead`
fn fuzz_aead(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = [0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    // NOTE(brycx): seal() is NOT deterministic - OSRNG to generate a nonce.
    let aead_key = orion::aead::SecretKey::try_from(&key).unwrap();

    if fuzzer_input.is_empty() {
        assert!(orion::aead::seal(&aead_key, fuzzer_input).is_err());
    } else {
        let aead_ciphertext = orion::aead::seal(&aead_key, fuzzer_input).unwrap();
        let aead_decrypted = orion::aead::open(&aead_key, &aead_ciphertext).unwrap();
        assert_eq!(fuzzer_input, &aead_decrypted[..]);

        let mut mutated_ciphertext = aead_ciphertext.clone();
        if mutate_value(fuzzer_input, &mut mutated_ciphertext) > 0 {
            assert!(orion::aead::open(&aead_key, &aead_ciphertext).is_err());
        }
    }
}

/// `orion::pwhash`
fn fuzz_pwhash(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut password = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut password);

    if password.is_empty() {
        assert!(orion::pwhash::Password::try_from(&password).is_err());
    } else {
        let pwhash_password = orion::pwhash::Password::try_from(&password).unwrap();
        let iterations: u32 = seeded_rng.random_range(1..=4);
        let lanes: u32 = seeded_rng.random_range(1..=3);
        let memory: u32 = seeded_rng.random_range(8 * lanes..=4096);
        let cost = orion::pwhash::CostParams::new(iterations, memory, lanes).unwrap();
        let password_hash = orion::pwhash::hash_password(&pwhash_password, &cost).unwrap();
        assert!(orion::pwhash::hash_password_verify(&password_hash, &pwhash_password).is_ok());
    }
}

/// `orion::kdf`
fn fuzz_kdf(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut password = vec![0u8; fuzzer_input.len() / 2];
    seeded_rng.fill_bytes(&mut password);

    let salt = rand_vec_in_range(seeded_rng, 0, 128);

    if password.is_empty() || salt.is_empty() {
        if password.is_empty() {
            assert!(orion::kdf::Password::try_from(&password).is_err());
        } else if salt.is_empty() {
            assert!(orion::kdf::Salt::try_from(&salt).is_err());
        }
    } else {
        let kdf_password = orion::kdf::Password::try_from(&password).unwrap();
        let kdf_salt = orion::kdf::Salt::try_from(&salt).unwrap();
        let iterations: u32 = seeded_rng.random_range(1..=4);
        let lanes: u32 = seeded_rng.random_range(1..=3);
        let memory: u32 = seeded_rng.random_range(8 * lanes..=4096);
        let cost = orion::pwhash::CostParams::new(iterations, memory, lanes).unwrap();
        let length: u32 = seeded_rng.random_range(4..=768);

        if salt.len() < 8 {
            assert!(orion::kdf::derive_key(&kdf_password, &kdf_salt, &cost, length).is_err());
            return;
        }

        let password_hash_first =
            orion::kdf::derive_key(&kdf_password, &kdf_salt, &cost, length).unwrap();
        let password_hash_second =
            orion::kdf::derive_key(&kdf_password, &kdf_salt, &cost, length).unwrap();
        assert_eq!(password_hash_first, password_hash_second);
    }
}

/// `orion::auth`
fn fuzz_auth(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = vec![0u8; seeded_rng.random_range(1..=64)];
    seeded_rng.fill_bytes(&mut key);

    let auth_key = orion::auth::SecretKey::try_from(&key).unwrap();
    if auth_key.len() < 32 || auth_key.len() > 64 {
        assert!(orion::auth::authenticate(&auth_key, fuzzer_input).is_err());
    } else {
        let tag = orion::auth::authenticate(&auth_key, fuzzer_input).unwrap();
        assert!(orion::auth::authenticate_verify(&tag, &auth_key, fuzzer_input).is_ok());
    }
}

/// `orion::hash`
fn fuzz_hash(fuzzer_input: &[u8]) {
    assert_eq!(
        orion::hash::digest(fuzzer_input).unwrap(),
        orion::hash::digest(fuzzer_input).unwrap()
    );
}

/// `orion::hpke`
fn fuzz_hpke(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    use orion::KP;

    let mut key = [0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    let recipient_kp =
        orion::hpke::KeyPair::try_from(&orion::kem::DecapsulationKey::from(key)).unwrap();

    let info = rand_vec_in_range(seeded_rng, 0, u16::MAX as usize);
    let psk = rand_vec_in_range(seeded_rng, 32, u16::MAX as usize);
    let psk_id = rand_vec_in_range(seeded_rng, 1, u16::MAX as usize);
    let aad = rand_vec_in_range(seeded_rng, 0, 32);

    // NOTE(brycx): Not deterministic KEM operation (internal RNG)

    let (mut hpke_sender, enc) =
        orion::hpke::HpkeBase::new_sender(recipient_kp.public(), &info).unwrap();
    let mut hpke_recipient =
        orion::hpke::HpkeBase::new_recipient(&enc, recipient_kp.private(), &info).unwrap();
    let (mut hpke_sender_psk, enc_psk) =
        orion::hpke::HpkePsk::new_sender(recipient_kp.public(), &info, &psk, &psk_id).unwrap();
    let mut hpke_recipient_psk =
        orion::hpke::HpkePsk::new_recipient(&enc_psk, recipient_kp.private(), &info, &psk, &psk_id)
            .unwrap();

    let n_seals = seeded_rng.random_range(1..=16);
    let mut cts: Vec<Vec<u8>> = Vec::new();
    let mut cts_psk: Vec<Vec<u8>> = Vec::new();

    for _ in 0..n_seals {
        cts.push(hpke_sender.seal(fuzzer_input, &aad).unwrap());
        cts_psk.push(hpke_sender_psk.seal(fuzzer_input, &aad).unwrap());
    }

    for (ct, ct_psk) in cts.iter().zip(cts_psk.iter()) {
        assert!(hpke_recipient.open(ct, &aad).is_ok());
        assert!(hpke_recipient_psk.open(ct_psk, &aad).is_ok());
    }
}

/// `orion::kem`
fn fuzz_kem(seeded_rng: &mut ChaCha8Rng) {
    use orion::KP;

    let mut key = [0u8; 32];

    // NOTE(brycx): Not deterministic KEM operation (internal RNG)

    seeded_rng.fill_bytes(&mut key);
    let alice = orion::kem::KeyPair::try_from(&orion::kem::DecapsulationKey::from(key)).unwrap();

    seeded_rng.fill_bytes(&mut key);
    let bob = orion::kem::KeyPair::try_from(&orion::kem::DecapsulationKey::from(key)).unwrap();

    let (alice_shared, alice_ciphertext) = alice.public().encap().unwrap();
    let (bob_shared, bob_ciphertext) = bob.public().encap().unwrap();

    assert_eq!(alice_shared, bob.decap(&alice_ciphertext).unwrap());
    assert_eq!(bob_shared, alice.decap(&bob_ciphertext).unwrap());
}

/// `orion::signer`
fn fuzz_signer(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = [0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    // NOTE(brycx): Not deterministic ML-DSA operation (internal RNG)
    let kp = orion::signer::SigningKeyPair::try_from(&orion::signer::Seed::from(key)).unwrap();
    let ctx = &rand_vec_in_range(seeded_rng, 0, 255);
    let sig = kp.sign(fuzzer_input, ctx).unwrap();
    assert!(kp.verify(fuzzer_input, ctx, &sig).is_ok());
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
            // Test `orion::hpke`
            fuzz_hpke(data, &mut seeded_rng);
            // Test `orion::kem`
            fuzz_kem(&mut seeded_rng);
            // Test `orion::signer`
            fuzz_signer(data, &mut seeded_rng);
        });
    }
}
