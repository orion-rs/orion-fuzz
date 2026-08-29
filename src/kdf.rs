use honggfuzz::fuzz;
pub mod utils;

use argon2::{Config, Variant, Version};
use orion::hazardous::{
    hash::sha2::{sha256::SHA256_OUTSIZE, sha384::SHA384_OUTSIZE, sha512::SHA512_OUTSIZE},
    kdf::{argon2 as orion_argon2, hkdf, pbkdf2, scrypt as orion_scrypt},
};
use utils::*;

/// See: https://github.com/briansmith/ring/blob/master/tests/hkdf_tests.rs
/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
struct RingHkdf<T>(T);

impl ring::hkdf::KeyType for RingHkdf<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<ring::hkdf::Okm<'_, RingHkdf<usize>>> for RingHkdf<Vec<u8>> {
    fn from(okm: ring::hkdf::Okm<RingHkdf<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        RingHkdf(r)
    }
}

fn fuzz_hkdf(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let outsize: usize = seeded_rng.random_range(1..=((255 * SHA512_OUTSIZE) * 2));

    let ikm = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 0, 128);
    let info = rand_vec_in_range(seeded_rng, 0, 128);
    let mut orion_okm = vec![0u8; outsize];

    // SHA-256
    if orion_okm.len() > 255 * SHA256_OUTSIZE {
        assert!(
            hkdf::Hkdf::<hkdf::SHA256>::derive_key(&salt, ikm, Some(&info), &mut orion_okm)
                .is_err()
        )
    } else {
        hkdf::Hkdf::<hkdf::SHA256>::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

        let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt);
        let RingHkdf(other_okm) = other_salt
            .extract(ikm)
            .expand(&[&info], RingHkdf(orion_okm.len()))
            .unwrap()
            .into();

        assert_eq!(orion_okm, other_okm);
    }

    // SHA-384
    if orion_okm.len() > 255 * SHA384_OUTSIZE {
        assert!(
            hkdf::Hkdf::<hkdf::SHA384>::derive_key(&salt, ikm, Some(&info), &mut orion_okm)
                .is_err()
        );
    } else {
        hkdf::Hkdf::<hkdf::SHA384>::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

        let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA384, &salt);
        let RingHkdf(other_okm) = other_salt
            .extract(ikm)
            .expand(&[&info], RingHkdf(orion_okm.len()))
            .unwrap()
            .into();

        assert_eq!(orion_okm, other_okm);
    }

    // SHA-512

    // orion
    if orion_okm.len() > 255 * SHA512_OUTSIZE {
        assert!(
            hkdf::Hkdf::<hkdf::SHA512>::derive_key(&salt, ikm, Some(&info), &mut orion_okm)
                .is_err()
        );
    } else {
        hkdf::Hkdf::<hkdf::SHA512>::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

        let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &salt);
        let RingHkdf(other_okm) = other_salt
            .extract(ikm)
            .expand(&[&info], RingHkdf(orion_okm.len()))
            .unwrap()
            .into();

        assert_eq!(orion_okm, other_okm);
    }
}

fn fuzz_pbkdf2(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let outsize: usize = seeded_rng.random_range(1..=256);
    let iterations: u32 = seeded_rng.random_range(1..=1000);

    let password = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 0, 128);
    let mut orion_dk = vec![0u8; outsize];
    let mut other_dk = vec![0u8; outsize];

    // SHA-256

    // orion
    pbkdf2::Pbkdf2::<pbkdf2::SHA256>::derive_key(
        password,
        &salt,
        iterations as usize,
        &mut orion_dk,
    )
    .unwrap();

    // ring
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iterations).unwrap(),
        &salt,
        password,
        &mut other_dk,
    );

    assert_eq!(orion_dk, other_dk);

    // SHA-384

    // orion
    pbkdf2::Pbkdf2::<pbkdf2::SHA384>::derive_key(
        password,
        &salt,
        iterations as usize,
        &mut orion_dk,
    )
    .unwrap();

    // ring
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA384,
        std::num::NonZeroU32::new(iterations).unwrap(),
        &salt,
        password,
        &mut other_dk,
    );

    assert_eq!(orion_dk, other_dk);

    // SHA-512

    // orion
    pbkdf2::Pbkdf2::<pbkdf2::SHA512>::derive_key(
        password,
        &salt,
        iterations as usize,
        &mut orion_dk,
    )
    .unwrap();

    // ring
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(iterations).unwrap(),
        &salt,
        password,
        &mut other_dk,
    );

    assert_eq!(orion_dk, other_dk);
}

fn fuzz_argon2(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let lanes = seeded_rng.random_range(1..=5);
    let outsize: u32 = seeded_rng.random_range(4..=256);
    let memory: u32 = seeded_rng.random_range(8..=1024);
    let passes: u32 = seeded_rng.random_range(1..=5);
    if orion_argon2::CostParams::new(passes, memory, lanes).is_err() {
        return;
    }

    let password = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 8, 32);
    let secret = rand_vec_in_range(seeded_rng, 0, 32);
    let ad = rand_vec_in_range(seeded_rng, 0, 32);

    // rust-argon2 - Argon2i
    let config = Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: memory,
        time_cost: passes,
        lanes,
        secret: &secret,
        ad: &ad,
        hash_length: outsize,
        thread_mode: argon2::ThreadMode::Sequential,
    };

    let other_dk = argon2::hash_raw(password, &salt[..], &config).unwrap();

    // orion
    let cost = orion_argon2::CostParams::new(passes, memory, lanes).unwrap();
    let mut orion_dk = vec![0u8; outsize as usize];
    orion_argon2::Argon2::<orion_argon2::I, orion_argon2::Sequential>::derive_key(
        password,
        &salt,
        &cost,
        Some(&secret),
        Some(&ad),
        &mut orion_dk,
    )
    .unwrap();

    assert_eq!(other_dk, orion_dk);

    // rust-argon2 - Argon2id
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: memory,
        time_cost: passes,
        lanes,
        secret: &secret,
        ad: &ad,
        hash_length: outsize,
        thread_mode: argon2::ThreadMode::Sequential,
    };

    let other_dk = argon2::hash_raw(password, &salt[..], &config).unwrap();

    // orion
    let cost = orion_argon2::CostParams::new(passes, memory, lanes).unwrap();
    let mut orion_dk = vec![0u8; outsize as usize];
    orion_argon2::Argon2::<orion_argon2::ID, orion_argon2::Sequential>::derive_key(
        password,
        &salt,
        &cost,
        Some(&secret),
        Some(&ad),
        &mut orion_dk,
    )
    .unwrap();

    assert_eq!(other_dk, orion_dk);
}

fn fuzz_scrypt(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let outsize: usize = seeded_rng.random_range(1..=32);
    let log2_n: u8 = seeded_rng.random_range(1..=16);
    let r: u32 = seeded_rng.random_range(1..=16);
    let p: u32 = seeded_rng.random_range(1..=16);
    if orion_scrypt::CostParams::new(log2_n as u32, r, p).is_err() {
        return;
    }

    let password = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 0, 64);
    let mut orion_dk = vec![0u8; outsize];
    let mut other_dk = vec![0u8; outsize];

    // orion
    let cost = orion_scrypt::CostParams::new(log2_n as u32, r, p).unwrap();
    orion_scrypt::Scrypt::derive_key(password, &salt, &cost, &mut orion_dk).unwrap();

    // RustCrypto
    let params = scrypt::Params::new(log2_n, r, p).unwrap();
    scrypt::scrypt(password, &salt, &params, &mut other_dk).unwrap();

    assert_eq!(orion_dk, other_dk);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::kdf::hkdf`
            fuzz_hkdf(data, &mut seeded_rng);
            // Test `orion::hazardous::kdf::pbkdf2`
            fuzz_pbkdf2(data, &mut seeded_rng);
            // Test `orion::hazardous::kdf::argon2`
            fuzz_argon2(data, &mut seeded_rng);
            // Test `orion::hazardous::kdf::scrypt`
            fuzz_scrypt(data, &mut seeded_rng);
        });
    }
}
