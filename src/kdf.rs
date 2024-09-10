#[macro_use]
extern crate honggfuzz;
extern crate argon2;
extern crate orion;
extern crate ring;
pub mod utils;

use argon2::{Config, Variant, Version};
use orion::hazardous::{
    hash::sha2::{sha256::SHA256_OUTSIZE, sha384::SHA384_OUTSIZE, sha512::SHA512_OUTSIZE},
    kdf::{argon2i as orion_argon2i, hkdf, pbkdf2},
};
use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, Rng};

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

fn fuzz_hkdf(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let outsize: usize = seeded_rng.gen_range(1..=16320);

    let ikm = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 0, 128);
    let info = rand_vec_in_range(seeded_rng, 0, 128);
    let mut orion_okm = vec![0u8; outsize];

    // SHA-256

    // orion
    if orion_okm.len() > 255 * SHA256_OUTSIZE {
        assert!(hkdf::sha256::derive_key(&salt, ikm, Some(&info), &mut orion_okm).is_err());
        return;
    }
    hkdf::sha256::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

    // ring
    let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt);
    let RingHkdf(other_okm) = other_salt
        .extract(ikm)
        .expand(&[&info], RingHkdf(orion_okm.len()))
        .unwrap()
        .into();

    assert_eq!(orion_okm, other_okm);

    // SHA-384

    // orion
    if orion_okm.len() > 255 * SHA384_OUTSIZE {
        assert!(hkdf::sha384::derive_key(&salt, ikm, Some(&info), &mut orion_okm).is_err());
        return;
    }
    hkdf::sha384::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

    // ring
    let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA384, &salt);
    let RingHkdf(other_okm) = other_salt
        .extract(ikm)
        .expand(&[&info], RingHkdf(orion_okm.len()))
        .unwrap()
        .into();

    assert_eq!(orion_okm, other_okm);

    // SHA-512

    // orion
    if orion_okm.len() > 255 * SHA512_OUTSIZE {
        assert!(hkdf::sha512::derive_key(&salt, ikm, Some(&info), &mut orion_okm).is_err());
        return;
    }
    hkdf::sha512::derive_key(&salt, ikm, Some(&info), &mut orion_okm).unwrap();

    // ring
    let other_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &salt);
    let RingHkdf(other_okm) = other_salt
        .extract(ikm)
        .expand(&[&info], RingHkdf(orion_okm.len()))
        .unwrap()
        .into();

    assert_eq!(orion_okm, other_okm);
}

fn fuzz_pbkdf2(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let outsize: usize = seeded_rng.gen_range(1..=256);
    let iterations: u32 = seeded_rng.gen_range(1..=1000);

    let password = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 0, 128);
    let mut orion_dk = vec![0u8; outsize];
    let mut other_dk = vec![0u8; outsize];

    // SHA-256

    // orion
    let orion_password = pbkdf2::sha256::Password::from_slice(password).unwrap();
    pbkdf2::sha256::derive_key(&orion_password, &salt, iterations as usize, &mut orion_dk).unwrap();

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
    let orion_password = pbkdf2::sha384::Password::from_slice(password).unwrap();
    pbkdf2::sha384::derive_key(&orion_password, &salt, iterations as usize, &mut orion_dk).unwrap();

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
    let orion_password = pbkdf2::sha512::Password::from_slice(password).unwrap();
    pbkdf2::sha512::derive_key(&orion_password, &salt, iterations as usize, &mut orion_dk).unwrap();

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

fn fuzz_argon2(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let lanes = 1;
    let outsize: u32 = seeded_rng.gen_range(4..=256);
    let memory: u32 = seeded_rng.gen_range(8..=1024);
    let passes: u32 = seeded_rng.gen_range(1..=10);

    let password = fuzzer_input;
    let salt = rand_vec_in_range(seeded_rng, 8, 32);
    let secret = rand_vec_in_range(seeded_rng, 0, 32);
    let ad = rand_vec_in_range(seeded_rng, 0, 32);

    // rust-argon2
    let config = Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: memory,
        time_cost: passes,
        lanes,
        secret: &secret,
        ad: &ad,
        hash_length: outsize,
    };

    let other_dk = argon2::hash_raw(password, &salt[..], &config).unwrap();

    // orion
    let mut orion_dk = vec![0u8; outsize as usize];
    orion_argon2i::derive_key(
        password,
        &salt,
        passes,
        memory,
        Some(&secret),
        Some(&ad),
        &mut orion_dk,
    )
    .unwrap();

    assert_eq!(other_dk, orion_dk);
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
        });
    }
}
