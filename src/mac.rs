#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate ring;
extern crate sodiumoxide;
pub mod utils;

use std::marker::PhantomData;

use orion::errors::UnknownCryptoError;
use orion::hazardous::mac::hmac;
use orion::hazardous::mac::poly1305;
use sodiumoxide::crypto::onetimeauth;
use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, RngCore};

const POLY1305_BLOCKSIZE: usize = 16;

/// A trait to define behavior for a HMAC secret key. It is important to have this,
/// so that we can ensure we fuzz different key-lengths and the resulting padding of it.
trait HmacKey {
    /// Construct a key from a byte slice, applying padding if needed.
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError>
    where
        Self: Sized;
}

impl HmacKey for hmac::sha256::SecretKey {
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Self::from_slice(slice)
    }
}

impl HmacKey for hmac::sha384::SecretKey {
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Self::from_slice(slice)
    }
}

impl HmacKey for hmac::sha512::SecretKey {
    fn from_slice(slice: &[u8]) -> Result<Self, UnknownCryptoError> {
        Self::from_slice(slice)
    }
}

trait HmacTagAsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl HmacTagAsBytes for hmac::sha256::Tag {
    fn as_bytes(&self) -> &[u8] {
        self.unprotected_as_bytes()
    }
}

impl HmacTagAsBytes for hmac::sha384::Tag {
    fn as_bytes(&self) -> &[u8] {
        self.unprotected_as_bytes()
    }
}

impl HmacTagAsBytes for hmac::sha512::Tag {
    fn as_bytes(&self) -> &[u8] {
        self.unprotected_as_bytes()
    }
}

// A wrapper trait to reduce duplicate functional test-code when fuzzing SHA256/384/512.
trait HmacFuzzType<T: PartialEq + HmacTagAsBytes, S: HmacKey> {
    fn new(secret_key: &S) -> Self;

    fn reset(&mut self);

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    fn finalize(&mut self) -> Result<T, UnknownCryptoError>;

    fn hmac(secret_key: &S, data: &[u8]) -> Result<T, UnknownCryptoError>;

    fn get_blocksize() -> usize;
}

impl HmacFuzzType<hmac::sha256::Tag, hmac::sha256::SecretKey> for hmac::sha256::HmacSha256 {
    fn new(secret_key: &hmac::sha256::SecretKey) -> Self {
        Self::new(secret_key)
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<hmac::sha256::Tag, UnknownCryptoError> {
        self.finalize()
    }

    fn hmac(
        secret_key: &hmac::sha256::SecretKey,
        data: &[u8],
    ) -> Result<hmac::sha256::Tag, UnknownCryptoError> {
        hmac::sha256::HmacSha256::hmac(secret_key, data)
    }

    fn get_blocksize() -> usize {
        orion::hazardous::hash::sha2::sha256::SHA256_BLOCKSIZE
    }
}

impl HmacFuzzType<hmac::sha384::Tag, hmac::sha384::SecretKey> for hmac::sha384::HmacSha384 {
    fn new(secret_key: &hmac::sha384::SecretKey) -> Self {
        Self::new(secret_key)
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<hmac::sha384::Tag, UnknownCryptoError> {
        self.finalize()
    }

    fn hmac(
        secret_key: &hmac::sha384::SecretKey,
        data: &[u8],
    ) -> Result<hmac::sha384::Tag, UnknownCryptoError> {
        hmac::sha384::HmacSha384::hmac(secret_key, data)
    }

    fn get_blocksize() -> usize {
        orion::hazardous::hash::sha2::sha384::SHA384_BLOCKSIZE
    }
}

impl HmacFuzzType<hmac::sha512::Tag, hmac::sha512::SecretKey> for hmac::sha512::HmacSha512 {
    fn new(secret_key: &hmac::sha512::SecretKey) -> Self {
        Self::new(secret_key)
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<hmac::sha512::Tag, UnknownCryptoError> {
        self.finalize()
    }

    fn hmac(
        secret_key: &hmac::sha512::SecretKey,
        data: &[u8],
    ) -> Result<hmac::sha512::Tag, UnknownCryptoError> {
        hmac::sha512::HmacSha512::hmac(secret_key, data)
    }

    fn get_blocksize() -> usize {
        orion::hazardous::hash::sha2::sha512::SHA512_BLOCKSIZE
    }
}

/// A HMAC fuzzer.
struct HmacFuzzer<R, S, T> {
    _return_type: PhantomData<R>,
    _key: PhantomData<S>,
    _fuzzer: PhantomData<T>,
    ring_digest: &'static ring::hmac::Algorithm,
}

impl<R, S, T> HmacFuzzer<R, S, T>
where
    R: PartialEq + HmacTagAsBytes + core::fmt::Debug,
    S: HmacKey,
    T: HmacFuzzType<R, S>,
{
    pub fn new(ring_digest: &'static ring::hmac::Algorithm) -> Self {
        Self {
            _return_type: PhantomData,
            _key: PhantomData,
            _fuzzer: PhantomData,
            ring_digest,
        }
    }

    /// Fuzz the Orion implementation and check results with ring.
    pub fn fuzz(&self, seeded_rng: &mut ChaChaRng, fuzzer_input: &[u8]) {
        let key = rand_vec_in_range(seeded_rng, 0, T::get_blocksize() * 2);

        // orion
        let orion_key = S::from_slice(&key).unwrap();
        let mut orion_ctx = T::new(&orion_key);
        orion_ctx.update(fuzzer_input).unwrap();

        // ring
        let ring_key = ring::hmac::Key::new(*self.ring_digest, &key);
        let mut other_ctx = ring::hmac::Context::with_key(&ring_key);
        other_ctx.update(fuzzer_input);

        let mut collected_data: Vec<u8> = Vec::new();
        collected_data.extend_from_slice(fuzzer_input);

        if fuzzer_input.len() > T::get_blocksize() {
            orion_ctx.update(b"").unwrap();
            other_ctx.update(b"");
            collected_data.extend_from_slice(b"");
        }
        if fuzzer_input.len() > T::get_blocksize() * 2 {
            orion_ctx.update(b"Extra").unwrap();
            other_ctx.update(b"Extra");
            collected_data.extend_from_slice(b"Extra");
        }
        if fuzzer_input.len() > T::get_blocksize() * 3 {
            orion_ctx.update(&[0u8; 256]).unwrap();
            other_ctx.update(&[0u8; 256]);
            collected_data.extend_from_slice(&[0u8; 256]);
        }
        if fuzzer_input.len() > T::get_blocksize() * 4 {
            orion_ctx
                .update(&vec![0u8; T::get_blocksize() - 1])
                .unwrap();
            other_ctx.update(&vec![0u8; T::get_blocksize() - 1]);
            collected_data.extend_from_slice(&vec![0u8; T::get_blocksize() - 1]);
        }

        let other_tag = other_ctx.sign();
        let orion_tag = orion_ctx.finalize().unwrap();

        let orion_one_shot = T::hmac(&orion_key, &collected_data).unwrap();
        let other_one_shot = ring::hmac::sign(&ring_key, &collected_data);

        assert_eq!(other_tag.as_ref(), orion_tag.as_bytes());
        assert_eq!(orion_one_shot, orion_tag);
        assert_eq!(other_one_shot.as_ref(), orion_tag.as_bytes());
    }
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
    // Setup SHA2
    let hmac_sha256_fuzzer: HmacFuzzer<
        hmac::sha256::Tag,
        hmac::sha256::SecretKey,
        hmac::sha256::HmacSha256,
    > = HmacFuzzer::new(&ring::hmac::HMAC_SHA256);
    let hmac_sha384_fuzzer: HmacFuzzer<
        hmac::sha384::Tag,
        hmac::sha384::SecretKey,
        hmac::sha384::HmacSha384,
    > = HmacFuzzer::new(&ring::hmac::HMAC_SHA384);
    let hmac_sha512_fuzzer: HmacFuzzer<
        hmac::sha512::Tag,
        hmac::sha512::SecretKey,
        hmac::sha512::HmacSha512,
    > = HmacFuzzer::new(&ring::hmac::HMAC_SHA512);

    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::mac::hmac`
            hmac_sha256_fuzzer.fuzz(&mut seeded_rng, data);
            hmac_sha384_fuzzer.fuzz(&mut seeded_rng, data);
            hmac_sha512_fuzzer.fuzz(&mut seeded_rng, data);
            // Test `orion::hazardous::mac::poly1305`
            fuzz_poly1305(data, &mut seeded_rng);
        });
    }
}
