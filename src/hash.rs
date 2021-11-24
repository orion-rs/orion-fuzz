#[macro_use]
extern crate honggfuzz;
extern crate blake2_rfc;
extern crate orion;
extern crate ring;
pub mod utils;

use orion::hazardous::hash::sha2;
use orion::{errors::UnknownCryptoError, hazardous::hash::blake2::blake2b};
use std::marker::PhantomData;
use utils::{make_seeded_rng, ChaChaRng, Rng};

const BLAKE2B_BLOCKSIZE: usize = 128;

fn fuzz_blake2b(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let outsize: usize = seeded_rng.gen_range(1..=64);

    let mut orion_ctx: blake2b::Blake2b;
    let mut other_ctx: blake2_rfc::blake2b::Blake2b;

    orion_ctx = blake2b::Blake2b::new(outsize).unwrap();
    other_ctx = blake2_rfc::blake2b::Blake2b::new(outsize);

    other_ctx.update(fuzzer_input);
    orion_ctx.update(fuzzer_input).unwrap();

    let mut collected_data: Vec<u8> = Vec::new();
    collected_data.extend_from_slice(fuzzer_input);

    if fuzzer_input.len() > BLAKE2B_BLOCKSIZE {
        other_ctx.update(b"");
        orion_ctx.update(b"").unwrap();
        collected_data.extend_from_slice(b"");
    }
    if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 2 {
        other_ctx.update(b"Extra");
        orion_ctx.update(b"Extra").unwrap();
        collected_data.extend_from_slice(b"Extra");
    }
    if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 3 {
        other_ctx.update(&[0u8; 256]);
        orion_ctx.update(&[0u8; 256]).unwrap();
        collected_data.extend_from_slice(&[0u8; 256]);
    }

    let other_hash = other_ctx.finalize();
    let orion_hash = orion_ctx.finalize().unwrap();

    assert_eq!(orion_hash, other_hash.as_bytes());

    if outsize == 32 {
        let orion_one_shot = blake2b::Hasher::Blake2b256.digest(&collected_data).unwrap();
        assert_eq!(orion_one_shot, other_hash.as_bytes());
    } else if outsize == 48 {
        let orion_one_shot = blake2b::Hasher::Blake2b384.digest(&collected_data).unwrap();
        assert_eq!(orion_one_shot, other_hash.as_bytes());
    } else if outsize == 64 {
        let orion_one_shot = blake2b::Hasher::Blake2b512.digest(&collected_data).unwrap();
        assert_eq!(orion_one_shot, other_hash.as_bytes());
    } else {
    }
}

// A wrapper trait to reduce duplicate functional test-code when fuzzing SHA256/384/512.
trait Sha2FuzzType<T: PartialEq> {
    fn reset(&mut self);

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    fn finalize(&mut self) -> Result<T, UnknownCryptoError>;

    fn digest(&self, data: &[u8]) -> Result<T, UnknownCryptoError>;

    fn get_blocksize() -> usize;
}

impl Sha2FuzzType<sha2::sha256::Digest> for sha2::sha256::Sha256 {
    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha256::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(&self, data: &[u8]) -> Result<sha2::sha256::Digest, UnknownCryptoError> {
        sha2::sha256::Sha256::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha256::SHA256_BLOCKSIZE
    }
}

impl Sha2FuzzType<sha2::sha384::Digest> for sha2::sha384::Sha384 {
    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha384::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(&self, data: &[u8]) -> Result<sha2::sha384::Digest, UnknownCryptoError> {
        sha2::sha384::Sha384::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha384::SHA384_BLOCKSIZE
    }
}

impl Sha2FuzzType<sha2::sha512::Digest> for sha2::sha512::Sha512 {
    fn reset(&mut self) {
        self.reset();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha512::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(&self, data: &[u8]) -> Result<sha2::sha512::Digest, UnknownCryptoError> {
        sha2::sha512::Sha512::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha512::SHA512_BLOCKSIZE
    }
}

/// A SHA2 fuzzer.
struct Sha2Fuzzer<R, T> {
    _return_type: PhantomData<R>,
    // The initial context to base further calls upon.
    own_context: T,

    ring_digest: &'static ring::digest::Algorithm,
}

impl<R, T> Sha2Fuzzer<R, T>
where
    R: PartialEq + AsRef<[u8]>,
    T: Sha2FuzzType<R>,
{
    pub fn new(sha2_initial_state: T, ring_digest: &'static ring::digest::Algorithm) -> Self {
        Self {
            _return_type: PhantomData,
            own_context: sha2_initial_state,
            ring_digest,
        }
    }

    /// Fuzz the Orion implementation and check results with ring.
    pub fn fuzz(&mut self, fuzzer_input: &[u8]) {
        // Clear the state
        self.own_context.reset();

        let mut collected_data: Vec<u8> = Vec::new();

        collected_data.extend_from_slice(fuzzer_input);
        self.own_context.update(fuzzer_input).unwrap();

        if fuzzer_input.len() > T::get_blocksize() {
            collected_data.extend_from_slice(b"");
            self.own_context.update(b"").unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 2 {
            collected_data.extend_from_slice(b"Extra");
            self.own_context.update(b"Extra").unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 3 {
            collected_data.extend_from_slice(&[0u8; 256]);
            self.own_context.update(&[0u8; 256]).unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 4 {
            collected_data.extend_from_slice(&vec![0u8; T::get_blocksize() - 1]);
            self.own_context
                .update(&vec![0u8; T::get_blocksize() - 1])
                .unwrap();
        }

        let digest_other = ring::digest::digest(self.ring_digest, &collected_data);
        let orion_one_shot = self.own_context.digest(&collected_data).unwrap();

        assert_eq!(orion_one_shot.as_ref(), digest_other.as_ref());
        assert_eq!(
            self.own_context.finalize().unwrap().as_ref(),
            digest_other.as_ref()
        );
    }
}

fn main() {
    // Setup SHA2
    let mut sha256_fuzzer = Sha2Fuzzer::new(sha2::sha256::Sha256::new(), &ring::digest::SHA256);
    let mut sha384_fuzzer = Sha2Fuzzer::new(sha2::sha384::Sha384::new(), &ring::digest::SHA384);
    let mut sha512_fuzzer = Sha2Fuzzer::new(sha2::sha512::Sha512::new(), &ring::digest::SHA512);

    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::hash::blake2::blake2b`
            fuzz_blake2b(data, &mut seeded_rng);
            // Test `orion::hazardous::hash::sha2`
            sha256_fuzzer.fuzz(data);
            sha384_fuzzer.fuzz(data);
            sha512_fuzzer.fuzz(data);
        });
    }
}
