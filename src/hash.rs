#[macro_use]
extern crate honggfuzz;
extern crate blake2_rfc;
extern crate orion;
extern crate ring;
pub mod utils;

use orion::hazardous::hash::sha2;
use orion::hazardous::hash::sha2::sha512::{self, SHA512_BLOCKSIZE};
use orion::{errors::UnknownCryptoError, hazardous::hash::blake2b};
use utils::{make_seeded_rng, rand_vec_in_range, ChaChaRng, Rng};

const BLAKE2B_BLOCKSIZE: usize = 128;

fn fuzz_blake2b(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let keyed: bool = seeded_rng.gen();
    let outsize: usize = seeded_rng.gen_range(1, 64 + 1);

    let mut orion_ctx: blake2b::Blake2b;
    let mut other_ctx: blake2_rfc::blake2b::Blake2b;

    if keyed {
        let key = rand_vec_in_range(seeded_rng, 1, 64);
        let orion_key = blake2b::SecretKey::from_slice(&key).unwrap();
        orion_ctx = blake2b::Blake2b::new(Some(&orion_key), outsize).unwrap();
        other_ctx = blake2_rfc::blake2b::Blake2b::with_key(outsize, &key);
    } else {
        orion_ctx = blake2b::Blake2b::new(None, outsize).unwrap();
        other_ctx = blake2_rfc::blake2b::Blake2b::new(outsize);
    }

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

    assert!(orion_hash == other_hash.as_bytes());

    if !keyed {
        if outsize == 32 {
            let orion_one_shot = blake2b::Hasher::Blake2b256.digest(&collected_data).unwrap();
            assert!(orion_one_shot == other_hash.as_bytes());
        } else if outsize == 48 {
            let orion_one_shot = blake2b::Hasher::Blake2b384.digest(&collected_data).unwrap();
            assert!(orion_one_shot == other_hash.as_bytes());
        } else if outsize == 64 {
            let orion_one_shot = blake2b::Hasher::Blake2b512.digest(&collected_data).unwrap();
            assert!(orion_one_shot == other_hash.as_bytes());
        } else {
        }
    }
}

// A wrapper trait to reduce duplicate functional test-code when fuzzing SHA256/384/512.
trait Sha2FuzzType {
    fn new() -> Self;

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    fn finalize(&mut self) -> Result<T: PartialEq, UnknownCryptoError>;

    fn digest(data: &[u8]) -> Result<T: PartialEq, UnknownCryptoError>;

    fn get_blocksize() -> usize;
}

impl Sha2FuzzType for sha2::sha256::Sha256 {
    fn new() -> Self {
        return sha2::sha256::Sha256::new();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha256::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(data: &[u8]) -> Result<sha2::sha256::Digest, UnknownCryptoError> {
        sha2::sha256::Sha256::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha256::SHA256_BLOCKSIZE
    }
}

impl Sha2FuzzType for sha2::sha384::Sha384 {
    fn new() -> Self {
        return sha2::sha384::Sha384::new();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha384::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(data: &[u8]) -> Result<sha2::sha384::Digest, UnknownCryptoError> {
        sha2::sha384::Sha384::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha384::SHA384_BLOCKSIZE
    }
}

impl Sha2FuzzType for sha2::sha512::Sha512 {
    fn new() -> Self {
        return sha2::sha512::Sha512::new();
    }

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
        self.update(data)
    }

    fn finalize(&mut self) -> Result<sha2::sha512::Digest, UnknownCryptoError> {
        self.finalize()
    }

    fn digest(data: &[u8]) -> Result<sha2::sha512::Digest, UnknownCryptoError> {
        sha2::sha512::Sha512::digest(data)
    }

    fn get_blocksize() -> usize {
        sha2::sha512::SHA512_BLOCKSIZE
    }
}

fn fuzz_sha2(fuzzer_input: &[u8], orion_impl: Sha2FuzzType, ring_impl: ring::digest::Algorithm) {
    let mut orion_ctx = orion_impl::new();
    let mut collected_data: Vec<u8> = Vec::new();

    collected_data.extend_from_slice(fuzzer_input);
    orion_ctx.update(fuzzer_input).unwrap();

    if fuzzer_input.len() > orion_impl::get_blocksize() {
        collected_data.extend_from_slice(b"");
        orion_ctx.update(b"").unwrap();
    }
    if fuzzer_input.len() > orion_impl::get_blocksize() * 2 {
        collected_data.extend_from_slice(b"Extra");
        orion_ctx.update(b"Extra").unwrap();
    }
    if fuzzer_input.len() > orion_impl::get_blocksize() * 3 {
        collected_data.extend_from_slice(&[0u8; 256]);
        orion_ctx.update(&[0u8; 256]).unwrap();
    }
    if fuzzer_input.len() > orion_impl::get_blocksize() * 4 {
        collected_data.extend_from_slice(vec![0u8; orion_impl::get_blocksize() - 1]);
        orion_ctx.update(&vec![0u8; orion_impl::get_blocksize() - 1]).unwrap();
    }

    let digest_other = ring::digest::digest(&ring_impl, &collected_data);
    let orion_one_shot = orion_impl::digest(&collected_data).unwrap();

    assert!(orion_one_shot == digest_other.as_ref());
    assert!(orion_ctx.finalize().unwrap() == digest_other.as_ref());
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::hash::blake2b`
            fuzz_blake2b(data, &mut seeded_rng);
            // Test `orion::hazardous::hash::sha2`
            fuzz_sha2(data, sha2::sha256::Sha256, ring::digest::SHA256);
            fuzz_sha2(data, sha2::sha384::Sha382, ring::digest::SHA384);
            fuzz_sha2(data, sha2::sha512::Sha512, ring::digest::SHA512);
        });
    }
}
