#[macro_use]
extern crate honggfuzz;
extern crate blake2_rfc;
extern crate orion;
extern crate ring;
pub mod utils;

use sha3 as other_sha3;

use orion::hazardous::hash::sha2::sha256::{Digest as Sha256Digest, Sha256, SHA256_BLOCKSIZE};
use orion::hazardous::hash::sha2::sha384::{Digest as Sha384Digest, Sha384, SHA384_BLOCKSIZE};
use orion::hazardous::hash::sha2::sha512::{Digest as Sha512Digest, Sha512, SHA512_BLOCKSIZE};

use orion::hazardous::hash::sha3::sha224::{
    Digest as Sha3_224Digest, Sha224 as Sha3_224, SHA3_224_RATE,
};
use orion::hazardous::hash::sha3::sha256::{
    Digest as Sha3_256Digest, Sha256 as Sha3_256, SHA3_256_RATE,
};
use orion::hazardous::hash::sha3::sha384::{
    Digest as Sha3_384Digest, Sha384 as Sha3_384, SHA3_384_RATE,
};
use orion::hazardous::hash::sha3::sha512::{
    Digest as Sha3_512Digest, Sha512 as Sha3_512, SHA3_512_RATE,
};

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
trait ShaFuzzType<T: PartialEq> {
    fn reset(&mut self);

    fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    fn finalize(&mut self) -> Result<T, UnknownCryptoError>;

    fn digest(&self, data: &[u8]) -> Result<T, UnknownCryptoError>;

    fn get_blocksize() -> usize;
}

/// A trait for the other implementation that Orion should be fuzzed against.
/// This is used for SHA3 as it's not compatible with the apporahc used for SHA2.
trait ShaComparableType<T>
where
    T: AsRef<[u8]>,
{
    fn digest(data: &[u8]) -> T;
}

macro_rules! impl_sha_fuzztype_trait (($sha_variant:ident, $sha_digest:ident, $sha_bs:expr) => (
    impl ShaFuzzType<$sha_digest> for $sha_variant {
        fn reset(&mut self) {
            self.reset();
        }

        fn update(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self.update(data)
        }

        fn finalize(&mut self) -> Result<$sha_digest, UnknownCryptoError> {
            self.finalize()
        }

        fn digest(&self, data: &[u8]) -> Result<$sha_digest, UnknownCryptoError> {
            $sha_variant::digest(data)
        }

        fn get_blocksize() -> usize {
            $sha_bs
        }
    }
));

impl_sha_fuzztype_trait!(Sha256, Sha256Digest, SHA256_BLOCKSIZE);
impl_sha_fuzztype_trait!(Sha384, Sha384Digest, SHA384_BLOCKSIZE);
impl_sha_fuzztype_trait!(Sha512, Sha512Digest, SHA512_BLOCKSIZE);

impl_sha_fuzztype_trait!(Sha3_224, Sha3_224Digest, SHA3_224_RATE);
impl_sha_fuzztype_trait!(Sha3_256, Sha3_256Digest, SHA3_256_RATE);
impl_sha_fuzztype_trait!(Sha3_384, Sha3_384Digest, SHA3_384_RATE);
impl_sha_fuzztype_trait!(Sha3_512, Sha3_512Digest, SHA3_512_RATE);

// We use Orion's return Digest here otherwise we get too many generic type
// parameters. So we construct Orion's Digest from `sha3` crate and compare later.

impl ShaComparableType<Sha3_224Digest> for other_sha3::Sha3_224 {
    fn digest(data: &[u8]) -> Sha3_224Digest {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_224::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Sha3_224Digest::from_slice(hash.as_ref()).unwrap()
    }
}

impl ShaComparableType<Sha3_256Digest> for other_sha3::Sha3_256 {
    fn digest(data: &[u8]) -> Sha3_256Digest {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Sha3_256Digest::from_slice(hash.as_ref()).unwrap()
    }
}

impl ShaComparableType<Sha3_384Digest> for other_sha3::Sha3_384 {
    fn digest(data: &[u8]) -> Sha3_384Digest {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_384::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Sha3_384Digest::from_slice(hash.as_ref()).unwrap()
    }
}

impl ShaComparableType<Sha3_512Digest> for other_sha3::Sha3_512 {
    fn digest(data: &[u8]) -> Sha3_512Digest {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Sha3_512Digest::from_slice(hash.as_ref()).unwrap()
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
    T: ShaFuzzType<R>,
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

/// A SHA3 fuzzer.
struct Sha3Fuzzer<R, T, O> {
    _return_type: PhantomData<R>,
    // The initial context to base further calls upon.
    own_context: T,
    _other_impl: PhantomData<O>,
}

impl<R, T, O> Sha3Fuzzer<R, T, O>
where
    R: PartialEq + AsRef<[u8]>,
    T: ShaFuzzType<R>,
    O: ShaComparableType<R>,
{
    pub fn new(sha2_initial_state: T) -> Self {
        Self {
            _return_type: PhantomData,
            own_context: sha2_initial_state,
            _other_impl: PhantomData,
        }
    }

    /// Fuzz the Orion implementation and check results with RustCrypto's `sha3` crate.
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

        let digest_other = O::digest(&collected_data);
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
    let mut sha256_fuzzer = Sha2Fuzzer::new(Sha256::new(), &ring::digest::SHA256);
    let mut sha384_fuzzer = Sha2Fuzzer::new(Sha384::new(), &ring::digest::SHA384);
    let mut sha512_fuzzer = Sha2Fuzzer::new(Sha512::new(), &ring::digest::SHA512);

    // Setup SHA3
    let mut sha3_224_fuzzer: Sha3Fuzzer<Sha3_224Digest, Sha3_224, other_sha3::Sha3_224> =
        Sha3Fuzzer::new(Sha3_224::new());
    let mut sha3_256_fuzzer: Sha3Fuzzer<Sha3_256Digest, Sha3_256, other_sha3::Sha3_256> =
        Sha3Fuzzer::new(Sha3_256::new());
    let mut sha3_384_fuzzer: Sha3Fuzzer<Sha3_384Digest, Sha3_384, other_sha3::Sha3_384> =
        Sha3Fuzzer::new(Sha3_384::new());
    let mut sha3_512_fuzzer: Sha3Fuzzer<Sha3_512Digest, Sha3_512, other_sha3::Sha3_512> =
        Sha3Fuzzer::new(Sha3_512::new());

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
            // Test `orion::hazardous::hash::sha3`
            sha3_224_fuzzer.fuzz(data);
            sha3_256_fuzzer.fuzz(data);
            sha3_384_fuzzer.fuzz(data);
            sha3_512_fuzzer.fuzz(data);
        });
    }
}
