#[macro_use]
extern crate honggfuzz;

extern crate orion;
use sha3 as other_sha3;

pub mod utils;
use orion::errors::UnknownCryptoError;
use orion::hazardous::hash::sha3::shake128::{Shake128, SHAKE_128_RATE};
use orion::hazardous::hash::sha3::shake256::{Shake256, SHAKE_256_RATE};
use std::marker::PhantomData;
use utils::{make_seeded_rng, ChaChaRng, Rng};

// A wrapper trait to reduce duplicate functional test-code when fuzzing SHAKE128/SHAK256.
trait XofFuzzType {
    fn reset(&mut self);

    fn absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError>;

    fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError>;

    fn get_blocksize() -> usize;
}

/// A trait for the other implementation that Orion should be fuzzed against.
trait XofComparableType {
    fn digest(data: &[u8], dest: &mut [u8]);
}

macro_rules! impl_shake_fuzztype_trait (($shake_variant:ident, $shake_bs:expr) => (
    impl XofFuzzType for $shake_variant {
        fn reset(&mut self) {
            self.reset();
        }

        fn absorb(&mut self, data: &[u8]) -> Result<(), UnknownCryptoError> {
            self.absorb(data)
        }

        fn squeeze(&mut self, dest: &mut [u8]) -> Result<(), UnknownCryptoError> {
            self.squeeze(dest)
        }

        fn get_blocksize() -> usize {
            $shake_bs
        }
    }
));

impl_shake_fuzztype_trait!(Shake128, SHAKE_128_RATE);
impl_shake_fuzztype_trait!(Shake256, SHAKE_256_RATE);

impl XofComparableType for other_sha3::Shake128 {
    fn digest(data: &[u8], dest: &mut [u8]) {
        use other_sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = other_sha3::Shake128::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        reader.read(dest);
    }
}

impl XofComparableType for other_sha3::Shake256 {
    fn digest(data: &[u8], dest: &mut [u8]) {
        use other_sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = other_sha3::Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        reader.read(dest);
    }
}

/// A SHAKE fuzzer.
struct ShakeFuzzer<T, O> {
    // The initial context to base further calls upon.
    own_context: T,
    _other_impl: PhantomData<O>,
}

impl<T, O> ShakeFuzzer<T, O>
where
    T: XofFuzzType,
    O: XofComparableType,
{
    pub fn new(shake_initial_state: T) -> Self {
        Self {
            own_context: shake_initial_state,
            _other_impl: PhantomData,
        }
    }

    /// Fuzz the Orion implementation and check results with RustCrypto's `sha3` crate.
    pub fn fuzz(&mut self, fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
        // Clear the state
        self.own_context.reset();
        let mut collected_data: Vec<u8> = Vec::new();

        // Incremental absorbation:
        collected_data.extend_from_slice(fuzzer_input);
        self.own_context.absorb(fuzzer_input).unwrap();

        if fuzzer_input.len() > T::get_blocksize() {
            collected_data.extend_from_slice(b"");
            self.own_context.absorb(b"").unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 2 {
            collected_data.extend_from_slice(b"Extra");
            self.own_context.absorb(b"Extra").unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 3 {
            collected_data.extend_from_slice(&[0u8; 256]);
            self.own_context.absorb(&[0u8; 256]).unwrap();
        }
        if fuzzer_input.len() > T::get_blocksize() * 4 {
            collected_data.extend_from_slice(&vec![0u8; T::get_blocksize() - 1]);
            self.own_context
                .absorb(&vec![0u8; T::get_blocksize() - 1])
                .unwrap();
        }

        // Incremental squeezing:
        let dest_size: usize = seeded_rng.gen_range(1..=16320);
        let squeeze_size: usize = seeded_rng.gen_range(1..=dest_size);

        let mut squeeze_dest_own = vec![0u8; dest_size];
        let mut squeeze_dest_other = vec![0u8; dest_size];

        O::digest(&collected_data, &mut squeeze_dest_other);

        for out_chunk in squeeze_dest_own.chunks_mut(squeeze_size) {
            self.own_context.squeeze(out_chunk).unwrap();
        }

        assert_eq!(squeeze_dest_own, squeeze_dest_other);
    }
}

fn main() {
    let mut shake128_fuzzer: ShakeFuzzer<Shake128, other_sha3::Shake128> =
        ShakeFuzzer::new(Shake128::new());
    let mut shake256_fuzzer: ShakeFuzzer<Shake256, other_sha3::Shake256> =
        ShakeFuzzer::new(Shake256::new());

    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::hash::sha3::shake*`
            shake128_fuzzer.fuzz(data, &mut seeded_rng);
            shake256_fuzzer.fuzz(data, &mut seeded_rng);
        });
    }
}
