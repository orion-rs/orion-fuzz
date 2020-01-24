extern crate rand_chacha;
extern crate rand_core;

pub use self::rand_chacha::ChaChaRng;
pub use self::rand_core::{RngCore, SeedableRng};

pub fn make_seeded_rng(fuzzer_input: &[u8]) -> ChaChaRng {
    // We need 8 bytes worth of data to convet into u64, so start with zero and replace
    // as much of those as there is data available.
    let mut seed_slice = [0u8; 8];
    if fuzzer_input.len() >= 8 {
        seed_slice.copy_from_slice(&fuzzer_input[..8]);
    } else {
        seed_slice[..fuzzer_input.len()].copy_from_slice(&fuzzer_input);
    }

    let seed: u64 = u64::from_le_bytes(seed_slice);

    ChaChaRng::seed_from_u64(seed)
}

/// Generate random u32 within the lower and upper bound (inclusive).
pub fn rand_in_range(rng: &mut ChaChaRng, lb: u32, ub: u32) -> u32 {
    let mut res = rng.next_u32();

    while res < lb || res > ub {
        res = rng.next_u32();
    }

    res
}
