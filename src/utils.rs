extern crate rand;
extern crate rand_chacha;

pub use self::rand::{Rng, RngCore, SeedableRng};
pub use self::rand_chacha::ChaChaRng;

pub fn make_seeded_rng(fuzzer_input: &[u8]) -> ChaChaRng {
    // We need 8 bytes worth of data to convert into u64, so start with zero and replace
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

/// Generate a vector of random length within the lower and upper bound (both inclusive) and fill it with random data.
pub fn rand_vec_in_range(seeded_rng: &mut ChaChaRng, lb: usize, ub: usize) -> Vec<u8> {
    let rand_len: usize = seeded_rng.gen_range(lb..=ub);
    let mut bytes = vec![0u8; rand_len];
    seeded_rng.fill_bytes(&mut bytes);

    bytes
}
