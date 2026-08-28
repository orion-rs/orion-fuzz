pub use rand::rngs::ChaCha8Rng;
pub use rand::{Rng, RngExt, SeedableRng, TryRng};

pub fn make_seeded_rng(fuzzer_input: &[u8]) -> ChaCha8Rng {
    // We need 8 bytes worth of data to convert into u64, so start with zero and replace
    // as much of those as there is data available.

    // We hash the fuzzer input to make sure each time it it modifed,
    // even past the 8 bytes, it still affects the entirety of thederived key.
    let hashedinput =
        orion::hazardous::hash::sha3::sha3_224::Sha3_224::digest(fuzzer_input).unwrap();
    let mut seed_slice = [0u8; 8];
    seed_slice.copy_from_slice(&hashedinput.as_ref()[..8]);

    let seed: u64 = u64::from_le_bytes(seed_slice);
    ChaCha8Rng::seed_from_u64(seed)
}

/// Generate a vector of random length within the lower and upper bound (both inclusive) and fill it with random data.
pub fn rand_vec_in_range(seeded_rng: &mut ChaCha8Rng, lb: usize, ub: usize) -> Vec<u8> {
    let rand_len: usize = seeded_rng.random_range(lb..=ub);
    let mut bytes = vec![0u8; rand_len];
    seeded_rng.fill_bytes(&mut bytes);

    bytes
}

/// Based on fuzzer_input, mutate a value with a XOR mask.
pub fn mutate_value(fuzzer_input: &[u8], value: &mut [u8]) {
    let offset: usize = if fuzzer_input.is_empty() {
        0
    } else {
        fuzzer_input[0] as usize
    };

    let mask: u8 = if fuzzer_input.len() < 2 {
        1
    } else {
        fuzzer_input[1]
    };

    value[offset % value.len()] ^= mask;
}
