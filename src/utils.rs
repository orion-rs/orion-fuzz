pub use rand::rngs::ChaCha8Rng;
pub use rand::{Rng, RngExt, SeedableRng, TryRng};

pub fn make_seeded_rng(fuzzer_input: &[u8]) -> ChaCha8Rng {
    // We hash the fuzzer input to make sure each time it is modifed,
    // if if it past the 32 bytes we need.
    let hashedinput =
        orion::hazardous::hash::sha3::sha3_256::Sha3_256::digest(fuzzer_input).unwrap();
    let mut seed_slice = [0u8; 32];
    seed_slice.copy_from_slice(hashedinput.as_ref());

    ChaCha8Rng::from_seed(seed_slice)
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
    if value.is_empty() {
        return;
    }

    let offset: usize = if fuzzer_input.is_empty() {
        0
    } else {
        fuzzer_input[0] as usize
    };

    let mask: u8 = match fuzzer_input.get(1) {
        Some(0) | None => 1,
        Some(&m) => m,
    };

    value[offset % value.len()] ^= mask;
}
