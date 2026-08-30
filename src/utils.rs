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

/// Based on fuzzer_input, mutate value(s) with a XOR mask,
/// with a fuzzer_input-derived stride (neighbouring bytes).
pub fn mutate_value(fuzzer_input: &[u8], value: &mut [u8]) -> usize {
    const MAX_FLIPS: usize = 8;

    if value.is_empty() {
        return 0;
    }

    let mut hdr = [0u8; 7];
    let n = core::cmp::min(fuzzer_input.len(), hdr.len());
    hdr[..n].copy_from_slice(&fuzzer_input[..n]);

    let offset = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let mask = if hdr[4] == 0 { 1 } else { hdr[4] };
    let flips = 1 + core::cmp::min(hdr[5].trailing_ones() as usize, MAX_FLIPS - 1);
    let stride = 1 + hdr[6] as usize;

    let mut hit = [usize::MAX; MAX_FLIPS];
    let mut changed = 0usize;

    for i in 0..flips {
        let idx = offset.wrapping_add(i * stride) % value.len();
        if hit[..changed].contains(&idx) {
            // Avoid flipping same byte twice reverting back to original.
            continue;
        }

        value[idx] ^= mask.rotate_left(i as u32);
        hit[changed] = idx;
        changed += 1;
    }

    debug_assert!(changed >= 1);

    changed
}
