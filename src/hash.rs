#[macro_use]
extern crate honggfuzz;
extern crate blake2_rfc;
extern crate orion;
extern crate ring;
pub mod utils;

use orion::hazardous::hash::blake2b;
use orion::hazardous::hash::sha2::sha512::{self, SHA512_BLOCKSIZE};
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

// TODO: Add SHA256/384

fn fuzz_sha512(fuzzer_input: &[u8]) {
    let mut orion_ctx = sha512::Sha512::new();
    let mut collected_data: Vec<u8> = Vec::new();

    collected_data.extend_from_slice(fuzzer_input);
    orion_ctx.update(fuzzer_input).unwrap();

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
        collected_data.extend_from_slice(b"");
        orion_ctx.update(b"").unwrap();
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
        collected_data.extend_from_slice(b"Extra");
        orion_ctx.update(b"Extra").unwrap();
    }
    if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
        collected_data.extend_from_slice(&[0u8; 256]);
        orion_ctx.update(&[0u8; 256]).unwrap();
    }

    let digest_other = ring::digest::digest(&ring::digest::SHA512, &collected_data);
    let orion_one_shot = sha512::Sha512::digest(&collected_data).unwrap();

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
            // Test `orion::hazardous::hash::sha512`
            fuzz_sha512(data);
        });
    }
}
