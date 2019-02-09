#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate blake2_rfc; // For blake2b
extern crate ring; // For sha512
pub mod utils;

use utils::{ChaChaRng, make_seeded_rng, RngCore};
use orion::hazardous::hash::blake2b;
use orion::hazardous::hash::sha512;
use orion::hazardous::constants::{SHA512_BLOCKSIZE, BLAKE2B_BLOCKSIZE};


fn fuzz_blake2b_non_keyed(fuzzer_input: &[u8], outsize: usize) {
    assert!(outsize < 65);
    assert!(outsize > 0);

	let mut context = blake2_rfc::blake2b::Blake2b::new(outsize);
	context.update(fuzzer_input);

	let mut state = blake2b::init(None, outsize).unwrap();
	state.update(fuzzer_input).unwrap();

	let mut other_data: Vec<u8> = Vec::new();
	other_data.extend_from_slice(fuzzer_input);

	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE {
		context.update(b"");
		state.update(b"").unwrap();
		other_data.extend_from_slice(b"");
	}
	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 2 {
		context.update(b"Extra");
		state.update(b"Extra").unwrap();
		other_data.extend_from_slice(b"Extra");
	}
	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 3 {
		context.update(&[0u8; 256]);
		state.update(&[0u8; 256]).unwrap();
		other_data.extend_from_slice(&[0u8; 256]);
	}

	let other_hash = context.finalize();
	let orion_hash = state.finalize().unwrap();

	assert_eq!(other_hash.as_bytes(), orion_hash.as_bytes());

	if outsize == 32 {
		let orion_one_shot = blake2b::Hasher::Blake2b256.digest(&other_data).unwrap();
		assert_eq!(other_hash.as_bytes(), orion_one_shot.as_bytes());
	} else if outsize == 48 {
		let orion_one_shot = blake2b::Hasher::Blake2b384.digest(&other_data).unwrap();
		assert_eq!(other_hash.as_bytes(), orion_one_shot.as_bytes());
	} else if outsize == 64 {
		let orion_one_shot = blake2b::Hasher::Blake2b512.digest(&other_data).unwrap();
		assert_eq!(other_hash.as_bytes(), orion_one_shot.as_bytes());
	} else {

	}
}

fn fuzz_blake2b_keyed(fuzzer_input: &[u8], outsize: usize, keysize: usize, seeded_rng: &mut ChaChaRng) {
    assert!(keysize < 65);
    assert!(keysize > 0);
    assert!(outsize < 65);
    assert!(outsize > 0);
    
    let mut key = vec![0u8; keysize];
    seeded_rng.fill_bytes(&mut key);
	
    let orion_key = blake2b::SecretKey::from_slice(&key).unwrap();

	let mut context = blake2_rfc::blake2b::Blake2b::with_key(outsize, &key);
	context.update(fuzzer_input);

	let mut state = blake2b::init(Some(&orion_key), outsize).unwrap();
	state.update(fuzzer_input).unwrap();

	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE {
		context.update(b"");
		state.update(b"").unwrap();
	}
	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 2 {
		context.update(b"Extra");
		state.update(b"Extra").unwrap();
	}
	if fuzzer_input.len() > BLAKE2B_BLOCKSIZE * 3 {
		context.update(&[0u8; 256]);
		state.update(&[0u8; 256]).unwrap();
	}

	let other_hash = context.finalize();
	let orion_hash = state.finalize().unwrap();

	assert_eq!(other_hash.as_bytes(), orion_hash.as_bytes());
}

fn fuzz_sha512(fuzzer_input: &[u8]) {
    let mut state = sha512::init();
    let mut other_data: Vec<u8> = Vec::new();

    other_data.extend_from_slice(fuzzer_input);
    state.update(fuzzer_input).unwrap();

    if fuzzer_input.len() > SHA512_BLOCKSIZE {
		other_data.extend_from_slice(b"");
		state.update(b"").unwrap();
	}
	if fuzzer_input.len() > SHA512_BLOCKSIZE * 2 {
		other_data.extend_from_slice(b"Extra");
		state.update(b"Extra").unwrap();
	}
	if fuzzer_input.len() > SHA512_BLOCKSIZE * 3 {
		other_data.extend_from_slice(&[0u8; 256]);
		state.update(&[0u8; 256]).unwrap();
	}
    
    let digest_other = ring::digest::digest(&ring::digest::SHA512, &other_data);
	let orion_one_shot = sha512::digest(&other_data).unwrap();

	assert!(orion_one_shot.as_bytes() == digest_other.as_ref());
    assert!(state.finalize().unwrap().as_bytes() == digest_other.as_ref());
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::hash::blake2b`
            // through all valid hash-length values
            for outsize in 1..65 {
                // thorugh all valid key-lengths 
                for keysize in 1..65 {
                    fuzz_blake2b_keyed(data, outsize, keysize, &mut seeded_rng);
                }
                fuzz_blake2b_non_keyed(data, outsize);
            }
            
            // Test `orion::hazardous::hash::sha512`
            fuzz_sha512(data);
        });
    }
}
