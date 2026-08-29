use honggfuzz::fuzz;
use orion::hazardous::ecc::x25519;
use std::convert::TryFrom;
use utils::*;

pub mod utils;

/// `orion::hazardous::ecc::x25519`
fn fuzz_x25519(seeded_rng: &mut ChaCha8Rng, fuzzer_input: &[u8]) {
    // Key-agreement
    if let Ok(bob_public) = x25519::PublicKey::try_from(fuzzer_input) {
        let mut alice_k = [0u8; x25519::PRIVATE_KEY_SIZE];
        seeded_rng.fill_bytes(&mut alice_k);

        let alice_secret = x25519::PrivateKey::try_from(&alice_k).unwrap();
        if let Ok(alice_shared) = x25519::key_agreement(&alice_secret, &bob_public) {
            // x25519_dalek (we use the bare-byte function since this is the one documented as adherent to RFC)
            let dalek_bob_public: [u8; 32] = bob_public.as_ref().try_into().unwrap();
            let dalek_alice_shared = x25519_dalek::x25519(alice_k, dalek_bob_public);

            assert_eq!(alice_shared, dalek_alice_shared.as_ref());
        }
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::ecc::x25519`
            fuzz_x25519(&mut seeded_rng, data);
        });
    }
}
