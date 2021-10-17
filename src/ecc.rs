#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate x25519_dalek;

use orion::hazardous::ecc::x25519;
use std::convert::TryFrom;
use utils::{make_seeded_rng, ChaChaRng, RngCore};

pub mod utils;

/// `orion::hazardous::ecc::x25519`
fn fuzz_x25519(seeded_rng: &mut ChaChaRng) {
    // Key-agreement
    let mut alice_k = [0u8; x25519::PRIVATE_KEY_SIZE];
    let mut bob_k = [0u8; x25519::PRIVATE_KEY_SIZE];
    seeded_rng.fill_bytes(&mut alice_k);
    seeded_rng.fill_bytes(&mut bob_k);

    let alice_secret = x25519::PrivateKey::from_slice(&alice_k).unwrap();
    let alice_public = x25519::PublicKey::try_from(&alice_secret).unwrap();
    let bob_secret = x25519::PrivateKey::from_slice(&bob_k).unwrap();
    let bob_public = x25519::PublicKey::try_from(&bob_secret).unwrap();

    let alice_shared = x25519::key_agreement(&alice_secret, &bob_public).unwrap();
    let bob_shared = x25519::key_agreement(&bob_secret, &alice_public).unwrap();

    assert_eq!(alice_shared, bob_shared);

    // x25519_dalek (we use the bare-byte function since this is the one documented as adherent to RFC)
    let dalek_alice_public: [u8; 32] = alice_public.to_bytes();
    let dalek_bob_public: [u8; 32] = bob_public.to_bytes();
    let dalek_alice_shared = x25519_dalek::x25519(alice_k, dalek_bob_public);
    let dalek_bob_shared = x25519_dalek::x25519(bob_k, dalek_alice_public);

    assert_eq!(alice_shared, dalek_alice_shared.as_ref());
    assert_eq!(bob_shared, dalek_bob_shared.as_ref());
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::ecc::x25519`
            fuzz_x25519(&mut seeded_rng);
        });
    }
}
