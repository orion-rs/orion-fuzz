#[macro_use]
extern crate honggfuzz;
extern crate fips204;
extern crate orion;

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use orion::KP;
use utils::*;

pub mod utils;

/// `orion::hazardous::dsa::mldsa44`
fn fuzz_mldsa44(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa44::*;

    if let (Ok(_sk), Ok(_pk), Ok(_sig)) = (
        SigningKey::try_from(data),
        VerifyingKey::try_from(data),
        Signature::try_from(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);

    let ctxsize = seeded_rng.random_range(0..=255);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&seed).unwrap()).unwrap();
    let (other_public, other_private) = fips204::ml_dsa_44::KG::keygen_from_seed(&seed);
    assert_eq!(
        orion_kp.private().unprotected_as_ref(),
        &other_private.clone().into_bytes()
    );
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_public.clone().into_bytes()
    );

    // We sign `data` and compare and verify cross-crate
    let orion_sig = orion_kp
        .private()
        .sign_with_rnd(
            data,
            &vec![0u8; ctxsize],
            &ExplicitRandom::try_from(&rnd).unwrap(),
        )
        .unwrap();
    let other_sig = other_private
        .try_sign_with_seed(&rnd, data, &vec![0u8; ctxsize])
        .unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &vec![0u8; ctxsize],
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &vec![0u8; ctxsize]));
}

/// `orion::hazardous::dsa::mldsa65`
fn fuzz_mldsa65(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa65::*;

    if let (Ok(_sk), Ok(_pk), Ok(_sig)) = (
        SigningKey::try_from(data),
        VerifyingKey::try_from(data),
        Signature::try_from(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);

    let ctxsize = seeded_rng.random_range(0..=255);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&seed).unwrap()).unwrap();
    let (other_public, other_private) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
    assert_eq!(
        orion_kp.private().unprotected_as_ref(),
        &other_private.clone().into_bytes()
    );
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_public.clone().into_bytes()
    );

    // We sign `data` and compare and verify cross-crate
    let orion_sig = orion_kp
        .private()
        .sign_with_rnd(
            data,
            &vec![0u8; ctxsize],
            &ExplicitRandom::try_from(&rnd).unwrap(),
        )
        .unwrap();
    let other_sig = other_private
        .try_sign_with_seed(&rnd, data, &vec![0u8; ctxsize])
        .unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &vec![0u8; ctxsize],
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &vec![0u8; ctxsize]));
}

/// `orion::hazardous::dsa::mldsa87`
fn fuzz_mldsa87(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa87::*;

    if let (Ok(_sk), Ok(_pk), Ok(_sig)) = (
        SigningKey::try_from(data),
        VerifyingKey::try_from(data),
        Signature::try_from(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);

    let ctxsize = seeded_rng.random_range(0..=255);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&seed).unwrap()).unwrap();
    let (other_public, other_private) = fips204::ml_dsa_87::KG::keygen_from_seed(&seed);
    assert_eq!(
        orion_kp.private().unprotected_as_ref(),
        &other_private.clone().into_bytes()
    );
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_public.clone().into_bytes()
    );

    // We sign `data` and compare and verify cross-crate
    let orion_sig = orion_kp
        .private()
        .sign_with_rnd(
            data,
            &vec![0u8; ctxsize],
            &ExplicitRandom::try_from(&rnd).unwrap(),
        )
        .unwrap();
    let other_sig = other_private
        .try_sign_with_seed(&rnd, data, &vec![0u8; ctxsize])
        .unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &vec![0u8; ctxsize],
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &vec![0u8; ctxsize]));
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::dsa::mldsa*`
            fuzz_mldsa44(&mut seeded_rng, data);
            fuzz_mldsa65(&mut seeded_rng, data);
            fuzz_mldsa87(&mut seeded_rng, data);
        });
    }
}
