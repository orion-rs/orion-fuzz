#[macro_use]
extern crate honggfuzz;
extern crate fips204;
extern crate orion;

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use orion::KP;
use utils::*;

pub mod utils;

fn fuzz_keys(fuzzer_input: &[u8]) {
    use orion::hazardous::dsa::{mldsa44, mldsa65, mldsa87};

    // ML-DSA44
    let mut buf = [0u8; mldsa44::VERIFYING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa44::VERIFYING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(pk) = mldsa44::VerifyingKey::try_from(&buf[..]) {
        assert_eq!(pk.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa44::SIGNING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa44::SIGNING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sk) = mldsa44::SigningKey::try_from(&buf[..]) {
        assert_eq!(sk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa44::SIGNATURE_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa44::SIGNATURE_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sig) = mldsa44::Signature::try_from(&buf[..]) {
        assert_eq!(sig.as_ref(), &buf[..]);
    }

    // ML-DSA65
    let mut buf = [0u8; mldsa65::VERIFYING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa65::VERIFYING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(pk) = mldsa65::VerifyingKey::try_from(&buf[..]) {
        assert_eq!(pk.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa65::SIGNING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa65::SIGNING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sk) = mldsa65::SigningKey::try_from(&buf[..]) {
        assert_eq!(sk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa65::SIGNATURE_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa65::SIGNATURE_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sig) = mldsa65::Signature::try_from(&buf[..]) {
        assert_eq!(sig.as_ref(), &buf[..]);
    }

    // ML-DSA87
    let mut buf = [0u8; mldsa87::VERIFYING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa87::VERIFYING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(pk) = mldsa87::VerifyingKey::try_from(&buf[..]) {
        assert_eq!(pk.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa87::SIGNING_KEY_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa87::SIGNING_KEY_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sk) = mldsa87::SigningKey::try_from(&buf[..]) {
        assert_eq!(sk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mldsa87::SIGNATURE_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mldsa87::SIGNATURE_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(sig) = mldsa87::Signature::try_from(&buf[..]) {
        assert_eq!(sig.as_ref(), &buf[..]);
    }
}

/// `orion::hazardous::dsa::mldsa44`
fn fuzz_mldsa44(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa44::*;

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);
    let ctx = rand_vec_in_range(seeded_rng, 0, 255);

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
        .sign_with_rnd(data, &ctx, &ExplicitRandom::try_from(&rnd).unwrap())
        .unwrap();
    let other_sig = other_private.try_sign_with_seed(&rnd, data, &ctx).unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &ctx,
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let mut sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &ctx));

    mutate_value(data, &mut sigbytes);
    if let Ok(sigmutated) = Signature::try_from(&sigbytes) {
        match (
            orion_kp.public().verify(data, &ctx, &sigmutated),
            other_public.verify(data, &sigbytes, &ctx),
        ) {
            (Ok(_), true) => (),
            (Err(_), false) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated signature: {:?}.", sigbytes)
            ),
        }
    }
}

/// `orion::hazardous::dsa::mldsa65`
fn fuzz_mldsa65(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa65::*;

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);
    let ctx = rand_vec_in_range(seeded_rng, 0, 255);

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
        .sign_with_rnd(data, &ctx, &ExplicitRandom::try_from(&rnd).unwrap())
        .unwrap();
    let other_sig = other_private.try_sign_with_seed(&rnd, data, &ctx).unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &ctx,
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let mut sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &ctx));

    mutate_value(data, &mut sigbytes);
    if let Ok(sigmutated) = Signature::try_from(&sigbytes) {
        match (
            orion_kp.public().verify(data, &ctx, &sigmutated),
            other_public.verify(data, &sigbytes, &ctx),
        ) {
            (Ok(_), true) => (),
            (Err(_), false) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated signature: {:?}.", sigbytes)
            ),
        }
    }
}

/// `orion::hazardous::dsa::mldsa87`
fn fuzz_mldsa87(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::dsa::mldsa87::*;

    // Generate seeds
    let mut seed = [0u8; SEED_SIZE];
    let mut rnd = [0u8; RAND_SIZE];
    seeded_rng.fill_bytes(&mut seed);
    seeded_rng.fill_bytes(&mut rnd);
    let ctx = rand_vec_in_range(seeded_rng, 0, 255);

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
        .sign_with_rnd(data, &ctx, &ExplicitRandom::try_from(&rnd).unwrap())
        .unwrap();
    let other_sig = other_private.try_sign_with_seed(&rnd, data, &ctx).unwrap();

    assert_eq!(orion_sig, other_sig.clone().as_slice());
    assert!(
        orion_kp
            .public()
            .verify(
                data,
                &ctx,
                &Signature::try_from(other_sig.clone().as_slice()).unwrap()
            )
            .is_ok()
    );

    let mut sigbytes: [u8; SIGNATURE_SIZE] = orion_sig.as_ref().try_into().unwrap();
    assert!(other_public.verify(data, &sigbytes, &ctx));

    mutate_value(data, &mut sigbytes);
    if let Ok(sigmutated) = Signature::try_from(&sigbytes) {
        match (
            orion_kp.public().verify(data, &ctx, &sigmutated),
            other_public.verify(data, &sigbytes, &ctx),
        ) {
            (Ok(_), true) => (),
            (Err(_), false) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated signature: {:?}.", sigbytes)
            ),
        }
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            fuzz_keys(data);

            // Test `orion::hazardous::dsa::mldsa*`
            fuzz_mldsa44(&mut seeded_rng, data);
            fuzz_mldsa65(&mut seeded_rng, data);
            fuzz_mldsa87(&mut seeded_rng, data);
        });
    }
}
