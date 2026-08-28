use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use honggfuzz::fuzz;
use orion::KP;
use orion::hazardous::kem::*;
use utils::*;

pub mod utils;

fn fuzz_keys(fuzzer_input: &[u8]) {
    use orion::hazardous::kem::{mlkem512, mlkem768, mlkem1024, xwing};

    // ML-KEM512
    let mut buf = [0u8; mlkem512::EK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem512::EK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ek) = mlkem512::EncapsulationKey::try_from(&buf[..]) {
        assert_eq!(ek.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem512::DK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem512::DK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(dk) = mlkem512::DecapsulationKey::unchecked_from_slice(&buf[..]) {
        assert_eq!(dk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem512::CIPHERTEXT_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem512::CIPHERTEXT_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ct) = mlkem512::Ciphertext::try_from(&buf[..]) {
        assert_eq!(ct.as_ref(), &buf[..]);
    }

    // ML-KEM768
    let mut buf = [0u8; mlkem768::EK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem768::EK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ek) = mlkem768::EncapsulationKey::try_from(&buf[..]) {
        assert_eq!(ek.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem768::DK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem768::DK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(dk) = mlkem768::DecapsulationKey::unchecked_from_slice(&buf[..]) {
        assert_eq!(dk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem768::CIPHERTEXT_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem768::CIPHERTEXT_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ct) = mlkem768::Ciphertext::try_from(&buf[..]) {
        assert_eq!(ct.as_ref(), &buf[..]);
    }

    // ML-KEM1024
    let mut buf = [0u8; mlkem1024::EK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem1024::EK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ek) = mlkem1024::EncapsulationKey::try_from(&buf[..]) {
        assert_eq!(ek.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem1024::DK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem1024::DK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(dk) = mlkem1024::DecapsulationKey::unchecked_from_slice(&buf[..]) {
        assert_eq!(dk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; mlkem1024::CIPHERTEXT_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), mlkem1024::CIPHERTEXT_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ct) = mlkem1024::Ciphertext::try_from(&buf[..]) {
        assert_eq!(ct.as_ref(), &buf[..]);
    }

    // X-Wing
    let mut buf = [0u8; xwing::EK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), xwing::EK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ek) = xwing::EncapsulationKey::try_from(&buf[..]) {
        assert_eq!(ek.as_ref(), &buf[..]);
    }

    let mut buf = [0u8; xwing::DK_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), xwing::DK_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(dk) = xwing::DecapsulationKey::try_from(&buf[..]) {
        assert_eq!(dk.unprotected_as_ref(), &buf[..]);
    }

    let mut buf = [0u8; xwing::CIPHERTEXT_SIZE];
    let n = core::cmp::min(fuzzer_input.len(), xwing::CIPHERTEXT_SIZE);
    buf[..n].copy_from_slice(&fuzzer_input[..n]);
    if let Ok(ct) = xwing::Ciphertext::try_from(&buf[..]) {
        assert_eq!(ct.as_ref(), &buf[..]);
    }
}

/// `orion::hazardous::kem::mlkem512`
fn fuzz_mlkem512(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::kem::mlkem512::*;

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_512::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&ExplicitRandom::from(explicit_randomness))
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = orion_kp
        .decap(&mlkem512::Ciphertext::from(other_ct.clone().into_bytes()))
        .unwrap();
    assert_eq!(
        orion_ss_other,
        orion_kp
            .private()
            .decap(&mlkem512::Ciphertext::from(other_ct.into_bytes()))
            .unwrap()
    );

    let mut ctbytes: [u8; 768] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_512::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_ref(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_ref()
    );

    mutate_value(data, &mut ctbytes);
    if let (Ok(orion_ctmutated), Ok(other_mutated)) = (
        mlkem512::Ciphertext::try_from(&ctbytes),
        fips203::ml_kem_512::CipherText::try_from_bytes(ctbytes),
    ) {
        match (
            orion_kp.private().decap(&orion_ctmutated),
            other_decapkey.try_decaps(&other_mutated),
        ) {
            (Ok(_), Ok(_)) => (),
            (Err(_), Err(_)) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated ciphertext: {:?}.", &ctbytes)
            ),
        }
    }
}

/// `orion::hazardous::kem::mlkem768`
fn fuzz_mlkem768(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::kem::mlkem768::*;

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_768::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&ExplicitRandom::from(explicit_randomness))
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = orion_kp
        .decap(&mlkem768::Ciphertext::from(other_ct.clone().into_bytes()))
        .unwrap();
    assert_eq!(
        orion_ss_other,
        orion_kp
            .private()
            .decap(&mlkem768::Ciphertext::from(other_ct.into_bytes()))
            .unwrap()
    );
    let mut ctbytes: [u8; 1088] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_768::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_ref(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_ref()
    );

    mutate_value(data, &mut ctbytes);
    if let (Ok(orion_ctmutated), Ok(other_mutated)) = (
        mlkem768::Ciphertext::try_from(&ctbytes),
        fips203::ml_kem_768::CipherText::try_from_bytes(ctbytes),
    ) {
        match (
            orion_kp.private().decap(&orion_ctmutated),
            other_decapkey.try_decaps(&other_mutated),
        ) {
            (Ok(_), Ok(_)) => (),
            (Err(_), Err(_)) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated ciphertext: {:?}.", &ctbytes)
            ),
        }
    }
}

/// `orion::hazardous::kem::mlkem1024`
fn fuzz_mlkem1024(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use orion::hazardous::kem::mlkem1024::*;

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::try_from(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_1024::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&ExplicitRandom::from(explicit_randomness))
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = orion_kp
        .decap(&mlkem1024::Ciphertext::from(other_ct.clone().into_bytes()))
        .unwrap();
    assert_eq!(
        orion_ss_other,
        orion_kp
            .private()
            .decap(&mlkem1024::Ciphertext::from(other_ct.into_bytes()))
            .unwrap()
    );
    let mut ctbytes: [u8; 1568] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_1024::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_ref(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_ref()
    );

    mutate_value(data, &mut ctbytes);
    if let (Ok(orion_ctmutated), Ok(other_mutated)) = (
        mlkem1024::Ciphertext::try_from(&ctbytes),
        fips203::ml_kem_1024::CipherText::try_from_bytes(ctbytes),
    ) {
        match (
            orion_kp.private().decap(&orion_ctmutated),
            other_decapkey.try_decaps(&other_mutated),
        ) {
            (Ok(_), Ok(_)) => (),
            (Err(_), Err(_)) => (),
            _ => panic!(
                "{}",
                format!("Disagreed on mutated ciphertext: {:?}.", &ctbytes)
            ),
        }
    }
}

/// `orion::hazardous::kem::xwing`
fn fuzz_xwing(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use kem::{Decapsulate, Decapsulator, Encapsulate, KeyExport};
    use orion::hazardous::kem::xwing::*;

    // Generate seeds
    let mut seed = [0u8; 32];
    seeded_rng.fill_bytes(&mut seed);
    // Make two RNGs for reproduceability (ChaCha8Rng has no Clone impl):
    let mut orion_eseed = make_seeded_rng(data);
    let mut other_eseed = make_seeded_rng(data);
    let mut eseed = [0u8; 64];
    orion_eseed.fill_bytes(&mut eseed);

    let orion_decapkey = DecapsulationKey::try_from(&seed).unwrap();
    let orion_kp = KeyPair::try_from(&orion_decapkey).unwrap();

    let other_decapkey = x_wing::DecapsulationKey::from(seed);
    let other_encapkey = other_decapkey.encapsulation_key();
    assert_eq!(
        orion_kp.private().unprotected_as_ref(),
        orion_decapkey.unprotected_as_ref()
    );
    assert_eq!(
        orion_kp.public().as_ref(),
        other_encapkey.clone().to_bytes().as_slice()
    );

    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&Eseed::from(eseed))
        .unwrap();
    let (other_ct, other_ss) = other_encapkey.encapsulate_with_rng(&mut other_eseed);

    assert_eq!(orion_ct, other_ct.clone().as_slice()[..]);
    assert_eq!(orion_ss, other_ss.clone().as_slice()[..]);

    let orion_ss_other = orion_kp.decap(&Ciphertext::from(other_ct.0)).unwrap();
    let ctbytes: [u8; CIPHERTEXT_SIZE] = orion_ct.as_ref().try_into().unwrap();
    let kemct = kem::Ciphertext::<x_wing::XWingKem>::from(ctbytes);
    let other_ss_orion = other_decapkey.decapsulate(&x_wing::Ciphertext::try_from(kemct).unwrap());

    assert_eq!(orion_ss_other.unprotected_as_ref(), &other_ss[..]);
    assert_eq!(&other_ss_orion[..], orion_ss.unprotected_as_ref());
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            fuzz_keys(data);

            // Test `orion::hazardous::kem::mlkem*`
            fuzz_mlkem512(&mut seeded_rng, data);
            fuzz_mlkem768(&mut seeded_rng, data);
            fuzz_mlkem1024(&mut seeded_rng, data);
            // Test `orion::hazardous::kem::xwing`
            fuzz_xwing(&mut seeded_rng, data);
        });
    }
}
