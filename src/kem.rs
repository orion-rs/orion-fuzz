#[macro_use]
extern crate honggfuzz;
extern crate fips203;
extern crate orion;

use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use orion::hazardous::kem::*;
use utils::{make_seeded_rng, ChaChaRng, RngCore};

pub mod utils;

/// `orion::hazardous::kem::mlkem512`
fn fuzz_mlkem512(seeded_rng: &mut ChaChaRng, data: &[u8]) {
    use orion::hazardous::kem::mlkem512::*;

    if let (Ok(_ek), Ok(_dk)) = (
        EncapsulationKey::from_slice(data),
        DecapsulationKey::unchecked_from_slice(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::from_slice(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_512::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&explicit_randomness)
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = mlkem512::MlKem512::decap(
        orion_kp.private(),
        &mlkem512::Ciphertext::from(other_ct.into_bytes()),
    )
    .unwrap();
    let ctbytes: [u8; 768] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_512::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_bytes(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_bytes()
    );
}

/// `orion::hazardous::kem::mlkem768`
fn fuzz_mlkem768(seeded_rng: &mut ChaChaRng, data: &[u8]) {
    use orion::hazardous::kem::mlkem768::*;

    if let (Ok(_ek), Ok(_dk)) = (
        EncapsulationKey::from_slice(data),
        DecapsulationKey::unchecked_from_slice(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::from_slice(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_768::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&explicit_randomness)
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = mlkem768::MlKem768::decap(
        orion_kp.private(),
        &mlkem768::Ciphertext::from(other_ct.into_bytes()),
    )
    .unwrap();
    let ctbytes: [u8; 1088] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_768::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_bytes(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_bytes()
    );
}

/// `orion::hazardous::kem::mlkem1024`
fn fuzz_mlkem1024(seeded_rng: &mut ChaChaRng, data: &[u8]) {
    use orion::hazardous::kem::mlkem1024::*;

    if let (Ok(_ek), Ok(_dk)) = (
        EncapsulationKey::from_slice(data),
        DecapsulationKey::unchecked_from_slice(data),
    ) {
        panic!("this should never happen")
    }

    // Generate seeds
    let mut dz = [0u8; 64];
    seeded_rng.fill_bytes(&mut dz);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&dz[..32]);
    z.copy_from_slice(&dz[32..]);

    let mut explicit_randomness = [0u8; 32];
    seeded_rng.fill_bytes(&mut explicit_randomness);

    let orion_kp = KeyPair::try_from(&Seed::from_slice(&dz).unwrap()).unwrap();
    let (other_encapkey, other_decapkey) = fips203::ml_kem_1024::KG::keygen_from_seed(d, z);
    assert_eq!(
        orion_kp.public().as_ref(),
        &other_encapkey.clone().into_bytes()
    );

    // We encaspulate for fips203-crate and the other way around
    let (orion_ss, orion_ct) = orion_kp
        .public()
        .encap_deterministic(&explicit_randomness)
        .unwrap();
    let (other_ss, other_ct) = other_encapkey.encaps_from_seed(&explicit_randomness);

    assert_eq!(orion_ct, &other_ct.clone().into_bytes()[..]);
    assert_eq!(orion_ss, &other_ss.clone().into_bytes()[..]);

    let orion_ss_other = mlkem1024::MlKem1024::decap(
        orion_kp.private(),
        &mlkem1024::Ciphertext::from(other_ct.into_bytes()),
    )
    .unwrap();
    let ctbytes: [u8; 1568] = orion_ct.as_ref().try_into().unwrap();
    let other_ss_orion = other_decapkey
        .try_decaps(&fips203::ml_kem_1024::CipherText::try_from_bytes(ctbytes).unwrap())
        .unwrap();

    assert_eq!(
        orion_ss_other.unprotected_as_bytes(),
        &other_ss.into_bytes()[..]
    );
    assert_eq!(
        &other_ss_orion.into_bytes()[..],
        orion_ss.unprotected_as_bytes()
    );
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::kem::mlkem*`
            fuzz_mlkem512(&mut seeded_rng, data);
            fuzz_mlkem768(&mut seeded_rng, data);
            fuzz_mlkem1024(&mut seeded_rng, data);
        });
    }
}
