use honggfuzz::fuzz;
use hpke::{Kem, OpModeR, OpModeS, PskBundle, Serializable};
use orion::KP;
use orion::hazardous::kem::x25519_hkdf_sha256::KeyPair;
use orion::hazardous::kem::x25519_hkdf_sha256::{PrivateKey, PublicKey};
use utils::*;

pub mod utils;

/// `orion::hazardous::hpke::{*, DHKEM_X25519_SHA256_CHACHA20}`
fn fuzz_dhkem_x25519_hkdf_sha256_modebase(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let recipient_kp = KeyPair::derive(&kp_ikm_r).unwrap();
    let other_recipient_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_r);

    // Cannot compare these private keys directly due to the faulty HPKE RFC 9180 test vectors and hpke-rs
    // not returning clamped keys. So we create an Orion instance which will clamp it, and compare this instead.
    let other_clamped_privatekey =
        PrivateKey::try_from(other_recipient_kp.0.to_bytes().as_slice()).unwrap();
    // the PublicKey does not need the clamping so this is fine as-is.
    assert_eq!(recipient_kp.private(), &other_clamped_privatekey);
    assert_eq!(
        recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 32];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(recipient_kp.public(), &info).unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &other_recipient_kp.0,
            &<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref())
                .unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModeBase::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
        &PublicKey::from(other_encapped_key_bytes),
        recipient_kp.private(),
        &info,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn fuzz_dhkem_x25519_hkdf_sha256_modepsk(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let psk = rand_vec_in_range(seeded_rng, 32, 64);
    let psk_id = rand_vec_in_range(seeded_rng, 1, 64);

    let recipient_kp = KeyPair::derive(&kp_ikm_r).unwrap();
    let other_recipient_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_r);

    // Cannot compare these private keys directly due to the faulty HPKE RFC 9180 test vectors and hpke-rs
    // not returning clamped keys. So we create an Orion instance which will clamp it, and compare this instead.
    let other_clamped_privatekey =
        PrivateKey::try_from(other_recipient_kp.0.to_bytes().as_slice()).unwrap();
    // the PublicKey does not need the clamping so this is fine as-is.
    assert_eq!(recipient_kp.private(), &other_clamped_privatekey);
    assert_eq!(
        recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 32];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
            recipient_kp.public(),
            &info,
            &psk,
            &psk_id,
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.0,
            &<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref())
                .unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModePsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
        &PublicKey::from(other_encapped_key_bytes),
        recipient_kp.private(),
        &info,
        &psk,
        &psk_id,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn fuzz_dhkem_x25519_hkdf_sha256_modeauth(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_s = [0u8; 32];
    let mut kp_ikm_r = [0u8; 32];
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    seeded_rng.fill_bytes(&mut kp_ikm_s);
    seeded_rng.fill_bytes(&mut kp_ikm_r);

    let sender_kp = KeyPair::derive(&kp_ikm_s).unwrap();
    let recipient_kp = KeyPair::derive(&kp_ikm_r).unwrap();

    let other_sender_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_s);
    let other_recipient_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_r);

    // Cannot compare these private keys directly due to the faulty HPKE RFC 9180 test vectors and hpke-rs
    // not returning clamped keys. So we create an Orion instance which will clamp it, and compare this instead.
    let other_clamped_privatekey_s =
        PrivateKey::try_from(other_sender_kp.0.to_bytes().as_slice()).unwrap();
    let other_clamped_privatekey_r =
        PrivateKey::try_from(other_recipient_kp.0.to_bytes().as_slice()).unwrap();
    // the PublicKey does not need the clamping so this is fine as-is.
    assert_eq!(recipient_kp.private(), &other_clamped_privatekey_r);
    assert_eq!(sender_kp.private(), &other_clamped_privatekey_s);
    assert_eq!(
        recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );
    assert_eq!(sender_kp.public(), other_sender_kp.1.to_bytes().as_slice());

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Auth(other_sender_kp.clone()),
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 32];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
            recipient_kp.public(),
            &info,
            sender_kp.private(),
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Auth(
                <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(sender_kp.public().as_ref())
                    .unwrap(),
            ),
            &other_recipient_kp.0,
            &<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref())
                .unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModeAuth::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
        &PublicKey::from(other_encapped_key_bytes),
        recipient_kp.private(),
        &info,
        &PublicKey::try_from(other_sender_kp.1.to_bytes().as_slice()).unwrap(),
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn fuzz_dhkem_x25519_hkdf_sha256_modeauthpsk(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_s = [0u8; 32];
    let mut kp_ikm_r = [0u8; 32];
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let psk = rand_vec_in_range(seeded_rng, 32, 64);
    let psk_id = rand_vec_in_range(seeded_rng, 1, 64);

    seeded_rng.fill_bytes(&mut kp_ikm_s);
    seeded_rng.fill_bytes(&mut kp_ikm_r);

    let sender_kp = KeyPair::derive(&kp_ikm_s).unwrap();
    let recipient_kp = KeyPair::derive(&kp_ikm_r).unwrap();

    let other_sender_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_s);
    let other_recipient_kp = X25519HkdfSha256::derive_keypair(&kp_ikm_r);

    // Cannot compare these private keys directly due to the faulty HPKE RFC 9180 test vectors and hpke-rs
    // not returning clamped keys. So we create an Orion instance which will clamp it, and compare this instead.
    let other_clamped_privatekey_s =
        PrivateKey::try_from(other_sender_kp.0.to_bytes().as_slice()).unwrap();
    let other_clamped_privatekey_r =
        PrivateKey::try_from(other_recipient_kp.0.to_bytes().as_slice()).unwrap();
    // the PublicKey does not need the clamping so this is fine as-is.
    assert_eq!(recipient_kp.private(), &other_clamped_privatekey_r);
    assert_eq!(sender_kp.private(), &other_clamped_privatekey_s);
    assert_eq!(
        recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );
    assert_eq!(sender_kp.public(), other_sender_kp.1.to_bytes().as_slice());

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::AuthPsk(
                other_sender_kp.clone(),
                PskBundle::new(&psk, &psk_id).unwrap(),
            ),
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 32];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_sender(
            recipient_kp.public(),
            &info,
            &psk,
            &psk_id,
            sender_kp.private(),
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::AuthPsk(
                <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(sender_kp.public().as_ref())
                    .unwrap(),
                PskBundle::new(&psk, &psk_id).unwrap(),
            ),
            &other_recipient_kp.0,
            &<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref())
                .unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModeAuthPsk::<DHKEM_X25519_SHA256_CHACHA20>::new_recipient(
        &PublicKey::from(other_encapped_key_bytes),
        recipient_kp.private(),
        &info,
        &psk,
        &psk_id,
        &PublicKey::try_from(other_sender_kp.1.to_bytes().as_slice()).unwrap(),
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

/// `orion::hazardous::hpke::{*, MLKEM768_X25519_SHA256_CHACHA20}`
fn fuzz_mlkem768_x25519_hkdf_sha256_modebase(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let orion_recipient_kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&kp_ikm_r).unwrap();
    let other_recipient_kp = XWing::derive_keypair(&kp_ikm_r);

    assert_eq!(
        orion_recipient_kp.private(),
        other_recipient_kp.0.to_bytes().as_slice()
    );
    assert_eq!(
        orion_recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 1120];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::new_sender(orion_recipient_kp.public(), &info)
            .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &other_recipient_kp.0,
            &<XWing as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref()).unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModeBase::<MLKEM768_X25519_SHA256_CHACHA20>::new_recipient(
        &orion::hazardous::kem::xwing::Ciphertext::from(other_encapped_key_bytes),
        orion_recipient_kp.private(),
        &info,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn fuzz_mlkem768_x25519_hkdf_sha256_modepsk(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let psk = rand_vec_in_range(seeded_rng, 32, 64);
    let psk_id = rand_vec_in_range(seeded_rng, 1, 64);

    let orion_recipient_kp = MLKEM768_X25519_SHA256_CHACHA20::derive_keypair(&kp_ikm_r).unwrap();
    let other_recipient_kp = XWing::derive_keypair(&kp_ikm_r);

    assert_eq!(
        orion_recipient_kp.private(),
        other_recipient_kp.0.to_bytes().as_slice()
    );
    assert_eq!(
        orion_recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 1120];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::new_sender(
            orion_recipient_kp.public(),
            &info,
            &psk,
            &psk_id,
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.0,
            &<XWing as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref()).unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModePsk::<MLKEM768_X25519_SHA256_CHACHA20>::new_recipient(
        &orion::hazardous::kem::xwing::Ciphertext::from(other_encapped_key_bytes),
        orion_recipient_kp.private(),
        &info,
        &psk,
        &psk_id,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

/// `orion::hazardous::hpke::{*, MLKEM768_X25519_SHAKE256_CHACHA20}`
fn fuzz_mlkem768_x25519_shake256_modebase(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::KdfShake256, kem::XWing};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let orion_recipient_kp = MLKEM768_X25519_SHAKE256_CHACHA20::derive_keypair(&kp_ikm_r).unwrap();
    let other_recipient_kp = XWing::derive_keypair(&kp_ikm_r);

    assert_eq!(
        orion_recipient_kp.private(),
        other_recipient_kp.0.to_bytes().as_slice()
    );
    assert_eq!(
        orion_recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, KdfShake256, XWing>(
            &OpModeS::Base,
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 1120];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModeBase::<MLKEM768_X25519_SHAKE256_CHACHA20>::new_sender(
            orion_recipient_kp.public(),
            &info,
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, KdfShake256, XWing>(
            &OpModeR::Base,
            &other_recipient_kp.0,
            &<XWing as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref()).unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModeBase::<MLKEM768_X25519_SHAKE256_CHACHA20>::new_recipient(
        &orion::hazardous::kem::xwing::Ciphertext::from(other_encapped_key_bytes),
        orion_recipient_kp.private(),
        &info,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn fuzz_mlkem768_x25519_shake256_modepsk(seeded_rng: &mut ChaCha8Rng, data: &[u8]) {
    use hpke::Deserializable;
    use hpke::{aead::ChaCha20Poly1305, kdf::KdfShake256, kem::XWing};
    use orion::hazardous::hpke::*;

    let mut kp_ikm_r = [0u8; 32];
    seeded_rng.fill_bytes(&mut kp_ikm_r);
    let info = rand_vec_in_range(seeded_rng, 0, 64);

    let psk = rand_vec_in_range(seeded_rng, 32, 64);
    let psk_id = rand_vec_in_range(seeded_rng, 1, 64);

    let orion_recipient_kp = MLKEM768_X25519_SHAKE256_CHACHA20::derive_keypair(&kp_ikm_r).unwrap();
    let other_recipient_kp = XWing::derive_keypair(&kp_ikm_r);

    assert_eq!(
        orion_recipient_kp.private(),
        other_recipient_kp.0.to_bytes().as_slice()
    );
    assert_eq!(
        orion_recipient_kp.public(),
        other_recipient_kp.1.to_bytes().as_slice()
    );

    let (other_encapsulated_key, mut other_hpke_context_sender) =
        hpke::setup_sender_with_rng::<ChaCha20Poly1305, KdfShake256, XWing>(
            &OpModeS::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.1,
            &info,
            seeded_rng,
        )
        .expect("invalid server pubkey!");

    let mut other_encapped_key_bytes = [0u8; 1120];
    other_encapsulated_key.write_exact(&mut other_encapped_key_bytes);

    let (mut hpke_sender, orion_encapped_key) =
        ModePsk::<MLKEM768_X25519_SHAKE256_CHACHA20>::new_sender(
            orion_recipient_kp.public(),
            &info,
            &psk,
            &psk_id,
        )
        .unwrap();

    let mut other_hpke_context_recipient =
        hpke::setup_receiver::<ChaCha20Poly1305, KdfShake256, XWing>(
            &OpModeR::Psk(PskBundle::new(&psk, &psk_id).unwrap()),
            &other_recipient_kp.0,
            &<XWing as Kem>::EncappedKey::from_bytes(orion_encapped_key.as_ref()).unwrap(),
            &info,
        )
        .expect("failed to set up recipient!");
    let mut hpke_recipient = ModePsk::<MLKEM768_X25519_SHAKE256_CHACHA20>::new_recipient(
        &orion::hazardous::kem::xwing::Ciphertext::from(other_encapped_key_bytes),
        orion_recipient_kp.private(),
        &info,
        &psk,
        &psk_id,
    )
    .unwrap();

    let aad = rand_vec_in_range(seeded_rng, 0, 64);
    let plaintext = data;
    let mut orion_cts: Vec<Vec<u8>> = Vec::new();
    let mut other_cts: Vec<Vec<u8>> = Vec::new();
    let n = seeded_rng.random_range(1..=16);

    for _ in 0..n {
        let mut orion_ct = vec![0u8; plaintext.len() + 16];
        hpke_sender.seal(plaintext, &aad, &mut orion_ct).unwrap();
        let other_ct = other_hpke_context_sender.seal(plaintext, &aad).unwrap();
        // Non-deterministic instances
        assert_ne!(&orion_ct, &other_ct);
        if let Some(prev) = orion_cts.last().as_ref() {
            // nonce should forward making distinct ciphertexts for smae PT
            assert_ne!(prev.as_slice(), orion_ct.as_slice());
        }

        orion_cts.push(orion_ct);
        other_cts.push(other_ct);
    }

    for (orion_ct, other_ct) in orion_cts.iter().zip(other_cts.iter()) {
        let mut orion_pt = vec![0u8; plaintext.len()];
        hpke_recipient.open(other_ct, &aad, &mut orion_pt).unwrap();
        let other_plaintext = other_hpke_context_recipient
            .open(orion_ct, &aad)
            .expect("invalid ciphertext!");

        assert_eq!(orion_pt, other_plaintext);
    }

    let exporter_context = rand_vec_in_range(seeded_rng, 0, 64);
    let mut out_export_orion = rand_vec_in_range(seeded_rng, 1, 64);
    let mut out_export_other = out_export_orion.clone();

    // OtherR <= OrionS, OrionR <= OtherS
    other_hpke_context_recipient
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_sender
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);

    other_hpke_context_sender
        .export(&exporter_context, &mut out_export_other)
        .unwrap();
    hpke_recipient
        .export_secret(&exporter_context, &mut out_export_orion)
        .unwrap();
    assert_eq!(&out_export_other, &out_export_orion);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::hpke::{*, DHKEM_X25519_SHA256_CHACHA20}`
            fuzz_dhkem_x25519_hkdf_sha256_modebase(&mut seeded_rng, data);
            fuzz_dhkem_x25519_hkdf_sha256_modepsk(&mut seeded_rng, data);
            fuzz_dhkem_x25519_hkdf_sha256_modeauth(&mut seeded_rng, data);
            fuzz_dhkem_x25519_hkdf_sha256_modeauthpsk(&mut seeded_rng, data);

            // Test `orion::hazardous::hpke::{*, MLKEM768_X25519_SHA256_CHACHA20}`
            fuzz_mlkem768_x25519_hkdf_sha256_modebase(&mut seeded_rng, data);
            fuzz_mlkem768_x25519_hkdf_sha256_modepsk(&mut seeded_rng, data);

            // Test `orion::hazardous::hpke::{*, MLKEM768_X25519_SHAKE256_CHACHA20}`
            fuzz_mlkem768_x25519_shake256_modebase(&mut seeded_rng, data);
            fuzz_mlkem768_x25519_shake256_modepsk(&mut seeded_rng, data);
        });
    }
}
