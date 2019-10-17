#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate sodiumoxide;
pub mod utils;

use utils::{make_seeded_rng, ChaChaRng, RngCore};

use orion::hazardous::aead::xchacha20poly1305_stream::*;
use orion::hazardous::stream::chacha20::SecretKey;

use sodiumoxide::crypto::secretstream::xchacha20poly1305 as sodium_stream;

/// Randomly select which tag should be passed to sealing a chunk.
fn select_tag(seeded_rng: &mut ChaChaRng) -> (Tag, sodium_stream::Tag) {
    let mut rand_select = [0u8; 1];
    seeded_rng.fill_bytes(&mut rand_select);

    if rand_select[0] <= 63u8 {
        (Tag::MESSAGE, sodium_stream::Tag::Message)
    } else if rand_select[0] <= 126u8 {
        (Tag::PUSH, sodium_stream::Tag::Push)
    } else if rand_select[0] <= 189u8 {
        (Tag::REKEY, sodium_stream::Tag::Rekey)
    } else {
        (Tag::FINISH, sodium_stream::Tag::Final)
    }
}

/// Select additional data to authenticate based on input chunk.
fn select_ad(input_chunk: &[u8], seeded_rng: &mut ChaChaRng) -> Vec<u8> {
    // `ad` will be both tested as Some and None as None is the same as [0u8; 0]
    if input_chunk.is_empty() {
        vec![0u8; 0]
    } else if input_chunk[0] > 127 {
        let mut tmp = vec![0u8; input_chunk.len() / 8];
        seeded_rng.fill_bytes(&mut tmp);
        tmp
    } else {
        vec![0u8; 0]
    }
}

/// `orion::hazardous::` // TODO: Missing
fn fuzz_secret_stream(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    let mut key = vec![0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    let (mut sodium_state_enc, sodium_header) =
        sodium_stream::Stream::init_push(&sodium_stream::Key::from_slice(&key).unwrap()).unwrap();

    let mut orion_state_enc = SecretStreamXChaCha20Poly1305::new(
        &SecretKey::from_slice(&key[..]).unwrap(),
        &Nonce::from_slice(sodium_header.as_ref()).unwrap(),
    );

    // `seal_chunk()`
    let rnd_chunksize = seeded_rng.next_u32() as usize;
    let mut collected_enc: Vec<u8> = Vec::new();
    let mut collected_ad: Vec<Vec<u8>> = Vec::new();

    for input_chunk in fuzzer_input.chunks(rnd_chunksize) {
        let (orion_tag, sodium_tag) = select_tag(seeded_rng);
        let ad = select_ad(input_chunk, seeded_rng);

        let mut orion_msg: Vec<u8> =
            vec![0u8; input_chunk.len() + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        let mut sodium_msg = orion_msg.clone();
        // Last message in the stream
        orion_state_enc
            .seal_chunk(input_chunk, Some(&ad), &mut orion_msg, orion_tag)
            .unwrap();

        sodium_state_enc
            .push_to_vec(input_chunk, Some(&ad), sodium_tag, &mut sodium_msg)
            .unwrap();

        assert_eq!(orion_msg, sodium_msg);
        collected_enc.extend_from_slice(&orion_msg);
        collected_ad.push(ad);

        // Finalizing a sodiumoxide state with Tag:Final consumes the stream.
        if sodium_tag == sodium_stream::Tag::Final {
            break;
        }
    }

    let mut orion_state_dec = SecretStreamXChaCha20Poly1305::new(
        &SecretKey::from_slice(&key[..]).unwrap(),
        &Nonce::from_slice(sodium_header.as_ref()).unwrap(),
    );

    let mut sodium_state_dec = sodium_stream::Stream::init_pull(
        &sodium_header,
        &sodium_stream::Key::from_slice(&key).unwrap(),
    )
    .unwrap();

    // `open_chunk()`
    let mut collected_dec: Vec<u8> = Vec::new();
    let dec_rnd_chunksize = rnd_chunksize + SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    for (idx, input_chunk) in collected_enc.chunks(dec_rnd_chunksize).enumerate() {
        let ad = collected_ad.get(idx).unwrap();
        
        let mut orion_msg: Vec<u8> =
            vec![0u8; input_chunk.len() - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];

        let _orion_tag = orion_state_dec
            .open_chunk(input_chunk, Some(ad), &mut orion_msg)
            .unwrap();

        let (sodium_msg, _sodium_tag) = sodium_state_dec.pull(input_chunk, Some(ad)).unwrap();
        assert_eq!(orion_msg, sodium_msg);
        collected_dec.extend_from_slice(&orion_msg);
    }

    assert_eq!(fuzzer_input, &collected_dec[..]);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::` // TODO: Missing
            fuzz_secret_stream(data, &mut seeded_rng);
        });
    }
}
