use honggfuzz::fuzz;
pub mod utils;

use core::convert::TryFrom;
use orion::hazardous::aead::streaming::*;
use orion::hazardous::stream::chacha20::SecretKey;
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as sodium_stream;
use std::cmp::max;
use utils::*;

/// Randomly select which tag should be passed to sealing a chunk.
fn select_tag(seeded_rng: &mut ChaCha8Rng) -> (StreamTag, sodium_stream::Tag) {
    let rnd_choice: u8 = seeded_rng.random_range(0..4);

    let orion_tag = StreamTag::try_from(rnd_choice).expect("UNEXPECTED: RNG range number invalid");
    let other_tag = match rnd_choice {
        0 => sodium_stream::Tag::Message,
        1 => sodium_stream::Tag::Push,
        2 => sodium_stream::Tag::Rekey,
        3 => sodium_stream::Tag::Final,
        _ => panic!("SeededRng could generated number out of bounds"),
    };

    (orion_tag, other_tag)
}

fn fuzz_secret_stream(fuzzer_input: &[u8], seeded_rng: &mut ChaCha8Rng) {
    let mut key = vec![0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    let (mut sodium_state_enc, sodium_header) =
        sodium_stream::Stream::init_push(&sodium_stream::Key::from_slice(&key).unwrap()).unwrap();

    let mut orion_state_enc = StreamXChaCha20Poly1305::new(
        &SecretKey::try_from(&key[..]).unwrap(),
        &Nonce::try_from(sodium_header.as_ref()).unwrap(),
    );

    // `seal_chunk()`
    let rnd_chunksize: usize = seeded_rng.random_range(1..=max(1, fuzzer_input.len()));
    let mut collected_chunks: Vec<Vec<u8>> = Vec::new();
    let mut collected_ad: Vec<Vec<u8>> = Vec::new();

    for input_chunk in fuzzer_input.chunks(rnd_chunksize) {
        let (orion_tag, sodium_tag) = select_tag(seeded_rng);
        let ad = rand_vec_in_range(seeded_rng, 0, 64);

        let mut orion_msg: Vec<u8> = vec![0u8; input_chunk.len() + ABYTES];
        let mut sodium_msg = orion_msg.clone();
        // Last message in the stream
        orion_state_enc
            .seal_chunk(input_chunk, Some(&ad), &mut orion_msg, &orion_tag)
            .unwrap();

        sodium_state_enc
            .push_to_vec(input_chunk, Some(&ad), sodium_tag, &mut sodium_msg)
            .unwrap();

        assert_eq!(orion_msg, sodium_msg);
        collected_chunks.push(orion_msg);
        collected_ad.push(ad);

        // Finalizing a sodiumoxide state with Tag:Final consumes the stream.
        if sodium_tag == sodium_stream::Tag::Final {
            break;
        }
    }

    let mut orion_state_dec = StreamXChaCha20Poly1305::new(
        &SecretKey::try_from(&key[..]).unwrap(),
        &Nonce::try_from(sodium_header.as_ref()).unwrap(),
    );

    let mut sodium_state_dec = sodium_stream::Stream::init_pull(
        &sodium_header,
        &sodium_stream::Key::from_slice(&key).unwrap(),
    )
    .unwrap();

    // `open_chunk()`
    for (input_chunk, ad) in collected_chunks.iter().zip(collected_ad.iter()) {
        let mut orion_msg: Vec<u8> = vec![0u8; input_chunk.len() - ABYTES];
        let _orion_tag = orion_state_dec
            .open_chunk(input_chunk, Some(ad), &mut orion_msg)
            .unwrap();

        let (sodium_msg, _sodium_tag) = sodium_state_dec.pull(input_chunk, Some(ad)).unwrap();
        assert_eq!(orion_msg, sodium_msg);
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // Seed the RNG
            let mut seeded_rng = make_seeded_rng(data);

            // Test `orion::hazardous::aead::streaming`
            fuzz_secret_stream(data, &mut seeded_rng);
        });
    }
}
