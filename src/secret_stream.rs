#[macro_use]
extern crate honggfuzz;
extern crate orion;
extern crate sodiumoxide;
pub mod utils;

use utils::{make_seeded_rng, ChaChaRng, RngCore};

use orion::hazardous::secret_stream::xchacha20poly1305::*;
use orion::hazardous::stream::chacha20::SecretKey;

use sodiumoxide::crypto::secretstream::xchacha20poly1305 as sodium_stream;

/// `orion::hazardous::` // TODO: Missing
fn fuzz_secret_stream(fuzzer_input: &[u8], seeded_rng: &mut ChaChaRng) {
    if fuzzer_input.is_empty() {
        return;
    }

    let mut key = vec![0u8; 32];
    seeded_rng.fill_bytes(&mut key);

    // `ad` will be both tested as Some and None as None is the same as [0u8; 0]
    let ad: Vec<u8> = if fuzzer_input.is_empty() {
        vec![0u8; 0]
    } else if fuzzer_input[0] > 127 {
        let mut tmp = vec![0u8; fuzzer_input.len() / 8];
        seeded_rng.fill_bytes(&mut tmp);
        tmp
    } else {
        vec![0u8; 0]
    };

    let (mut sodium_state_enc, sodium_header) =
        sodium_stream::Stream::init_push(&sodium_stream::Key::from_slice(&key).unwrap()).unwrap();

    let mut orion_state_enc = SecretStreamXChaCha20Poly1305::new(
        &SecretKey::from_slice(&key[..]).unwrap(),
        &Nonce::from_slice(sodium_header.as_ref()).unwrap(),
    );

    // Push/Encrypt
    let rnd_chunksize = seeded_rng.next_u32() as usize;
    let mut collected_enc: Vec<u8> = Vec::new();

    for (idx, input_chunk) in fuzzer_input.chunks(rnd_chunksize).enumerate() {
        let mut orion_msg: Vec<u8> =
            vec![0u8; input_chunk.len() + SECRETSTREAM_XCHACHA20POLY1305_ABYTES];
        let mut sodium_msg = orion_msg.clone();

        if input_chunk.len() < rnd_chunksize
            || (input_chunk.len() * (idx + 1) == fuzzer_input.len())
        {
            // Last message in the stream
            orion_state_enc
                .encrypt_message(input_chunk, Some(&ad), &mut orion_msg, Tag::FINISH)
                .unwrap();

            sodium_state_enc
                .push_to_vec(
                    input_chunk,
                    Some(&ad),
                    sodium_stream::Tag::Final,
                    &mut sodium_msg,
                )
                .unwrap();
        } else {
            orion_state_enc
                .encrypt_message(input_chunk, Some(&ad), &mut orion_msg, Tag::MESSAGE)
                .unwrap();

            sodium_state_enc
                .push_to_vec(
                    input_chunk,
                    Some(&ad),
                    sodium_stream::Tag::Message,
                    &mut sodium_msg,
                )
                .unwrap();
        }

        assert_eq!(orion_msg, sodium_msg);
        collected_enc.extend_from_slice(&orion_msg);
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

    let mut collected_dec: Vec<u8> = Vec::new();
    let dec_rnd_chunksize = rnd_chunksize + SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    for (idx, input_chunk) in collected_enc.chunks(dec_rnd_chunksize).enumerate() {
        let mut orion_msg: Vec<u8> =
            vec![0u8; input_chunk.len() - SECRETSTREAM_XCHACHA20POLY1305_ABYTES];

        let orion_tag = orion_state_dec
            .decrypt_message(input_chunk, Some(&ad), &mut orion_msg)
            .unwrap();

        let (sodium_msg, _sodium_tag) = sodium_state_dec.pull(input_chunk, Some(&ad)).unwrap();

        if input_chunk.len() < dec_rnd_chunksize
            || (input_chunk.len() * (idx + 1) == collected_enc.len())
        {
            // Last message in the stream
            assert_eq!(orion_tag, Tag::FINISH);
        } else {
            assert_eq!(orion_tag, Tag::MESSAGE);
        }

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
