#[macro_use]
extern crate honggfuzz;
use core::fmt::Debug;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::convert::TryFrom;

fn fuzz_serde_impl<'a, T: Serialize + DeserializeOwned + PartialEq + Debug + TryFrom<&'a [u8]>>(
    fuzzer_input: &'a [u8],
) {
    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding();

    // Test that serialize->deserialize roundtrip starting from a valid newtype always passes.
    if let Ok(newtype_from_bytes) = T::try_from(fuzzer_input) {
        let serialized = bincode::serde::encode_to_vec(&newtype_from_bytes, config)
            .expect("Failed to serialize a newtype that was successful with try_from()");
        let newtype_roundtrip: (T, _) =
            bincode::serde::decode_from_slice(serialized.as_slice(), config)
                .expect("Failed to deserialized a valid serialized type");
        assert_eq!(
            newtype_from_bytes, newtype_roundtrip.0,
            "Roundtrip gave different newtypes"
        );
    }
}

fn fuzz_serde_impl_password_hash(fuzzer_input: &[u8]) {
    use orion::pwhash::PasswordHash;

    let config = bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding();

    let input = String::from_utf8_lossy(fuzzer_input).into_owned();
    if let Ok(newtype) = PasswordHash::from_encoded(&input) {
        match (
            bincode::serde::encode_to_vec(&fuzzer_input, config),
            bincode::serde::encode_to_vec(&newtype, config),
        ) {
            (Ok(from_raw), Ok(from_type)) => {
                assert_eq!(from_raw, from_type);
                let newtype_roundtrip: (PasswordHash, _) =
                    bincode::serde::decode_from_slice(from_raw.as_slice(), config)
                        .expect("Failed to deserialized a valid serialized type");
                assert_eq!(newtype_roundtrip.0, newtype);
            }
            _ => panic!("Failed serialization after successful try_from()"),
        }
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            fuzz_serde_impl::<orion::hazardous::ecc::x25519::PublicKey>(data);
            fuzz_serde_impl::<orion::hazardous::stream::chacha20::Nonce>(data);
            fuzz_serde_impl::<orion::hazardous::stream::xchacha20::Nonce>(data);
            fuzz_serde_impl::<orion::hazardous::mac::poly1305::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::hash::blake2::blake2b::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha2::sha256::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha2::sha384::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha2::sha512::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha256::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha384::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha512::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::blake2b::Tag>(data);
            fuzz_serde_impl::<orion::kdf::Salt>(data);
            fuzz_serde_impl::<orion::auth::Tag>(data);

            fuzz_serde_impl_password_hash(data);
        });
    }
}
