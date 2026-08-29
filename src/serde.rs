use core::fmt::Debug;
use honggfuzz::fuzz;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::convert::TryFrom;

fn fuzz_serde_impl<'a, T: Serialize + DeserializeOwned + PartialEq + Debug + TryFrom<&'a [u8]>>(
    fuzzer_input: &'a [u8],
) {
    // Test that serialize->deserialize roundtrip starting from a valid newtype always passes.
    if let Ok(newtype_from_bytes) = T::try_from(fuzzer_input) {
        let serialized = bincode::serialize(&newtype_from_bytes)
            .expect("Failed to serialize a newtype that was successful with try_from()");
        let newtype_roundtrip: T = bincode::deserialize(&serialized)
            .expect("Failed to deserialized a valid serialized type");
        assert_eq!(
            newtype_from_bytes, newtype_roundtrip,
            "Roundtrip gave different newtypes"
        );
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
            fuzz_serde_impl::<orion::hazardous::hash::sha3::sha3_224::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha3::sha3_256::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha3::sha3_384::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::hash::sha3::sha3_512::Digest>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha256::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha384::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::hmac::sha512::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::blake2b::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::mac::blake3::Tag>(data);
            fuzz_serde_impl::<orion::kdf::Salt>(data);
            fuzz_serde_impl::<orion::auth::Tag>(data);
            fuzz_serde_impl::<orion::hazardous::kdf::argon2::PasswordHash>(data);
            fuzz_serde_impl::<orion::hazardous::kdf::scrypt::PasswordHash>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa44::VerifyingKey>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa44::Signature>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa65::VerifyingKey>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa65::Signature>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa87::VerifyingKey>(data);
            fuzz_serde_impl::<orion::hazardous::dsa::mldsa87::Signature>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem512::EncapsulationKey>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem512::Ciphertext>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem768::EncapsulationKey>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem768::Ciphertext>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem1024::EncapsulationKey>(data);
            fuzz_serde_impl::<orion::hazardous::kem::mlkem1024::Ciphertext>(data);
            fuzz_serde_impl::<orion::hazardous::kem::xwing::EncapsulationKey>(data);
            fuzz_serde_impl::<orion::hazardous::kem::xwing::Ciphertext>(data);
        });
    }
}
