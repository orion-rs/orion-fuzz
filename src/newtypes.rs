use honggfuzz::fuzz;
use orion::generics::*;

/// Fuzz Public `TryFrom<&[u8]>` where arbitrary bytes make up
/// a valid type, only restricted by length.
pub fn fuzz_public_arbitrary_bytes<S: TypeSpec>(min: usize, max: usize, fuzzer_input: &[u8]) {
    if !(min..=max).contains(&fuzzer_input.len()) {
        assert!(Public::<S>::try_from(fuzzer_input).is_err()); // TryFrom<&[u8]>
        assert!(Public::<S>::try_from(&fuzzer_input.to_vec()).is_err()); // TryFrom<&Vec<u8>>
    } else {
        let public = Public::<S>::try_from(fuzzer_input).unwrap();
        assert_eq!(public, Public::<S>::try_from(fuzzer_input).unwrap());
        assert_eq!(public.as_ref(), fuzzer_input);
        assert_eq!(public, fuzzer_input); // PartialEq<&[u8]>
        assert!((min..=max).contains(&public.as_ref().len()));
        assert!((min..=max).contains(&public.len()));
        assert!(!public.is_empty());
    }
}

/// Fuzz Secret `TryFrom<&[u8]>` where arbitrary bytes make up
/// a valid type, only restricted by length.
pub fn fuzz_secret_arbitrary_bytes<S: TypeSpec>(min: usize, max: usize, fuzzer_input: &[u8]) {
    if !(min..=max).contains(&fuzzer_input.len()) {
        assert!(Secret::<S>::try_from(fuzzer_input).is_err()); // TryFrom<&[u8]>
        assert!(Secret::<S>::try_from(&fuzzer_input.to_vec()).is_err()); // TryFrom<&Vec<u8>>
    } else {
        let public = Secret::<S>::try_from(fuzzer_input).unwrap();
        assert_eq!(public, Secret::<S>::try_from(fuzzer_input).unwrap());
        assert_eq!(public.unprotected_as_ref(), fuzzer_input);
        assert_eq!(public, fuzzer_input); // PartialEq<&[u8]>
        assert!((min..=max).contains(&public.unprotected_as_ref().len()));
        assert!((min..=max).contains(&public.len()));
        assert!(!public.is_empty());
    }
}

pub mod typedefs {
    use super::*;

    // NOTE: These do not include:
    // - ML-KEM/X-Wing Encapsulation/Decapsulation keys with above generic functions
    // as they have additional input checking besides just length. These are instead
    // tested in kem.rs with TryFrom<&[u8]> on raw fuzzer output.
    // - PBKDF2 `Password` as they are simply `import as` for HMAC keys.

    pub fn fuzz_chacha20_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, ChaCha20Key};
        fuzz_secret_arbitrary_bytes::<ChaCha20Key>(CHACHA_KEYSIZE, CHACHA_KEYSIZE, fuzzer_input);
    }

    pub fn fuzz_chacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::chacha20::{ChaCha20Nonce, IETF_CHACHA_NONCESIZE};
        fuzz_public_arbitrary_bytes::<ChaCha20Nonce>(
            IETF_CHACHA_NONCESIZE,
            IETF_CHACHA_NONCESIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_xchacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::xchacha20::{XCHACHA_NONCESIZE, XChaCha20Nonce};
        fuzz_public_arbitrary_bytes::<XChaCha20Nonce>(
            XCHACHA_NONCESIZE,
            XCHACHA_NONCESIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_blake2b_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::blake2::blake2b::{
            BLAKE2B_MAX_OUTSIZE, BLAKE2B_MIN_OUTSIZE, Blake2bDigest,
        };
        fuzz_public_arbitrary_bytes::<Blake2bDigest>(
            BLAKE2B_MIN_OUTSIZE,
            BLAKE2B_MAX_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_blake2b_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::blake2b::{
            BLAKE2B_MAX_OUTSIZE, BLAKE2B_MIN_OUTSIZE, Blake2bTag,
        };
        fuzz_secret_arbitrary_bytes::<Blake2bTag>(
            BLAKE2B_MIN_OUTSIZE,
            BLAKE2B_MAX_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_blake2b_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::blake2b::{
            BLAKE2B_MAX_KEYSIZE, BLAKE2B_MIN_KEYSIZE, Blake2bKey,
        };
        fuzz_secret_arbitrary_bytes::<Blake2bKey>(
            BLAKE2B_MIN_KEYSIZE,
            BLAKE2B_MAX_KEYSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_sha256_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha256::{SHA256_OUTSIZE, Sha256Digest};
        fuzz_public_arbitrary_bytes::<Sha256Digest>(SHA256_OUTSIZE, SHA256_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_sha384_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha384::{SHA384_OUTSIZE, Sha384Digest};
        fuzz_public_arbitrary_bytes::<Sha384Digest>(SHA384_OUTSIZE, SHA384_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_sha512_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::{SHA512_OUTSIZE, Sha512Digest};
        fuzz_public_arbitrary_bytes::<Sha512Digest>(SHA512_OUTSIZE, SHA512_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_sha3_224_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha3::sha3_224::{SHA3_224_OUTSIZE, Sha3_224_Digest};
        fuzz_public_arbitrary_bytes::<Sha3_224_Digest>(
            SHA3_224_OUTSIZE,
            SHA3_224_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_sha3_256_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha3::sha3_256::{SHA3_256_OUTSIZE, Sha3_256_Digest};
        fuzz_public_arbitrary_bytes::<Sha3_256_Digest>(
            SHA3_256_OUTSIZE,
            SHA3_256_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_sha3_384_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha3::sha3_384::{SHA3_384_OUTSIZE, Sha3_384_Digest};
        fuzz_public_arbitrary_bytes::<Sha3_384_Digest>(
            SHA3_384_OUTSIZE,
            SHA3_384_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_sha3_512_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha3::sha3_512::{SHA3_512_OUTSIZE, Sha3_512_Digest};
        fuzz_public_arbitrary_bytes::<Sha3_512_Digest>(
            SHA3_512_OUTSIZE,
            SHA3_512_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_x25519_publickey(fuzzer_input: &[u8]) {
        use orion::hazardous::ecc::x25519::{PUBLIC_KEY_SIZE, X25519PublicKey};
        fuzz_public_arbitrary_bytes::<X25519PublicKey>(
            PUBLIC_KEY_SIZE,
            PUBLIC_KEY_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_x25519_privatekey(fuzzer_input: &[u8]) {
        use orion::hazardous::ecc::x25519::{PRIVATE_KEY_SIZE, X25519PrivateKey};
        fuzz_secret_arbitrary_bytes::<X25519PrivateKey>(
            PRIVATE_KEY_SIZE,
            PRIVATE_KEY_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_x25519_sharedsecret(fuzzer_input: &[u8]) {
        use orion::hazardous::ecc::x25519::{SHARED_KEY_SIZE, X25519SharedKey};
        fuzz_secret_arbitrary_bytes::<X25519SharedKey>(
            SHARED_KEY_SIZE,
            SHARED_KEY_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_hmac_sha256_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha256::{SHA256_BLOCKSIZE, SHA256_OUTSIZE, Sha256};
        use orion::hazardous::mac::hmac::sha256::SecretKey;

        // HMAC key is virtually unbounded as the padding/hashing happens on TryFrom<>.
        let sk = SecretKey::try_from(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA256_BLOCKSIZE {
            assert_eq!(&sk.unprotected_as_ref()[..fuzzer_input.len()], fuzzer_input);
        } else {
            let digest = Sha256::digest(fuzzer_input).unwrap();
            assert_eq!(&sk.unprotected_as_ref()[..SHA256_OUTSIZE], digest.as_ref());
        }

        assert_eq!(sk.unprotected_as_ref().len(), SHA256_BLOCKSIZE);
        assert_eq!(sk.len(), SHA256_BLOCKSIZE);
        assert!(!sk.is_empty());
    }

    pub fn fuzz_hmac_sha384_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha384::{SHA384_BLOCKSIZE, SHA384_OUTSIZE, Sha384};
        use orion::hazardous::mac::hmac::sha384::SecretKey;

        // HMAC key is virtually unbounded as the padding/hashing happens on TryFrom<>.
        let sk = SecretKey::try_from(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA384_BLOCKSIZE {
            assert_eq!(&sk.unprotected_as_ref()[..fuzzer_input.len()], fuzzer_input);
        } else {
            let digest = Sha384::digest(fuzzer_input).unwrap();
            assert_eq!(&sk.unprotected_as_ref()[..SHA384_OUTSIZE], digest.as_ref());
        }

        assert_eq!(sk.unprotected_as_ref().len(), SHA384_BLOCKSIZE);
        assert_eq!(sk.len(), SHA384_BLOCKSIZE);
        assert!(!sk.is_empty());
    }

    pub fn fuzz_hmac_sha512_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::{SHA512_BLOCKSIZE, SHA512_OUTSIZE, Sha512};
        use orion::hazardous::mac::hmac::sha512::SecretKey;

        // HMAC key is virtually unbounded as the padding/hashing happens on TryFrom<>.
        let sk = SecretKey::try_from(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA512_BLOCKSIZE {
            assert_eq!(&sk.unprotected_as_ref()[..fuzzer_input.len()], fuzzer_input);
        } else {
            let digest = Sha512::digest(fuzzer_input).unwrap();
            assert_eq!(&sk.unprotected_as_ref()[..SHA512_OUTSIZE], digest.as_ref());
        }

        assert_eq!(sk.unprotected_as_ref().len(), SHA512_BLOCKSIZE);
        assert_eq!(sk.len(), SHA512_BLOCKSIZE);
        assert!(!sk.is_empty());
    }

    pub fn fuzz_hmac_sha256_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
        use orion::hazardous::mac::hmac::sha256::HmacSha256Tag;
        fuzz_secret_arbitrary_bytes::<HmacSha256Tag>(SHA256_OUTSIZE, SHA256_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_hmac_sha384_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha384::SHA384_OUTSIZE;
        use orion::hazardous::mac::hmac::sha384::HmacSha384Tag;
        fuzz_secret_arbitrary_bytes::<HmacSha384Tag>(SHA384_OUTSIZE, SHA384_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_hmac_sha512_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;
        use orion::hazardous::mac::hmac::sha512::HmacSha512Tag;
        fuzz_secret_arbitrary_bytes::<HmacSha512Tag>(SHA512_OUTSIZE, SHA512_OUTSIZE, fuzzer_input);
    }

    pub fn fuzz_poly1305_onetime_key(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::poly1305::{POLY1305_KEYSIZE, Poly1305Key};
        fuzz_secret_arbitrary_bytes::<Poly1305Key>(
            POLY1305_KEYSIZE,
            POLY1305_KEYSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_poly1305_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::poly1305::{POLY1305_OUTSIZE, Poly1305Tag};
        fuzz_secret_arbitrary_bytes::<Poly1305Tag>(
            POLY1305_OUTSIZE,
            POLY1305_OUTSIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_xwing_keys(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::xwing::{DK_SIZE, XWingDecapKey};
        // X-Wing is equivalent to ML-KEM seed, so any byte slice is valid.
        fuzz_secret_arbitrary_bytes::<XWingDecapKey>(DK_SIZE, DK_SIZE, fuzzer_input);
    }

    pub fn fuzz_xwing_ciphertext(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::xwing::{CIPHERTEXT_SIZE, XWingCiphertext};
        fuzz_public_arbitrary_bytes::<XWingCiphertext>(
            CIPHERTEXT_SIZE,
            CIPHERTEXT_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_xwing_shared_secret(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::xwing::{SHARED_SECRET_SIZE, XWingSharedSecret};
        fuzz_secret_arbitrary_bytes::<XWingSharedSecret>(
            SHARED_SECRET_SIZE,
            SHARED_SECRET_SIZE,
            fuzzer_input,
        );
    }

    /// `EncapsulationKey`/`DecapsulationKey` are fuzzed as part of `kem::fuzz_keys()`.
    pub fn fuzz_mlkem512_seed(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem512::{MlKemSeed, SEED_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKemSeed>(SEED_SIZE, SEED_SIZE, fuzzer_input);
    }

    pub fn fuzz_mlkem512_ciphertext(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem512::{CIPHERTEXT_SIZE, Mlkem512Ciphertext};
        fuzz_public_arbitrary_bytes::<Mlkem512Ciphertext>(
            CIPHERTEXT_SIZE,
            CIPHERTEXT_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_mlkem512_shared_secret(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem512::{MlKem512SharedSecret, SHARED_SECRET_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKem512SharedSecret>(
            SHARED_SECRET_SIZE,
            SHARED_SECRET_SIZE,
            fuzzer_input,
        );
    }

    /// `EncapsulationKey`/`DecapsulationKey` are fuzzed as part of `kem::fuzz_keys()`.
    pub fn fuzz_mlkem768_seed(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem768::{MlKemSeed, SEED_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKemSeed>(SEED_SIZE, SEED_SIZE, fuzzer_input);
    }

    pub fn fuzz_mlkem768_ciphertext(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem768::{CIPHERTEXT_SIZE, Mlkem768Ciphertext};
        fuzz_public_arbitrary_bytes::<Mlkem768Ciphertext>(
            CIPHERTEXT_SIZE,
            CIPHERTEXT_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_mlkem768_shared_secret(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem768::{MlKem768SharedSecret, SHARED_SECRET_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKem768SharedSecret>(
            SHARED_SECRET_SIZE,
            SHARED_SECRET_SIZE,
            fuzzer_input,
        );
    }

    /// `EncapsulationKey`/`DecapsulationKey` are fuzzed as part of `kem::fuzz_keys()`.
    pub fn fuzz_mlkem1024_seed(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem1024::{MlKemSeed, SEED_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKemSeed>(SEED_SIZE, SEED_SIZE, fuzzer_input);
    }

    pub fn fuzz_mlkem1024_ciphertext(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem1024::{CIPHERTEXT_SIZE, Mlkem1024Ciphertext};
        fuzz_public_arbitrary_bytes::<Mlkem1024Ciphertext>(
            CIPHERTEXT_SIZE,
            CIPHERTEXT_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_mlkem1024_shared_secret(fuzzer_input: &[u8]) {
        use orion::hazardous::kem::mlkem1024::{MlKem1024SharedSecret, SHARED_SECRET_SIZE};
        fuzz_secret_arbitrary_bytes::<MlKem1024SharedSecret>(
            SHARED_SECRET_SIZE,
            SHARED_SECRET_SIZE,
            fuzzer_input,
        );
    }

    pub fn fuzz_argon2_password_hash(fuzzer_input: &[u8]) {
        use orion::hazardous::kdf::argon2::PasswordHash;

        if let Ok(hash) = PasswordHash::try_from(fuzzer_input) {
            assert_eq!(hash.unprotected_as_ref::<[u8]>(), fuzzer_input);
            assert!(!hash.is_empty());
        }
    }

    pub fn fuzz_scrypt_password_hash(fuzzer_input: &[u8]) {
        use orion::hazardous::kdf::scrypt::PasswordHash;

        if let Ok(hash) = PasswordHash::try_from(fuzzer_input) {
            assert_eq!(hash.unprotected_as_ref::<[u8]>(), fuzzer_input);
            assert!(!hash.is_empty());
        }
    }
}

pub mod hltypes {
    macro_rules! fuzz_type_variable_length {
        ($fuzz_name:ident, $type:ident, $as_ref_func:ident) => {
            pub fn $fuzz_name(fuzzer_input: &[u8]) {
                if fuzzer_input.is_empty() {
                    assert!($type::try_from(fuzzer_input).is_err());
                } else {
                    let sk = $type::try_from(fuzzer_input).unwrap();

                    assert_eq!(sk.$as_ref_func(), fuzzer_input);
                    assert_eq!(sk, fuzzer_input);
                    assert_eq!(sk.$as_ref_func().len(), fuzzer_input.len());
                    assert_eq!(sk.len(), fuzzer_input.len());
                    assert!(!sk.is_empty());
                }
            }
        };
    }

    use orion::aead::SecretKey;
    use orion::kdf::Salt;
    use orion::pwhash::Password;

    fuzz_type_variable_length!(fuzz_secret_key, SecretKey, unprotected_as_ref);
    fuzz_type_variable_length!(fuzz_salt, Salt, as_ref);
    fuzz_type_variable_length!(fuzz_password, Password, unprotected_as_ref);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // typedefs
            typedefs::fuzz_chacha20_secret_key(data);
            typedefs::fuzz_chacha20_nonce(data);
            typedefs::fuzz_xchacha20_nonce(data);
            typedefs::fuzz_blake2b_digest(data);
            typedefs::fuzz_blake2b_tag(data);
            typedefs::fuzz_blake2b_secret_key(data);
            typedefs::fuzz_sha256_digest(data);
            typedefs::fuzz_sha384_digest(data);
            typedefs::fuzz_sha512_digest(data);
            typedefs::fuzz_sha3_224_digest(data);
            typedefs::fuzz_sha3_256_digest(data);
            typedefs::fuzz_sha3_384_digest(data);
            typedefs::fuzz_sha3_512_digest(data);
            typedefs::fuzz_x25519_publickey(data);
            typedefs::fuzz_x25519_privatekey(data);
            typedefs::fuzz_x25519_sharedsecret(data);
            typedefs::fuzz_hmac_sha256_secret_key(data);
            typedefs::fuzz_hmac_sha384_secret_key(data);
            typedefs::fuzz_hmac_sha512_secret_key(data);
            typedefs::fuzz_hmac_sha256_tag(data);
            typedefs::fuzz_hmac_sha384_tag(data);
            typedefs::fuzz_hmac_sha512_tag(data);
            typedefs::fuzz_poly1305_onetime_key(data);
            typedefs::fuzz_poly1305_tag(data);
            typedefs::fuzz_xwing_keys(data);
            typedefs::fuzz_xwing_ciphertext(data);
            typedefs::fuzz_xwing_shared_secret(data);
            typedefs::fuzz_mlkem512_seed(data);
            typedefs::fuzz_mlkem512_ciphertext(data);
            typedefs::fuzz_mlkem512_shared_secret(data);
            typedefs::fuzz_mlkem768_seed(data);
            typedefs::fuzz_mlkem768_ciphertext(data);
            typedefs::fuzz_mlkem768_shared_secret(data);
            typedefs::fuzz_mlkem1024_seed(data);
            typedefs::fuzz_mlkem1024_ciphertext(data);
            typedefs::fuzz_mlkem1024_shared_secret(data);
            typedefs::fuzz_argon2_password_hash(data);
            typedefs::fuzz_scrypt_password_hash(data);

            // hltypes
            hltypes::fuzz_secret_key(data);
            hltypes::fuzz_password(data);
            hltypes::fuzz_salt(data);
        });
    }
}
