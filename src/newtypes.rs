#[macro_use]
extern crate honggfuzz;
extern crate orion;

pub mod typedefs {

    pub fn fuzz_chacha20_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::chacha20::{SecretKey, CHACHA_KEYSIZE};

        if fuzzer_input.len() != CHACHA_KEYSIZE {
            assert!(SecretKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = SecretKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk, fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), CHACHA_KEYSIZE);
            assert_eq!(sk.len(), CHACHA_KEYSIZE);
            assert!(!sk.is_empty());
        }

        let sk_rand = SecretKey::generate();

        assert_ne!(sk_rand.unprotected_as_bytes(), &[0u8; CHACHA_KEYSIZE]);
        assert_ne!(sk_rand, [0u8; CHACHA_KEYSIZE].as_ref());
        assert_eq!(sk_rand.unprotected_as_bytes().len(), CHACHA_KEYSIZE);
        assert_eq!(sk_rand.len(), CHACHA_KEYSIZE);
        assert!(!sk_rand.is_empty());
    }

    pub fn fuzz_chacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::chacha20::{Nonce, IETF_CHACHA_NONCESIZE};

        if fuzzer_input.len() != IETF_CHACHA_NONCESIZE {
            assert!(Nonce::from_slice(fuzzer_input).is_err());
        } else {
            let nonce = Nonce::from_slice(fuzzer_input).unwrap();

            assert_eq!(nonce.as_ref(), fuzzer_input);
            assert_eq!(nonce, fuzzer_input);
            assert_eq!(nonce.as_ref().len(), IETF_CHACHA_NONCESIZE);
            assert_eq!(nonce.len(), IETF_CHACHA_NONCESIZE);
            assert!(!nonce.is_empty());
        }
    }

    pub fn fuzz_xchacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::stream::xchacha20::{Nonce, XCHACHA_NONCESIZE};

        if fuzzer_input.len() != XCHACHA_NONCESIZE {
            assert!(Nonce::from_slice(fuzzer_input).is_err());
        } else {
            let nonce = Nonce::from_slice(fuzzer_input).unwrap();

            assert_eq!(nonce.as_ref(), fuzzer_input);
            assert_eq!(nonce, fuzzer_input);
            assert_eq!(nonce.as_ref().len(), XCHACHA_NONCESIZE);
            assert_eq!(nonce.len(), XCHACHA_NONCESIZE);
            assert!(!nonce.is_empty());
        }

        let nonce_rand = Nonce::generate();

        assert_ne!(nonce_rand.as_ref(), &[0u8; XCHACHA_NONCESIZE]);
        assert_ne!(nonce_rand, [0u8; XCHACHA_NONCESIZE].as_ref());
        assert_eq!(nonce_rand.as_ref().len(), XCHACHA_NONCESIZE);
        assert_eq!(nonce_rand.len(), XCHACHA_NONCESIZE);
        assert!(!nonce_rand.is_empty());
    }

    pub fn fuzz_blake2b_digest(fuzzer_input: &[u8]) {
        const BLAKE2B_OUTSIZE: usize = 64;
        use orion::hazardous::hash::blake2b::Digest;

        if fuzzer_input.is_empty() || fuzzer_input.len() > BLAKE2B_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_ref(), fuzzer_input);
            assert_eq!(hash, fuzzer_input);
            assert_eq!(hash.as_ref().len(), fuzzer_input.len());
            assert_eq!(hash.len(), fuzzer_input.len());
            assert!(!hash.is_empty());
        }
    }

    pub fn fuzz_blake2b_secret_key(fuzzer_input: &[u8]) {
        const BLAKE2B_KEYSIZE: usize = 64;
        use orion::hazardous::hash::blake2b::SecretKey;

        if fuzzer_input.is_empty() || fuzzer_input.len() > BLAKE2B_KEYSIZE {
            assert!(SecretKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = SecretKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk, fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), fuzzer_input.len());
            assert_eq!(sk.len(), fuzzer_input.len());
            assert!(!sk.is_empty());
        }

        let sk_rand = SecretKey::generate();
        assert_ne!(
            sk_rand.unprotected_as_bytes(),
            [0u8; BLAKE2B_KEYSIZE].as_ref()
        );

        assert_ne!(sk_rand, [0u8; BLAKE2B_KEYSIZE].as_ref());
        assert_eq!(sk_rand.unprotected_as_bytes().len(), BLAKE2B_KEYSIZE / 2);
        assert_eq!(sk_rand.len(), BLAKE2B_KEYSIZE / 2);
        assert!(!sk_rand.is_empty());
    }

    pub fn fuzz_sha256_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha256::{Digest, SHA256_OUTSIZE};

        if fuzzer_input.len() != SHA256_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_ref(), fuzzer_input);
            assert_eq!(hash, fuzzer_input);
            assert_eq!(hash.as_ref().len(), fuzzer_input.len());
            assert_eq!(hash.len(), fuzzer_input.len());
            assert!(!hash.is_empty());
        }
    }

    pub fn fuzz_sha384_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha384::{Digest, SHA384_OUTSIZE};

        if fuzzer_input.len() != SHA384_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_ref(), fuzzer_input);
            assert_eq!(hash, fuzzer_input);
            assert_eq!(hash.as_ref().len(), fuzzer_input.len());
            assert_eq!(hash.len(), fuzzer_input.len());
            assert!(!hash.is_empty());
        }
    }

    pub fn fuzz_sha512_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::{Digest, SHA512_OUTSIZE};

        if fuzzer_input.len() != SHA512_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_ref(), fuzzer_input);
            assert_eq!(hash, fuzzer_input);
            assert_eq!(hash.as_ref().len(), fuzzer_input.len());
            assert_eq!(hash.len(), fuzzer_input.len());
            assert!(!hash.is_empty());
        }
    }

    pub fn fuzz_pbkdf2_sha512_password(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::{Sha512, SHA512_BLOCKSIZE, SHA512_OUTSIZE};
        use orion::hazardous::kdf::pbkdf2::sha512::Password;

        let password = Password::from_slice(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA512_BLOCKSIZE {
            assert_eq!(
                &password.unprotected_as_bytes()[..fuzzer_input.len()],
                fuzzer_input
            );
        } else {
            let digest = Sha512::digest(fuzzer_input).unwrap();
            assert_eq!(
                &password.unprotected_as_bytes()[..SHA512_OUTSIZE],
                digest.as_ref()
            );
        }

        assert_eq!(password.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(password.len(), SHA512_BLOCKSIZE);
        assert!(!password.is_empty());

        let password_rand = Password::generate();

        assert_ne!(
            &password_rand.unprotected_as_bytes(),
            &[0u8; SHA512_BLOCKSIZE].as_ref()
        );
        assert_ne!(password_rand, [0u8; SHA512_BLOCKSIZE].as_ref());
        assert_eq!(password_rand.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(password_rand.len(), SHA512_BLOCKSIZE);
        assert!(!password_rand.is_empty());
    }

    pub fn fuzz_hmac_sha512_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::{Sha512, SHA512_BLOCKSIZE, SHA512_OUTSIZE};
        use orion::hazardous::mac::hmac::sha512::SecretKey;

        let sk = SecretKey::from_slice(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA512_BLOCKSIZE {
            assert_eq!(
                &sk.unprotected_as_bytes()[..fuzzer_input.len()],
                fuzzer_input
            );
        } else {
            let digest = Sha512::digest(fuzzer_input).unwrap();
            assert_eq!(
                &sk.unprotected_as_bytes()[..SHA512_OUTSIZE],
                digest.as_ref()
            );
        }

        assert_eq!(sk.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(sk.len(), SHA512_BLOCKSIZE);
        assert!(!sk.is_empty());

        let sk_rand = SecretKey::generate();

        assert_ne!(
            &sk_rand.unprotected_as_bytes(),
            &[0u8; SHA512_BLOCKSIZE].as_ref()
        );
        assert_ne!(sk_rand, [0u8; SHA512_BLOCKSIZE].as_ref());
        assert_eq!(sk_rand.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(sk_rand.len(), SHA512_BLOCKSIZE);
        assert!(!sk_rand.is_empty());
    }

    pub fn fuzz_hmac_sha512_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::hash::sha2::sha512::SHA512_OUTSIZE;
        use orion::hazardous::mac::hmac::sha512::Tag;

        if fuzzer_input.len() != SHA512_OUTSIZE {
            assert!(Tag::from_slice(fuzzer_input).is_err());
        } else {
            let tag = Tag::from_slice(fuzzer_input).unwrap();

            assert_eq!(tag.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(tag, fuzzer_input);
            assert_eq!(tag.unprotected_as_bytes().len(), SHA512_OUTSIZE);
            assert_eq!(tag.len(), SHA512_OUTSIZE);
            assert!(!tag.is_empty());
        }
    }

    pub fn fuzz_poly1305_onetime_key(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::poly1305::{OneTimeKey, POLY1305_KEYSIZE};

        if fuzzer_input.len() != POLY1305_KEYSIZE {
            assert!(OneTimeKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = OneTimeKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk, fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), POLY1305_KEYSIZE);
            assert_eq!(sk.len(), POLY1305_KEYSIZE);
            assert!(!sk.is_empty());
        }

        let sk_rand = OneTimeKey::generate();

        assert_ne!(sk_rand.unprotected_as_bytes(), &[0u8; POLY1305_KEYSIZE]);
        assert_ne!(sk_rand, [0u8; POLY1305_KEYSIZE].as_ref());
        assert_eq!(sk_rand.unprotected_as_bytes().len(), POLY1305_KEYSIZE);
        assert_eq!(sk_rand.len(), POLY1305_KEYSIZE);
        assert!(!sk_rand.is_empty());
    }

    pub fn fuzz_poly1305_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::mac::poly1305::{Tag, POLY1305_OUTSIZE};

        if fuzzer_input.len() != POLY1305_OUTSIZE {
            assert!(Tag::from_slice(fuzzer_input).is_err());
        } else {
            let tag = Tag::from_slice(fuzzer_input).unwrap();

            assert_eq!(tag.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(tag, fuzzer_input);
            assert_eq!(tag.unprotected_as_bytes().len(), POLY1305_OUTSIZE);
            assert_eq!(tag.len(), POLY1305_OUTSIZE);
            assert!(!tag.is_empty());
        }
    }
}

pub mod hltypes {
    macro_rules! fuzz_type_variable_length {
        ($fuzz_name:ident, $type:ident, $as_ref_func:ident) => {
            pub fn $fuzz_name(fuzzer_input: &[u8]) {
                if fuzzer_input.is_empty() {
                    assert!($type::from_slice(fuzzer_input).is_err());
                } else {
                    let sk = $type::from_slice(fuzzer_input).unwrap();

                    assert_eq!(sk.$as_ref_func(), fuzzer_input);
                    assert_eq!(sk, fuzzer_input);
                    assert_eq!(sk.$as_ref_func().len(), fuzzer_input.len());
                    assert_eq!(sk.len(), fuzzer_input.len());
                    assert!(!sk.is_empty());
                }

                // NOTE: This only tests lengths 1..=255
                let length = if fuzzer_input.is_empty() {
                    32
                } else {
                    fuzzer_input[0] as usize
                };

                if length == 0 {
                    assert!($type::generate(length).is_err());
                } else {
                    let sk_rand = $type::generate(length);

                    if sk_rand.is_ok() {
                        // Don't compare with a SecretKey of 0's because if length is low enough
                        // it might happen to actually generate one where the first bytes
                        // are 0.
                        let sk_actual = sk_rand.unwrap();
                        assert_eq!(sk_actual.$as_ref_func().len(), length);
                        assert_eq!(sk_actual.len(), length);
                        assert!(!sk_actual.is_empty());
                    }
                }
            }
        };
    }

    use orion::aead::SecretKey;
    use orion::kdf::Salt;
    use orion::pwhash::Password;

    fuzz_type_variable_length!(fuzz_secret_key, SecretKey, unprotected_as_bytes);
    fuzz_type_variable_length!(fuzz_salt, Salt, as_ref);
    fuzz_type_variable_length!(fuzz_password, Password, unprotected_as_bytes);

    pub fn fuzz_passwordhash(fuzzer_input: &[u8]) {
        use orion::pwhash::PasswordHash;

        let input = String::from_utf8_lossy(fuzzer_input);
        match PasswordHash::from_encoded(&input) {
            Ok(hash) => {
                assert_eq!(hash.unprotected_as_encoded(), input);
                assert!(!hash.is_empty());
            }
            Err(orion::errors::UnknownCryptoError) => (),
        }
    }
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // typedefs

            typedefs::fuzz_chacha20_secret_key(data);

            typedefs::fuzz_chacha20_nonce(data);

            typedefs::fuzz_xchacha20_nonce(data);

            typedefs::fuzz_blake2b_secret_key(data);

            typedefs::fuzz_blake2b_digest(data);

            typedefs::fuzz_sha512_digest(data);

            typedefs::fuzz_pbkdf2_sha512_password(data);

            typedefs::fuzz_hmac_sha512_secret_key(data);

            typedefs::fuzz_hmac_sha512_tag(data);

            typedefs::fuzz_poly1305_onetime_key(data);

            typedefs::fuzz_poly1305_tag(data);

            // hltypes

            hltypes::fuzz_secret_key(data);

            hltypes::fuzz_password(data);

            hltypes::fuzz_salt(data);

            hltypes::fuzz_passwordhash(data);
        });
    }
}
