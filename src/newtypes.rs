#[macro_use]
extern crate honggfuzz;
extern crate orion;

pub mod typedefs {
    use super::*;

    pub fn fuzz_chacha20_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::CHACHA_KEYSIZE;
        use orion::hazardous::stream::chacha20::SecretKey;

        if fuzzer_input.len() != CHACHA_KEYSIZE {
            assert!(SecretKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = SecretKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), CHACHA_KEYSIZE);
            assert_eq!(sk.get_length(), CHACHA_KEYSIZE);
        }

        let sk_rand = SecretKey::generate();

        if sk_rand.is_ok() {
            let sk_actual = sk_rand.unwrap();
            assert_ne!(sk_actual.unprotected_as_bytes(), &[0u8; CHACHA_KEYSIZE]);
            assert_eq!(sk_actual.unprotected_as_bytes().len(), CHACHA_KEYSIZE);
            assert_eq!(sk_actual.get_length(), CHACHA_KEYSIZE);
        }
    }

    pub fn fuzz_chacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::IETF_CHACHA_NONCESIZE;
        use orion::hazardous::stream::chacha20::Nonce;

        if fuzzer_input.len() != IETF_CHACHA_NONCESIZE {
            assert!(Nonce::from_slice(fuzzer_input).is_err());
        } else {
            let nonce = Nonce::from_slice(fuzzer_input).unwrap();

            assert_eq!(nonce.as_bytes(), fuzzer_input);
            assert_eq!(nonce.as_bytes().len(), IETF_CHACHA_NONCESIZE);
            assert_eq!(nonce.get_length(), IETF_CHACHA_NONCESIZE);
        }
    }

    pub fn fuzz_xchacha20_nonce(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::XCHACHA_NONCESIZE;
        use orion::hazardous::stream::xchacha20::Nonce;

        if fuzzer_input.len() != XCHACHA_NONCESIZE {
            assert!(Nonce::from_slice(fuzzer_input).is_err());
        } else {
            let nonce = Nonce::from_slice(fuzzer_input).unwrap();

            assert_eq!(nonce.as_bytes(), fuzzer_input);
            assert_eq!(nonce.as_bytes().len(), XCHACHA_NONCESIZE);
            assert_eq!(nonce.get_length(), XCHACHA_NONCESIZE);
        }

        let nonce_rand = Nonce::generate();

        if nonce_rand.is_ok() {
            let nonce_actual = nonce_rand.unwrap();
            assert_ne!(nonce_actual.as_bytes(), &[0u8; XCHACHA_NONCESIZE]);
            assert_eq!(nonce_actual.as_bytes().len(), XCHACHA_NONCESIZE);
            assert_eq!(nonce_actual.get_length(), XCHACHA_NONCESIZE);
        }
    }

    pub fn fuzz_blake2b_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::BLAKE2B_OUTSIZE;
        use orion::hazardous::hash::blake2b::Digest;

        if fuzzer_input.len() < 1 || fuzzer_input.len() > BLAKE2B_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_bytes(), fuzzer_input);
            assert_eq!(hash.as_bytes().len(), fuzzer_input.len());
            assert_eq!(hash.get_length(), fuzzer_input.len());
        }
    }

    pub fn fuzz_blake2b_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::{BLAKE2B_BLOCKSIZE, BLAKE2B_KEYSIZE};
        use orion::hazardous::hash::blake2b::SecretKey;

        if fuzzer_input.len() < 1 || fuzzer_input.len() > BLAKE2B_KEYSIZE {
            assert!(SecretKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = SecretKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(
                &sk.unprotected_as_bytes()[..sk.get_original_length()],
                fuzzer_input
            );
            assert_eq!(sk.unprotected_as_bytes().len(), BLAKE2B_BLOCKSIZE);
            assert_eq!(sk.get_length(), BLAKE2B_BLOCKSIZE);
            assert_eq!(sk.get_original_length(), fuzzer_input.len());
        }

        let sk_rand = SecretKey::generate();

        if sk_rand.is_ok() {
            let sk_actual = sk_rand.unwrap();
            assert_ne!(
                &sk_actual.unprotected_as_bytes(),
                &[0u8; BLAKE2B_BLOCKSIZE].as_ref()
            );
            assert_eq!(sk_actual.unprotected_as_bytes().len(), BLAKE2B_BLOCKSIZE);
            assert_eq!(sk_actual.get_length(), BLAKE2B_BLOCKSIZE);
            assert_eq!(sk_actual.get_original_length(), BLAKE2B_KEYSIZE);
        }
    }

    pub fn fuzz_sha512_digest(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::SHA512_OUTSIZE;
        use orion::hazardous::hash::sha512::Digest;

        if fuzzer_input.len() != SHA512_OUTSIZE {
            assert!(Digest::from_slice(fuzzer_input).is_err());
        } else {
            let hash = Digest::from_slice(fuzzer_input).unwrap();

            assert_eq!(hash.as_bytes(), fuzzer_input);
            assert_eq!(hash.as_bytes().len(), fuzzer_input.len());
            assert_eq!(hash.get_length(), fuzzer_input.len());
        }
    }

    pub fn fuzz_pbkdf2_password(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::SHA512_BLOCKSIZE;
        use orion::hazardous::constants::SHA512_OUTSIZE;
        use orion::hazardous::kdf::pbkdf2::Password;

        let password = Password::from_slice(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA512_BLOCKSIZE {
            assert_eq!(
                &password.unprotected_as_bytes()[..fuzzer_input.len()],
                fuzzer_input
            );
        } else {
            let digest = orion::hazardous::hash::sha512::digest(fuzzer_input).unwrap();
            assert_eq!(
                &password.unprotected_as_bytes()[..SHA512_OUTSIZE],
                digest.as_bytes()
            );
        }

        assert_eq!(password.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(password.get_length(), SHA512_BLOCKSIZE);

        let password_rand = Password::generate();

        if password_rand.is_ok() {
            let password_actual = password_rand.unwrap();
            assert_ne!(
                &password_actual.unprotected_as_bytes(),
                &[0u8; SHA512_BLOCKSIZE].as_ref()
            );
            assert_eq!(
                password_actual.unprotected_as_bytes().len(),
                SHA512_BLOCKSIZE
            );
            assert_eq!(password_actual.get_length(), SHA512_BLOCKSIZE);
        }
    }

    pub fn fuzz_hmac_secret_key(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::SHA512_BLOCKSIZE;
        use orion::hazardous::constants::SHA512_OUTSIZE;
        use orion::hazardous::mac::hmac::SecretKey;

        let sk = SecretKey::from_slice(fuzzer_input).unwrap();

        if fuzzer_input.len() <= SHA512_BLOCKSIZE {
            assert_eq!(
                &sk.unprotected_as_bytes()[..fuzzer_input.len()],
                fuzzer_input
            );
        } else {
            let digest = orion::hazardous::hash::sha512::digest(fuzzer_input).unwrap();
            assert_eq!(
                &sk.unprotected_as_bytes()[..SHA512_OUTSIZE],
                digest.as_bytes()
            );
        }

        assert_eq!(sk.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
        assert_eq!(sk.get_length(), SHA512_BLOCKSIZE);

        let sk_rand = SecretKey::generate();

        if sk_rand.is_ok() {
            let sk_actual = sk_rand.unwrap();
            assert_ne!(
                &sk_actual.unprotected_as_bytes(),
                &[0u8; SHA512_BLOCKSIZE].as_ref()
            );
            assert_eq!(sk_actual.unprotected_as_bytes().len(), SHA512_BLOCKSIZE);
            assert_eq!(sk_actual.get_length(), SHA512_BLOCKSIZE);
        }
    }

    pub fn fuzz_hmac_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::SHA512_OUTSIZE;
        use orion::hazardous::mac::hmac::Tag;

        if fuzzer_input.len() != SHA512_OUTSIZE {
            assert!(Tag::from_slice(fuzzer_input).is_err());
        } else {
            let tag = Tag::from_slice(fuzzer_input).unwrap();

            assert_eq!(tag.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(tag.unprotected_as_bytes().len(), SHA512_OUTSIZE);
            assert_eq!(tag.get_length(), SHA512_OUTSIZE);
        }
    }

    pub fn fuzz_poly1305_onetime_key(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::POLY1305_KEYSIZE;
        use orion::hazardous::mac::poly1305::OneTimeKey;

        if fuzzer_input.len() != POLY1305_KEYSIZE {
            assert!(OneTimeKey::from_slice(fuzzer_input).is_err());
        } else {
            let sk = OneTimeKey::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), POLY1305_KEYSIZE);
            assert_eq!(sk.get_length(), POLY1305_KEYSIZE);
        }

        let sk_rand = OneTimeKey::generate();

        if sk_rand.is_ok() {
            let sk_actual = sk_rand.unwrap();
            assert_ne!(sk_actual.unprotected_as_bytes(), &[0u8; POLY1305_KEYSIZE]);
            assert_eq!(sk_actual.unprotected_as_bytes().len(), POLY1305_KEYSIZE);
            assert_eq!(sk_actual.get_length(), POLY1305_KEYSIZE);
        }
    }

    pub fn fuzz_poly1305_tag(fuzzer_input: &[u8]) {
        use orion::hazardous::constants::POLY1305_OUTSIZE;
        use orion::hazardous::mac::poly1305::Tag;

        if fuzzer_input.len() != POLY1305_OUTSIZE {
            assert!(Tag::from_slice(fuzzer_input).is_err());
        } else {
            let tag = Tag::from_slice(fuzzer_input).unwrap();

            assert_eq!(tag.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(tag.unprotected_as_bytes().len(), POLY1305_OUTSIZE);
            assert_eq!(tag.get_length(), POLY1305_OUTSIZE);
        }
    }
}

pub mod hltypes {
    macro_rules! fuzz_type_variable_length {
        ($fuzz_name:ident, $type:ident, $as_bytes_func:ident) => {
            pub fn $fuzz_name(fuzzer_input: &[u8]) {
                if fuzzer_input.is_empty() {
                    assert!($type::from_slice(fuzzer_input).is_err());
                } else {
                    let sk = $type::from_slice(fuzzer_input).unwrap();

                    assert_eq!(sk.$as_bytes_func(), fuzzer_input);
                    assert_eq!(sk.$as_bytes_func().len(), fuzzer_input.len());
                    assert_eq!(sk.get_length(), fuzzer_input.len());
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
                        assert_eq!(sk_actual.$as_bytes_func().len(), length);
                        assert_eq!(sk_actual.get_length(), length);
                    }
                }
            }
        };
    }

    use orion::aead::SecretKey;
    use orion::kdf::Salt;
    use orion::pwhash::Password;

    fuzz_type_variable_length!(fuzz_secret_key, SecretKey, unprotected_as_bytes);
    fuzz_type_variable_length!(fuzz_salt, Salt, as_bytes);
    fuzz_type_variable_length!(fuzz_password, Password, unprotected_as_bytes);

    pub fn fuzz_passwordhash(fuzzer_input: &[u8]) {
        use orion::pwhash::PasswordHash;

        if fuzzer_input.len() != 128 {
            assert!(PasswordHash::from_slice(fuzzer_input).is_err());
        } else {
            let sk = PasswordHash::from_slice(fuzzer_input).unwrap();

            assert_eq!(sk.unprotected_as_bytes(), fuzzer_input);
            assert_eq!(sk.unprotected_as_bytes().len(), 128);
            assert_eq!(sk.get_length(), 128);
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

            typedefs::fuzz_pbkdf2_password(data);

            typedefs::fuzz_hmac_secret_key(data);

            typedefs::fuzz_hmac_tag(data);

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
