use crate::base::{CryptoInfo, Decryptor, Encryptor, KeyUsage, PrivateKey, PublicKey};
use crate::error::EzNaclError;
use crate::CryptoString;
// use rand::thread_rng;
// use rand::Rng;
use sodiumoxide::crypto::secretbox;

/// Returns the symmetric encryption algorithms supported by the library. Currently the only
/// supported encryption algorithm is XSalsa20, although AES support is planned.
pub fn get_supported_symmetric_algorithms() -> Vec<String> {
    vec![String::from("XSALSA20")]
}

/// An XSalsa20 symmetric encryption key
#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[cfg_attr(feature = "use_serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretKey {
    key: CryptoString,
}

fn is_valid_secretkey_type(algo: &str) -> bool {
    match algo {
        "XSALSA20" => true,
        // "AES-128" | "AES-256" => true,
        _ => false,
    }
}

impl SecretKey {
    /// Creates a new SecretKey from a CryptoString object
    pub fn from(key: &CryptoString) -> Option<SecretKey> {
        if is_valid_secretkey_type(key.prefix()) {
            Some(SecretKey { key: key.clone() })
        } else {
            None
        }
    }

    /// Creates a new SecretKey from a string containing CryptoString-formatted data
    pub fn from_string(keystr: &str) -> Option<SecretKey> {
        let keycs = match CryptoString::from(keystr) {
            Some(cs) => cs,
            None => return None,
        };

        SecretKey::from(&keycs)
    }

    /// Generates an XSalsa20 symmetric encryption key.
    pub fn generate(algo: &str) -> Option<SecretKey> {
        match algo {
            "XSALSA20" => {
                let raw_key = secretbox::gen_key();
                let key = CryptoString::from_bytes("XSALSA20", &raw_key[..])?;
                Some(SecretKey { key })
            }
            // "AES-128" => {
            // 	let mut key = [0u8; 16];
            // 	match thread_rng().try_fill(&mut key[..]) {
            // 		Ok(_) => (),
            // 		Err(e) => {
            // 			return None
            // 		}
            // 	};
            // 	let keycs = CryptoString::from_bytes("AES-128", &key[..])?;
            // 	Some(SecretKey { key: keycs })
            // },
            // "AES-256" => {
            // 	let mut key = [0u8; 32];
            // 	match thread_rng().try_fill(&mut key[..]) {
            // 		Ok(_) => (),
            // 		Err(e) => {
            // 			return None
            // 		}
            // 	};
            // 	let key = CryptoString::from_bytes("AES-256", &key[..])?;
            // 	Some(SecretKey { key })
            // },
            _ => None,
        }
    }
}

impl CryptoInfo for SecretKey {
    /// Indicates that the SecretKey object can perform both encryption and decryption
    fn get_usage(&self) -> KeyUsage {
        return KeyUsage::EncryptDecrypt;
    }

    /// Returns the string "XSALSA20"
    fn get_algorithm(&self) -> String {
        return String::from(self.key.prefix());
    }
}

impl PublicKey for SecretKey {
    /// Returns the object's key as a CryptoString object
    fn get_public_key(&self) -> CryptoString {
        self.key.clone()
    }

    /// Returns the object's key as a string
    fn get_public_str(&self) -> String {
        String::from(self.key.as_str())
    }

    /// Returns the object's key as a byte list
    fn get_public_bytes(&self) -> Vec<u8> {
        Vec::from(self.key.as_bytes())
    }
}

impl PrivateKey for SecretKey {
    /// Returns the object's key as a CryptoString object
    fn get_private_key(&self) -> CryptoString {
        self.key.clone()
    }

    /// Returns the object's key as a string
    fn get_private_str(&self) -> String {
        String::from(self.key.as_str())
    }

    /// Returns the object's key as a byte list
    fn get_private_bytes(&self) -> Vec<u8> {
        Vec::from(self.key.as_bytes())
    }
}

impl Encryptor for SecretKey {
    /// Encrypts the provided data using the XSalsa20 algorithm.
    fn encrypt(&self, data: &[u8]) -> Result<CryptoString, EzNaclError> {
        match self.key.prefix() {
            "XSALSA20" => {
                let nonce = secretbox::gen_nonce();
                let key = match secretbox::xsalsa20poly1305::Key::from_slice(&self.key.as_raw()) {
                    Some(v) => v,
                    None => return Err(EzNaclError::KeyError),
                };
                let mut ciphertext = secretbox::seal(data, &nonce, &key);

                let mut out = Vec::new();
                out.extend_from_slice(&nonce[..]);
                out.append(&mut ciphertext);

                match CryptoString::from_bytes("XSALSA20", &out) {
                    Some(v) => Ok(v),
                    None => Err(EzNaclError::EncodingError),
                }
            }
            // "AES-128" => {
            // let key: &[u8] = aes_gcm::Aes128Gcm::new();
            // let mut nonce = [0u8; 12];
            // match thread_rng().try_fill(&mut key[..]) {
            // 	Ok(_) => (),
            // 	Err(e) => {
            // 		return Err(EzNaclError::InternalError)
            // 	}
            // };

            // 	Err(EzNaclError::EncryptionError)
            // }
            _ => return Err(EzNaclError::UnsupportedAlgorithm),
        }
    }
}

impl Decryptor for SecretKey {
    /// Decrypts the XSalsa20-encrypted data.
    fn decrypt(&self, encdata: &CryptoString) -> Result<Vec<u8>, crate::EzNaclError> {
        let ciphertext = encdata.as_raw();
        let key = match secretbox::xsalsa20poly1305::Key::from_slice(&self.key.as_raw()) {
            Some(v) => v,
            None => return Err(EzNaclError::KeyError),
        };
        let nonce = match secretbox::xsalsa20poly1305::Nonce::from_slice(
            &ciphertext[..secretbox::xsalsa20poly1305::NONCEBYTES],
        ) {
            Some(v) => v,
            None => return Err(EzNaclError::SizeError),
        };

        match secretbox::open(
            &ciphertext[secretbox::xsalsa20poly1305::NONCEBYTES..],
            &nonce,
            &key,
        ) {
            Ok(v) => Ok(v),
            _ => Err(EzNaclError::DecryptionError),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn symmetric_encrypt_decrypt_test() {
        let key = match crate::SecretKey::from_string(
            "XSALSA20:hlibDY}Ls{F!yG83!a#E$|Nd3?MQ@9G=Q{7PB(@O",
        ) {
            Some(k) => k,
            None => panic!("symmetric_encrypt_decrypt_test failed to create key"),
        };

        let testdata = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let encdata = match key.encrypt(testdata.as_bytes()) {
            Ok(cs) => cs,
            Err(_) => panic!("symmetric_encrypt_decrypt_test encryption failure"),
        };

        let decdata = match key.decrypt(&encdata) {
            Ok(cs) => cs,
            Err(_) => panic!("symmetric_encrypt_decrypt_test decryption failure"),
        };

        let decstring = match String::from_utf8(decdata) {
            Ok(s) => s,
            Err(_) => panic!("symmetric_encrypt_decrypt_test failure decoding decrypted data"),
        };

        assert_eq!(testdata, decstring);
    }
}
