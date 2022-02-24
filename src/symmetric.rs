
use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage, Encryptor, Decryptor};
use crate::error::EzNaclError;
use sodiumoxide::crypto::secretbox;

/// An XSalsa20 symmetric encryption key
pub struct SecretKey {
	key: CryptoString
}

impl SecretKey {

	pub fn from(key: CryptoString) -> SecretKey {
		SecretKey { key }
	}

	/// Generates an XSalsa20 symmetric encryption key.
	pub fn generate() -> Option<SecretKey> {
		let raw_key = secretbox::gen_key();
		let key = CryptoString::from_bytes("XSALSA20", &raw_key[..])?;
		Some(SecretKey { key })
	}
}

impl CryptoInfo for SecretKey {

	fn get_usage(&self) -> KeyUsage {
		return KeyUsage::EncryptDecrypt;
	}

	fn get_algorithm(&self) -> String {
		return String::from("XSALSA20")
	}
}

impl PublicKey for SecretKey {

	fn get_public_key(&self) -> CryptoString {
		self.key.clone()
	}

	fn get_public_str(&self) -> String {
		String::from(self.key.as_str())
	}

	fn get_public_bytes(&self) -> Vec<u8> {
		Vec::from(self.key.as_bytes())
	}
}

impl PrivateKey for SecretKey {

	fn get_private_key(&self) -> CryptoString {
		self.key.clone()
	}

	fn get_private_str(&self) -> String {
		String::from(self.key.as_str())
	}

	fn get_private_bytes(&self) -> Vec<u8> {
		Vec::from(self.key.as_bytes())
	}
}

impl Encryptor for SecretKey {
	
	fn encrypt(&self, data: &[u8]) -> Result<CryptoString, EzNaclError> {

		let nonce = secretbox::gen_nonce();
		let key = match secretbox::xsalsa20poly1305::Key::from_slice(&self.key.as_raw()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};
		let ciphertext = secretbox::seal(data, &nonce, &key);

		match CryptoString::from_bytes("XSALSA20", &ciphertext) {
			Some(v) => Ok(v),
			None => Err(EzNaclError::EncodingError)
		}
	}
}

impl Decryptor for SecretKey {

	fn decrypt(&self, encdata: &CryptoString) -> Result<Vec<u8>, crate::EzNaclError> {

		let ciphertext = encdata.as_raw();
		let key = match secretbox::xsalsa20poly1305::Key::from_slice(&self.key.as_raw()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};
		let nonce = match secretbox::xsalsa20poly1305::Nonce::from_slice(
			&ciphertext[..secretbox::xsalsa20poly1305::KEYBYTES]) {
				Some(v) => v,
				None => return Err(EzNaclError::SizeError)
			};

		match secretbox::open(&ciphertext, &nonce, &key) {
			Ok(v) => Ok(v),
			_ => Err(EzNaclError::DecryptionError)
		}
	}
}

