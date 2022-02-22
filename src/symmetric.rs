
use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage};
use sodiumoxide;

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
		let raw_key = sodiumoxide::crypto::secretbox::gen_key();
		let key = CryptoString::from_bytes("XSALSA20", &raw_key[..])?;
		Some(SecretKey { key })
	}
}

impl CryptoInfo for SecretKey {

	fn get_usage(self) -> KeyUsage {
		return KeyUsage::EncryptDecrypt;
	}

	fn get_algorithm(self) -> String {
		return String::from("XSALSA20")
	}
}

impl PublicKey for SecretKey {

	fn get_public_key(self) -> CryptoString {
		self.key.clone()
	}

	fn get_public_str(self) -> String {
		String::from(self.key.as_str())
	}

	fn get_public_bytes(self) -> Vec<u8> {
		Vec::from(self.key.as_bytes())
	}
}

impl PrivateKey for SecretKey {

	fn get_private_key(self) -> CryptoString {
		self.key.clone()
	}

	fn get_private_str(self) -> String {
		String::from(self.key.as_str())
	}

	fn get_private_bytes(self) -> Vec<u8> {
		Vec::from(self.key.as_bytes())
	}
}
