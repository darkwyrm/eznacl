use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage, Encryptor, Decryptor};
use sodiumoxide::crypto;
use crate::error::EzNaclError;

/// A Curve25519 asymmetric encryption keypair
pub struct EncryptionPair {
	pubkey: CryptoString,
	privkey: CryptoString,
}

impl EncryptionPair {

	pub fn from(pubkey: CryptoString, privkey: CryptoString) -> EncryptionPair {
		EncryptionPair { pubkey, privkey }
	}

	pub fn from_strings(pubstr: &str, privstr: &str) -> Option<EncryptionPair> {
		
		let pubcs = match CryptoString::from(pubstr) {
			Some(cs) => cs,
			None => return None
		};
		let privcs = match CryptoString::from(privstr) {
			Some(cs) => cs,
			None => return None
		};

		Some(EncryptionPair { pubkey: pubcs, privkey: privcs })
	}

	/// Generates a Curve25519 asymmetric encryption keypair.
	pub fn generate() -> Option<EncryptionPair> {

		let (raw_ekey, raw_dkey) = crypto::box_::gen_keypair();
		let pubkey = CryptoString::from_bytes("CURVE25519", &raw_ekey[..])?;

		let privkey = CryptoString::from_bytes("CURVE25519", &raw_dkey[..])?;
		
		Some(EncryptionPair { pubkey, privkey })
	}
}

impl CryptoInfo for EncryptionPair {

	fn get_usage(&self) -> KeyUsage {
		KeyUsage::EncryptDecrypt
	}

	fn get_algorithm(&self) -> String {
		String::from("CURVE25519")
	}
}

impl PublicKey for EncryptionPair {

	fn get_public_key(&self) -> CryptoString {
		self.pubkey.clone()
	}

	fn get_public_str(&self) -> String {
		String::from(self.pubkey.as_str())
	}

	fn get_public_bytes(&self) -> Vec<u8> {
		Vec::from(self.pubkey.as_bytes())
	}
}

impl PrivateKey for EncryptionPair {

	fn get_private_key(&self) -> CryptoString {
		self.privkey.clone()
	}

	fn get_private_str(&self) -> String {
		String::from(self.privkey.as_str())
	}

	fn get_private_bytes(&self) -> Vec<u8> {
		Vec::from(self.privkey.as_bytes())
	}
}

impl Encryptor for EncryptionPair {
	
	fn encrypt(&self, data: &[u8]) -> Result<CryptoString, EzNaclError> {

		let rawkey = match crypto::box_::PublicKey::from_slice(&self.pubkey.as_bytes()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};
	
		let ciphertext = crypto::sealedbox::seal(data, &rawkey);
		match CryptoString::from_bytes("CURVE25519", &ciphertext) {
			Some(v) => Ok(v),
			None => Err(EzNaclError::EncodingError)
		}
	}
}

impl Decryptor for EncryptionPair {

	fn decrypt(&self, encdata: &CryptoString) -> Result<Vec<u8>, crate::EzNaclError> {

		let ciphertext = encdata.as_raw();
		let rpubkey = match crypto::box_::PublicKey::from_slice(&self.pubkey.as_bytes()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};
		let rprivkey = match crypto::box_::SecretKey::from_slice(&self.privkey.as_bytes()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};

		match crypto::sealedbox::open(&ciphertext, &rpubkey, &rprivkey) {
			Ok(v) => Ok(v),
			_ => Err(EzNaclError::DecryptionError)
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	
	#[test]
	fn encrypt_decrypt_test() {
		
		let keypair = match crate::EncryptionPair::from_strings(
			"CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`",
			"CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&") {
				Some(kp) => kp,
				None => panic!("encrypt_decrypt_test failed to create keypair")
			};
	
		
		let testdata = "This is some encryption test data";
		let encdata = match keypair.encrypt(testdata.as_bytes()) {
			Ok(cs) => cs,
			Err(_) => panic!("encrypt_decrypt_test encryption failure")
		};
		
		let decdata = match keypair.decrypt(&encdata) {
			Ok(cs) => cs,
			Err(_) => panic!("encrypt_decrypt_test decryption failure")
		};
		
		assert_eq!(testdata, String::from_utf8(decdata));
	}
}
