use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage};
use sodiumoxide;

/// An ED25519 asymmetric signing keypair
pub struct SigningPair {
	verkey: CryptoString,
	signkey: CryptoString,
}

impl SigningPair {

	pub fn from(verkey: CryptoString, signkey: CryptoString) -> SigningPair {
		SigningPair { verkey, signkey }
	}

	/// Generates a ED25519 asymmetric encryption keypair.
	pub fn generate() -> Option<SigningPair> {
		let (raw_vkey, raw_skey) = sodiumoxide::crypto::sign::gen_keypair();
		let verkey = CryptoString::from_bytes("ED25519", &raw_vkey[..])?;

		let signkey = CryptoString::from_bytes("ED25519", &raw_skey[..])?;
		Some(SigningPair { verkey, signkey })
	}
}

impl CryptoInfo for SigningPair {

	fn get_usage(self) -> KeyUsage {
		return KeyUsage::SignVerify;
	}

	fn get_algorithm(self) -> String {
		return String::from("ED25519")
	}
}

impl PublicKey for SigningPair {

	fn get_public_key(self) -> CryptoString {
		self.verkey.clone()
	}

	fn get_public_str(self) -> String {
		String::from(self.verkey.as_str())
	}

	fn get_public_bytes(self) -> Vec<u8> {
		Vec::from(self.verkey.as_bytes())
	}
}

impl PrivateKey for SigningPair {

	fn get_private_key(self) -> CryptoString {
		self.signkey.clone()
	}

	fn get_private_str(self) -> String {
		String::from(self.signkey.as_str())
	}

	fn get_private_bytes(self) -> Vec<u8> {
		Vec::from(self.signkey.as_bytes())
	}
}
