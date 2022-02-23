use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage, Sign, VerifySignature};
use sodiumoxide::crypto::sign;
use crate::error::EzNaclError;

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

		let (raw_vkey, raw_skey) = sign::gen_keypair();
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

impl Sign for SigningPair {

	fn sign(self, data: &[u8]) -> Result<CryptoString, EzNaclError> {

		let skey = match sign::ed25519::SecretKey::from_slice(self.signkey.as_bytes()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};
		let signature = sign::sign_detached(data, &skey);
		
		match CryptoString::from_bytes("ED25519", &signature.to_bytes()) {
			Some(cs) => Ok(cs),
			_ => Err(EzNaclError::EncodingError)
		}
	}
}

impl VerifySignature for SigningPair {

	fn verify(self, data: &[u8], signature: &CryptoString) -> Result<bool, EzNaclError> {

		let vkey = match sign::ed25519::PublicKey::from_slice(self.verkey.as_bytes()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};

		let rawsig = match sign::ed25519::Signature::from_bytes(signature.as_bytes()) {
			Ok(s) => s,

			// TODO: Create a signature error
			_ => return Err(EzNaclError::KeyError),
		};

		Ok(sign::verify_detached(&rawsig, data, &vkey))
	}
}
