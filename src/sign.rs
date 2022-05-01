use crate::CryptoString;
use crate::base::{CryptoInfo, PublicKey, PrivateKey, KeyUsage, Sign, VerifySignature};
use sodiumoxide::crypto::sign;
use crate::error::EzNaclError;

/// Returns the cryptographic signing algorithms supported by the library
pub fn get_supported_signing_algorithms() -> Vec<String> {
	vec![
		String::from("ED25519"),
	]
}

/// An Ed25519 asymmetric signing keypair
pub struct SigningPair {
	verkey: CryptoString,
	signkey: CryptoString,
}

impl SigningPair {
	/// Creates a SigningPair from two CryptoString objects
	pub fn from(verkey: CryptoString, signkey: CryptoString) -> SigningPair {
		SigningPair { verkey, signkey }
	}

	/// Creates a SigningPair from two strings containing CryptoString-formatted data
	pub fn from_strings(verstr: &str, signstr: &str) -> Option<SigningPair> {
		
		let vercs = match CryptoString::from(verstr) {
			Some(cs) => cs,
			None => return None
		};
		let signcs = match CryptoString::from(signstr) {
			Some(cs) => cs,
			None => return None
		};

		Some(SigningPair { verkey: vercs, signkey: signcs })
	}
	
	/// Generates a new ED25519 asymmetric encryption keypair.
	pub fn generate() -> Option<SigningPair> {

		let (raw_vkey, raw_skey) = sign::gen_keypair();
		let verkey = CryptoString::from_bytes("ED25519", &raw_vkey[..])?;

		let signkey = CryptoString::from_bytes("ED25519", &raw_skey[..32])?;
		Some(SigningPair { verkey, signkey })
	}
}

impl CryptoInfo for SigningPair {

	/// Indicates that the SigningPair object can perform both signing and verification
	fn get_usage(&self) -> KeyUsage {
		KeyUsage::SignVerify
	}

	/// Returns the string "ED25519"
	fn get_algorithm(&self) -> String {
		String::from("ED25519")
	}
}

impl PublicKey for SigningPair {

	/// Returns the public key as a CryptoString object
	fn get_public_key(&self) -> CryptoString {
		self.verkey.clone()
	}

	/// Returns the public key as a string
	fn get_public_str(&self) -> String {
		String::from(self.verkey.as_str())
	}

	/// Returns the public key as a byte list
	fn get_public_bytes(&self) -> Vec<u8> {
		Vec::from(self.verkey.as_bytes())
	}
}

impl PrivateKey for SigningPair {

	/// Returns the private key as a CryptoString object
	fn get_private_key(&self) -> CryptoString {
		self.signkey.clone()
	}

	/// Returns the private key as a string
	fn get_private_str(&self) -> String {
		String::from(self.signkey.as_str())
	}

	/// Returns the private key as a byte list
	fn get_private_bytes(&self) -> Vec<u8> {
		Vec::from(self.signkey.as_bytes())
	}
}

impl Sign for SigningPair {

	/// Signs the provided data using the Ed25519 algorithm
	fn sign(&self, data: &[u8]) -> Result<CryptoString, EzNaclError> {

		let mut fullkey = self.signkey.as_raw();
		fullkey.append(&mut self.verkey.as_raw());
		let skey = match sign::ed25519::SecretKey::from_slice(&fullkey) {
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

	/// Verifies the Ed25519 signature against the provided data
	fn verify(&self, data: &[u8], signature: &CryptoString) -> Result<bool, EzNaclError> {

		let vkey = match sign::ed25519::PublicKey::from_slice(&self.verkey.as_raw()) {
			Some(v) => v,
			None => return Err(EzNaclError::KeyError)
		};

		let rawsig = match sign::ed25519::Signature::from_bytes(&signature.as_raw()) {
			Ok(s) => s,
			_ => return Err(EzNaclError::SignatureError),
		};

		Ok(sign::verify_detached(&rawsig, data, &vkey))
	}
}

/// An Ed25519 verification key
pub struct VerificationKey {
	verkey: CryptoString,
}

impl VerificationKey {
	/// Creates a VerificationKey from a CryptoString object
	pub fn from(verkey: CryptoString) -> VerificationKey {
		VerificationKey { verkey }
	}

	/// Creates a VerificationKey from a string containing CryptoString-formatted data
	pub fn from_string(verstr: &str) -> Option<VerificationKey> {
		
		let vercs = match CryptoString::from(verstr) {
			Some(cs) => cs,
			None => return None
		};

		Some(VerificationKey { verkey: vercs })
	}
	
}

impl CryptoInfo for VerificationKey {

	/// Indicates that the VerificationKey object can perform both signing and verification
	fn get_usage(&self) -> KeyUsage {
		KeyUsage::SignVerify
	}

	/// Returns the string "ED25519"
	fn get_algorithm(&self) -> String {
		String::from("ED25519")
	}
}

impl PublicKey for VerificationKey {

	/// Returns the public key as a CryptoString object
	fn get_public_key(&self) -> CryptoString {
		self.verkey.clone()
	}

	/// Returns the public key as a string
	fn get_public_str(&self) -> String {
		String::from(self.verkey.as_str())
	}

	/// Returns the public key as a byte list
	fn get_public_bytes(&self) -> Vec<u8> {
		Vec::from(self.verkey.as_bytes())
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	
	#[test]
	fn sign_verify_test() {
		
		let keypair = match crate::SigningPair::from_strings(
			"ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx",
			"ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF") {
				Some(kp) => kp,
				None => panic!("sign_verify_test failed to create keypair")
			};
		
			let testdata = "This is some signing test data";
		let signature = match keypair.sign(testdata.as_bytes()) {
			Ok(cs) => cs,
			Err(_) => panic!("sign_verify_test signing failure")
		};
		
		match keypair.verify(&testdata.as_bytes(), &signature) {
			Ok(v) => assert!(v, "sign_verify_test failure to verify signature"),
			Err(_) => panic!("sign_verify_test verify() error")
		};
	}
}
