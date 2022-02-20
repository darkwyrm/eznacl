
pub use crate::EzNaclError;
pub use crate::CryptoString;

/// The KeyUsage type is for knowing what a cryptography key is to be used for.
pub enum KeyUsage {
	Signing,
	Verification,
	Encryption,
	Decryption,
	EncryptDecrypt
}

/// The CryptoInfo trait is implemented by encryption- and signature-related keys to convey what
/// they are and what operation(s) they are to be used for.
pub trait CryptoInfo {
	fn get_usage(self) -> KeyUsage;
	fn get_algorithm(self) -> String;
}

pub trait PublicKey {
	fn get_public_key(self) -> CryptoString;
	fn get_public_str(self) -> String;
	fn get_public_bytes(self) -> Vec<u8>;
}

pub trait PrivateKey {
	fn get_private_key(self) -> CryptoString;
	fn get_private_str(self) -> String;
	fn get_private_bytes(self) -> Vec<u8>;
}

/// The Encryptor trait is implemented by any encryption key
pub trait Encryptor {
	fn encrypt(self, data: &[u8]) -> CryptoString;
}

/// The Decryptor trait is implemented by any decryption key
pub trait Decryptor {
	fn decrypt(self, encdata: &str) -> Vec<u8>;
}

/// The Sign trait is implemented by any private signing key
pub trait Sign {
	fn sign(self, data: &[u8]) -> CryptoString;
}

/// The Verify trait is implemented by any public signature verification key
pub trait VerifySignature {
	fn verify(self, data: &u8, signature: &CryptoString) -> Result<bool, EzNaclError>;
}
