
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
	fn get_usage() -> KeyUsage;
	fn get_algorithm() -> String;
}

/// The Encryptor trait is implemented by any encryption key
pub trait Encryptor {
	fn encrypt(data: &[u8]) -> CryptoString;
}

/// The Decryptor trait is implemented by any decryption key
pub trait Decryptor {
	fn decrypt(encdata: &str) -> Vec<u8>;
}

/// The Sign trait is implemented by any private signing key
pub trait Sign {
	fn sign(data: &[u8]) -> CryptoString;
}

/// The Verify trait is implemented by any public signature verification key
pub trait VerifySignature {
	fn verify(data: &u8, signature: &CryptoString) -> Result<bool, EzNaclError>;
}
