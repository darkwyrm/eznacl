
pub use crate::EzNaclError;
pub use crate::CryptoString;

/// The KeyUsage type denotes the usage of a cryptography key, such as encryption, decryption, or
/// both.
pub enum KeyUsage {
	Sign,
	Verify,
	SignVerify,
	Encrypt,
	Decrypt,
	EncryptDecrypt
}

/// The CryptoInfo trait is implemented by encryption- and signature-related keys to convey what
/// they are and what operation(s) they are to be used for.
pub trait CryptoInfo {
	fn get_usage(&self) -> KeyUsage;
	fn get_algorithm(&self) -> String;
}

/// The PublicKey trait defines an interface for getting the key data in various formats
pub trait PublicKey {
	fn get_public_key(&self) -> CryptoString;
	fn get_public_str(&self) -> String;
	fn get_public_bytes(&self) -> Vec<u8>;
}

/// The Private trait defines an interface for getting the key data in various formats
pub trait PrivateKey {
	fn get_private_key(&self) -> CryptoString;
	fn get_private_str(&self) -> String;
	fn get_private_bytes(&self) -> Vec<u8>;
}

/// The Encryptor trait is implemented by any encryption key
pub trait Encryptor {
	fn encrypt(&self, data: &[u8]) -> Result<CryptoString, EzNaclError>;
}

/// The Decryptor trait is implemented by any decryption key
pub trait Decryptor {
	fn decrypt(&self, encdata: &CryptoString) -> Result<Vec<u8>, EzNaclError>;
}

/// The Sign trait is implemented by any private signing key
pub trait Sign {
	fn sign(&self, data: &[u8]) -> Result<CryptoString, EzNaclError>;
}

/// The Verify trait is implemented by any public signature verification key
pub trait VerifySignature {
	fn verify(&self, data: &[u8], signature: &CryptoString) -> Result<bool, EzNaclError>;
}
