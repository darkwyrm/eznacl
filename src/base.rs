pub use crate::CryptoString;
pub use crate::EzNaclError;

/// The KeyUsage type denotes the usage of a cryptography key, such as encryption, decryption, or
/// both.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "use_serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyUsage {
    Sign,
    Verify,
    SignVerify,
    Encrypt,
    Decrypt,
    EncryptDecrypt,
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

/// Returns true if the specified algorithm is one supported by the library, regardless of type.
pub fn is_supported_algorithm(name: &str) -> bool {
    match name {
        // Symmetric encryption algorithms
        "XSALSA20" => true,

        // Asymmetric encryption algorithms
        "CURVE25519" => true,

        // Signing algorithsm
        "ED25519" => true,

        // Hash algorithms
        "BLAKE2B-256" | "BLAKE2B-512" | "BLAKE3-256" => true,
        "K12-256" | "SHA-256" | "SHA-512" | "SHA3-256" | "SHA3-512" => true,

        _ => false,
    }
}
