use crate::cryptostring::CryptoString;
use crate::error::EzNaclError;

// GetHash generates a CryptoString hash of the supplied data
pub fn get_hash(algorithm: &str, data: &[u8]) -> Result<CryptoString, EzNaclError> {

	match algorithm.to_lowercase().as_str() {
		"blake2b-256" => {
			use blake2::Blake2bVar;
			use blake2::digest::{Update, VariableOutput};

			let mut hasher = Blake2bVar::new(16).unwrap();
			hasher.update(data);
			let mut buffer = [0u8; 16];
			hasher.finalize_variable(&mut buffer).unwrap();
			Ok(CryptoString::from_bytes("BLAKE2B-256", &buffer).unwrap())
		},
		"blake2b-512" => {
			use blake2::Blake2bVar;
			use blake2::digest::{Update, VariableOutput};

			let mut hasher = Blake2bVar::new(32).unwrap();
			hasher.update(data);
			let mut buffer = [0u8; 32];
			hasher.finalize_variable(&mut buffer).unwrap();
			Ok(CryptoString::from_bytes("BLAKE2B-512", &buffer).unwrap())
		},
		"blake3-256" => {
			let mut hasher = blake3::Hasher::new();
			hasher.update(data);
			let mut buffer = [0; 16];
			let mut reader = hasher.finalize_xof();
			reader.fill(&mut buffer);
			Ok(CryptoString::from_bytes("BLAKE2-256", &buffer).unwrap())
		},
		"sha-256" => {
			use sha2::{Sha256, Digest};
			let mut hasher = Sha256::new();
			hasher.update(data);
			let result = hasher.finalize();
			Ok(CryptoString::from_bytes("BLAKE2B-512", &result).unwrap())
		},
		_ => Err(EzNaclError::UnsupportedAlgorithm),
	}
}

// Implement check_hash
// pub fn check_hash(hash: &CryptoString, data: &[u8]) -> Result<bool, EzNaclError> {

// }