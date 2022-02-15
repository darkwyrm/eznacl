use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use crate::cryptostring::CryptoString;
use crate::error::EzNaclError;

// GetHash generates a CryptoString hash of the supplied data
pub fn get_hash(algorithm: &str, data: &[u8]) -> Result<CryptoString, EzNaclError> {
	
	// TODO: Finish get_hash()

	match algorithm.to_lowercase().as_str() {
		"blake2b-256" => {
			let mut hasher = Blake2bVar::new(16).unwrap();
			hasher.update(data);
			let mut buffer = [0u8; 16];
			hasher.finalize_variable(&mut buffer).unwrap();
			Ok(CryptoString::from_bytes("BLAKE2B-256", &buffer).unwrap())
		},
		_ => Err(EzNaclError::UnsupportedAlgorithm),
	}
}
