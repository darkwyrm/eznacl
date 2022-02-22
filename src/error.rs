use std::fmt;

#[derive(Debug)]
pub enum EzNaclError {
	DecodingError,
	DecryptionError,
	EncodingError,
	EncryptionError,
	KeyError,
	SizeError,
	UnsupportedAlgorithm
}

impl std::error::Error for EzNaclError {}

impl fmt::Display for EzNaclError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			EzNaclError::DecodingError => write!(f, "Base85 Decoding Error"),
			EzNaclError::DecryptionError => write!(f, "Decryption Error"),
			EzNaclError::EncodingError => write!(f, "Encoding Error"),
			EzNaclError::EncryptionError => write!(f, "Encryption Error"),
			EzNaclError::KeyError => write!(f, "Key Error"),
			EzNaclError::SizeError => write!(f, "Size Error"),
			EzNaclError::UnsupportedAlgorithm => write!(f, "Unsupported Algorithm"),
		}
	}
}
