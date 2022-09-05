use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum EzNaclError {
	#[error("base85 decoding error")]
	DecodingError,
	#[error("decryption error")]
	DecryptionError,
	#[error("encoding error")]
	EncodingError,
	#[error("encryption error")]
	EncryptionError,
	#[error("key error")]
	KeyError,
	#[error("signature error")]
	SignatureError,
	#[error("size error")]
	SizeError,
	#[error("unsupported algorithm")]
	UnsupportedAlgorithm,
	#[error("internal error")]
	InternalError
}
