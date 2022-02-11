
//! # CryptoString
//! One of the many challenges with working with encryption is that keys and hashes are arbitrary-looking binary blobs of data -- they have zero meaning to people just looking at them. They also lack context or any other descriptive information; a 256-bit BLAKE2B hash looks the same as a SHA256 hash, but Heaven help you if you get something mixed up.
//! 
//! The solution is to represent keys and hashes as text and pair an algorithm nametag with the text representation of the key or hash. For example, a sample 128-bit BLAKE2B hash in its binary form is represented in hex as `a6 30 2a b0 da ef 14 fb 9b 82 b9 69 3e 78 76 6b`. Without spaces, this is 32 characters. The same hash can be represented in CryptoString format as `BLAKE2B-128:rZ6h7+V2$mn}WG%K6rL(`.
//! 
//! The format consists of the prefix, a colon for the separator, and the Base85-encoded binary data. Base85 was chosen because of its higher efficiency and source code compatibility. The prefix consists of up to 24 characters, which may be capital ASCII letters, numbers, or dashes. A colon is used to separate the prefix from the encoded data.
//! 
//! The official prefixes as of this writing are:
//! 
//! - ED25519
//! - CURVE25519
//! - AES-128 / AES-256 / AES-384 / AES-512
//! - SALSA20 / XSALSA20
//! - SHA-256 / SHA-384 / SHA-512
//! - SHA3-256 / SHA3-384 / SHA3-512
//! - BLAKE2B-128 / BLAKE2B-256 / BLAKE2B-512
//! - BLAKE3-128 / BLAKE3-256 / BLAKE3-512
//! 
//! Regular usage of a CryptoString mostly involves creating an instance from other data. The constructor can take a CryptoString-formatted string or a string prefix and some raw bytes. Once data has been put into the instance, getting it back out is just a matter of casting to a string, or calling `to_string()`, `to_bytes()`, or `to_raw()`. The last of these three methods only returns the raw data stored in the object.

#[derive(Debug)]
pub struct CryptoString<'a> {
	totaldata: String,
	prefix: &'a str,
	data: &'a str,
}

impl ToString for CryptoString<'_> {
	fn to_string(&self) -> String {
		self.totaldata.clone()
	}
}

impl CryptoString<'_> {
	
	pub fn as_bytes(&self) -> &[u8] {
		self.totaldata.as_bytes()
	}

	pub fn as_str(&self) -> &str {
		self.totaldata.as_str()
	}

	pub fn is_empty(&self) -> bool {
        self.totaldata.is_empty()
    }

	pub fn prefix(&self) -> &str {
		self.prefix
	}

	pub fn data(&self) -> &str {
		self.data
	}
}
