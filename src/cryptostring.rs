
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
//! - BLAKE2B-256 / BLAKE2B-512
//! - BLAKE3-128
//! - K12-128
//! 
//! Regular usage of a CryptoString mostly involves creating an instance from other data. The constructor can take a CryptoString-formatted string or a string prefix and some raw bytes. Once data has been put into the instance, getting it back out is just a matter of casting to a string, or calling `to_string()`, `to_bytes()`, or `to_raw()`. The last of these three methods only returns the raw data stored in the object.

use base85::{encode, decode};
use regex::Regex;
use std::fmt;

lazy_static! {
	static ref RE_CRYPTOSTRING_FORMAT: regex::Regex = {
		Regex::new(r"^([A-Z0-9-]{1,24}):([0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]+)$").unwrap()
	};
	static ref RE_CRYPTOSTRING_PREFIX: regex::Regex = {
		Regex::new(r"^([A-Z0-9-]{1,24})$").unwrap()
	};
}

/// A class to store cryptography-related binary data encoded as text and associated with an
/// algorithm.
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct CryptoString {
	string: String
}

impl fmt::Display for CryptoString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.string)
    }
}

impl CryptoString {
	/// Creates a new CryptoString from a string containing CryptoString-formatted data
	pub fn from(s: &str) -> Option<CryptoString> {
		let caps = RE_CRYPTOSTRING_FORMAT.captures(s);
		match caps {
			Some(_) => {
				Some(CryptoString {string: String::from(s)})
			},
			_ => None
		}
	}

	/// Creates a new CryptoString from a string containing the algorithm and raw data
	pub fn from_bytes(algorithm: &str, buffer: &[u8]) -> Option<CryptoString> {
		if !RE_CRYPTOSTRING_PREFIX.is_match(algorithm) {
			return None
		}

		let mut out = CryptoString {string: String::from(algorithm)+":"};
		let encstr = encode(buffer);
		if encstr.len() == 0 {
			return None
		}
		out.string.push_str(&encstr);

		Some(out)
	}

	/// Returns the CryptoString data as a string of bytes
	pub fn as_bytes(&self) -> &[u8] {
		self.string.as_bytes()
	}

	/// Creates a new Vector of bytes containing the object's raw data
	pub fn as_raw(&self) -> Vec<u8> {
		let list: Vec<&str> = self.string.split(":").collect();
		return decode(list[1]).unwrap()
	}

	/// Returns the object's contents as  a string
	pub fn as_str(&self) -> &str {
		self.string.as_str()
	}

	/// Returns true if empty
	pub fn is_empty(&self) -> bool {
        self.string.is_empty()
    }

	/// Returns the object's algorithm prefix
	pub fn prefix(&self) -> &str {
		let list: Vec<&str> = self.string.split(":").collect();
		list[0]
	}

	/// Returns the object's encoded data
	pub fn data(&self) -> &str {
		let list: Vec<&str> = self.string.split(":").collect();
		list[1]
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn cs_test_from() {
		let testlist = [
			"ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*",
			"BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W",
			"CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"
		];
	
		for test in testlist.iter() {
			match crate::CryptoString::from(test) {
				None => panic!("from() test failure"),
				_ => { /* Do nothing */ },
			}
		}

		let faillist = [
			"ED25519",
			":123456789",
			"$ILLEGAL:123456789",
			" ",
			""
		];
		for test in faillist.iter() {
			match crate::CryptoString::from(test) {
				None => { /* Do nothing */ },
				_ => panic!("from() bad value test failure"),
			}
		}

	}

	#[test]
	fn cs_test_from_bytes_plus() {
		let faillist = [
			("", ":123456789"),
			("$ILLEGAL", "123456789"),
			("TEST", ""),
		];
		for test in faillist.iter() {
			match crate::CryptoString::from_bytes(test.0, test.1.as_bytes()) {
				None => { /* Do nothing */ },
				_ => panic!("from_bytes() bad value test failure"),
			}
		}
		
		let cs = match crate::CryptoString::from_bytes("TEST", b"aaaaaa") {
			Some(v) => v,
			_ => panic!("from_bytes() test failure"),
		};
		assert_eq!(cs.prefix(), "TEST");
		assert_eq!(cs.as_str(), "TEST:VPRomVPO");
		assert_eq!(cs.as_bytes(), b"TEST:VPRomVPO");
		assert_eq!(cs.as_raw(), b"aaaaaa");
		assert_eq!(cs.is_empty(), false);
	}
}
