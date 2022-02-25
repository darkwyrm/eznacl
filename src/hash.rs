use crate::cryptostring::CryptoString;
use crate::error::EzNaclError;

// GetHash generates a CryptoString hash of the supplied data. Currently the supported algorithms
// are BLAKE2B-256, BLAKE2B-512, BLAKE3-256, and SHA-256.
pub fn get_hash(algorithm: &str, data: &[u8]) -> Result<CryptoString, EzNaclError> {

	match algorithm.to_lowercase().as_str() {
		"blake2b-256" => {
			use blake2::Blake2bVar;
			use blake2::digest::{Update, VariableOutput};

			let mut hasher = Blake2bVar::new(32).unwrap();
			hasher.update(data);
			let mut buffer = [0u8; 32];
			hasher.finalize_variable(&mut buffer).unwrap();
			Ok(CryptoString::from_bytes("BLAKE2B-256", &buffer).unwrap())
		},
		"blake2b-512" => {
			use blake2::Blake2bVar;
			use blake2::digest::{Update, VariableOutput};

			let mut hasher = Blake2bVar::new(64).unwrap();
			hasher.update(data);
			let mut buffer = [0u8; 64];
			hasher.finalize_variable(&mut buffer).unwrap();
			Ok(CryptoString::from_bytes("BLAKE2B-512", &buffer).unwrap())
		},
		"blake3-256" => {
			let mut hasher = blake3::Hasher::new();
			hasher.update(data);
			let mut buffer = [0; 32];
			let mut reader = hasher.finalize_xof();
			reader.fill(&mut buffer);
			Ok(CryptoString::from_bytes("BLAKE3-256", &buffer).unwrap())
		},
		"sha-256" => {
			use sha2::{Sha256, Digest};
			let mut hasher = Sha256::new();
			hasher.update(data);
			let result = hasher.finalize();
			Ok(CryptoString::from_bytes("SHA-256", &result).unwrap())
		},
		_ => Err(EzNaclError::UnsupportedAlgorithm),
	}
}

#[cfg(test)]
mod tests {
	
	#[test]
	fn test_get_hash() {
		// These are the resulting hashes for the supported algorithms when applied to the string
		// "aaaaaaaa".
		let test256list = [
			("blake2b-256", String::from(r"BLAKE2B-256:?*e?y<{rF)B`7<5U8?bXQhNic6W4lmGlN}~Mu}la")),
			("sha-256", String::from(r"SHA-256:A3Wp)6`}|qqweQl!=L|-R>C51(W!W+B%4_+&b=VC")),
			("blake3-256", String::from(r"BLAKE3-256:vE_TL>ixs8I<**_vPE@wnTJom(OOqO$B(KLZ7n{E")),
		];

		for test in test256list.iter() {
			match crate::get_hash(test.0, b"aaaaaaaa") {
				Ok(cs) => {
					assert_eq!(cs.as_str(), test.1)
				},
				_ => panic!("get_hash(256) test failure")
			}
		}

		let test512list = [
			("blake2b-512", String::from(r"BLAKE2B-512:Dc660^4H`I3arYhx9i*D`R2+&UDv6-tV@Sr3npbaWJg;Q@>!zIERGSfgy0^&t=24zT=09vm4s;bY+gH*")),
		];

		for test in test512list.iter() {
			match crate::get_hash(test.0, b"aaaaaaaa") {
				Ok(cs) => {
					assert_eq!(cs.as_str(), test.1)
				},
				_ => panic!("get_hash(512) test failure")
			}
		}

	}
}
