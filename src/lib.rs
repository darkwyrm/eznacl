//! EZNaCl is an MPL2.0-licensed library that wraps around LibSodium and gets as close to push-button cryptography as a developer can feasibly be. At the same time, because it's cryptography, be very careful applying it--you can still shoot yourself in the foot.
//! 
//! No guarantees of any kind are provided with the library even though it has been written with care.
//! 
//! Also, please don't use this code to place important crypto keys in your code or embed backdoors. No one needs that kind of drama.
//! 
//! # Encryption and Decryption
//! 
//! Regardless of whether or not you are using public key or secret key cryptography, the usage is 
//! the same:
//! 
//! 1. Instantiate your key, either using `generate()` or from an existing CryptoString.
//! 2. Call [`encrypt()`](trait.Encryptor.html) or [`decrypt()`](trait.Decryptor.html) on your data
//! 3. Profit
//! 
//! ## Encryption Example
//! ```
//! use eznacl;
//! 
//! let keypair = EncryptionPair::generate().unwrap();
//! 
//! let testdata = "This is some encryption test data";
//! let encrypted_data = keypair.encrypt(testdata.as_bytes()).unwrap();
//! 
//! println!(
//! 	"\nUnencrypted data:\n{}\nEncrypted data:\n{}",
//! 	testdata,
//! 	encrypted_data.as_str());
//! ```
//! 
//! The structs to use for encryption and decryption are 
//! [`EncryptionPair`](struct.EncryptionPair.html) and [`SecretKey`](struct.SecretKey.html). If you 
//! only have access to a public key, then you will use 
//! [`EncryptionKey`](struct.EncryptionKey.html) instead. It is possible to substitute SecretKey for
//! EncryptionPair in the above example and achieve the same results using symmetric encryption.
//! 
//! # Signing and Verification
//! 
//! Signature-handling is little different. Instead of using 
//! [`EncryptionPair`](struct.EncryptionPair.html), you will use
//! [`SigningPair`](struct.SigningPair.html). 
//! 
//! ```
//! use eznacl;
//! 
//! let signpair = SigningPair::generate().unwrap();
//! 
//! let testdata = "This is some test data to sign";
//! let signature = match signpair.sign(testdata.as_bytes()) {
//! 	Ok(cs) => cs,
//! 	Err(_) => panic!("signing failure"),
//! };
//! println!("\nSignature for data: {}", signature);
//! 
//! match signpair.verify(testdata.as_bytes(), &signature) {
//! 	Ok(v) => {
//! 		if v {
//! 			println!("Verified signature")
//! 		} else {
//! 			println!("Signature failed to verify")
//! 		}
//! 	},
//! 	Err(e) => {
//! 		println!("Error verifying signature: {}", e);
//! 	}
//! }
//! ```
//! 
//! # Hashing
//! 
//! Generating hashes of data is literally as simple as possible for cases where data will fit into memory.
//! 
//! ```
//! let testdata = "This is some test data to hash";
//! let hash = get_hash("sha-256", testdata.as_bytes()).unwrap();
//! println!("\nTest data:\n{}\nHash of test data:\n{}\n", testdata, hash);
//! ```
//! 
//! Keep in mind that this form of hashing is **not intended for passwords**. This is because these hash algorithms are designed to be fast and will not provide protection against brute force attacks. Instead, use EzNaCl's password hashing facilities.
//! 
//! ```
//! let password = "This is my secret password";
//! let pwdhash = hash_password(&password, &HashStrength::Basic);
//! println!("\nPassword: {}\nPassword Hash:\n{}\n", password, pwdhash);
//! ```
//! 
//! **Note:** the password hashing API is not 100% stabilized and may see minor changes in the future.
//! 
//! Despite the name, the Basic level of hashing strength is suitable for most situations. In its current implementation, the different password levels utilize different amounts of RAM. 
//! 
//! - Basic: 1MB
//! - Extra: 2MB
//! - Secret: 4MB
//! - Extreme: 8MB
//! 
//! On an Intel i5-4590S, the Basic level of protection requires roughly 1 second to hash the password and only smaller differences on more or less powerful computers. For those situations requiring greater control over password hashing parameters, see [`hash_password_enhanced()`](fn.hash_password_enhanced.html).
//! 
//! # Using Existing Keys and Other Miscellaneous
//! 
//! EzNaCl is designed to interact with keys, signatures, and hashes as strings, not raw binary data. If you have existing binary key(s) you wish to utilize, create [`CryptoString`](struct.CryptoString.html)s from them using [`from_bytes()`](struct.CryptoString.html#method.from_bytes) and supplying the algorithm used. From there, create the key/keypair itself using the `from` method.
//! 
//! For more information on supported algorithms, see the documentation for the corresponding functions:
//! 
//! - [`Asymmetric Encryption`](fn.get_supported_asymmetric_algorithms.html)
//! - [`Symmetric Encryption:`](fn.get_supported_symmetric_algorithms.html)
//! - [`Signing`](fn.get_supported_signing_algorithms.html))
//! - [`Cryptographic Hashes`](fn.get_supported_hash_algorithms.html))
//! - [`Password Hashes`](fn.hash_password.html)

mod base;
mod cryptostring;
mod encrypt;
mod error;
mod hash;
mod password;
mod sign;
mod symmetric;

pub use base::*;
pub use cryptostring::CryptoString;
pub use encrypt::*;
pub use error::EzNaclError;
pub use hash::*;
pub use password::*;
pub use sign::*;
pub use symmetric::*;

#[macro_use]
extern crate lazy_static;

use sodiumoxide;

/// Initializes the underlying SodiumOxide library, which is needed for thread safety.
pub fn init() -> Result<(), ()> {
	sodiumoxide::init()
}
