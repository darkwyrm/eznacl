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
//! use eznacl::*;
//! 
//! let keypair = match eznacl::EncryptionPair::generate() {
//! 	Some(kp) => kp,
//! 	None => panic!("Failed to create keypair")
//! };
//!	
//! let testdata = "This is some encryption test data";
//! let encrypted_data = match keypair.encrypt(testdata.as_bytes()) {
//! 	Ok(cs) => cs,
//! 	Err(_) => panic!("encryption failure")
//! };
//!
//! print!("Unencrypted data: {}\nEncrypted data: {}", testdata, encrypted_data.as_str())
//! 
//! ```
//! 
//! The structs to use for encryption and decryption are 
//! [`EncryptionPair`](struct.EncryptionPair.html) and [`SecretKey`](struct.SecretKey.html). If you 
//! only have access to a public key, then you will use 
//! [`EncryptionKey`](struct.EncryptionKey.html) instead.
//! 
//! # Signing and Verification
//! 
//! Signature-handling is little different.

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
