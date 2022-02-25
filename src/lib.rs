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
