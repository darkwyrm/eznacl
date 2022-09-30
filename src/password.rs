use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::Rng;

/// The HashStrength type specifies how strong of a password hash is requested. Despite the term
/// 'Basic', it provides the recommended 1 second processing time on a 4th-generation Intel i5 and
/// an acceptable processing time on computers with less or more processor power. The other levels
/// increase the memory cost, increasing processing time without undue strain on weaker hardware.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "use_serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HashStrength {
    Basic,
    Extra,
    Secret,
    Extreme,
}

/// hash_password is a simple function to turn a string into a 256-bit Argon2 password hash. If you
/// don't want to bother fine-tuning your Argon2id parameters and just want something simple and
/// secure for day-to-day use, use this.
pub fn hash_password(password: &str, strength: &HashStrength) -> String {
    let mem = match strength {
        HashStrength::Basic => 0x100_000,   // 1MiB
        HashStrength::Extra => 0x200_000,   // 2MiB
        HashStrength::Secret => 0x400_000,  // 4Mib
        HashStrength::Extreme => 0x800_000, // 8MiB
    };

    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: mem,
        time_cost: 1,
        thread_mode: ThreadMode::Parallel,
        lanes: 2,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    hash
}

/// hash_password_enhanced() provides greater control over the password hashing process. Generally
/// speaking, threads should be double your available CPU cores. Dial in the memory cost to roughly
/// achieve your computation time and then adjust the time cost from there.
pub fn hash_password_enhanced(password: &str, memcost: u32, timecost: u32, threads: u32) -> String {
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: memcost,
        time_cost: timecost,
        thread_mode: ThreadMode::Parallel,
        lanes: threads,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    hash
}

/// Returns a true if the given password matches the given hash
pub fn check_password(password: &str, hash: &str) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(&hash, password.as_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pw_check_hash() {
        let password = "MyS3cretPassw*rd";
        let pwhash = crate::hash_password(password, &crate::HashStrength::Basic);

        match crate::check_password(password, &pwhash) {
            Ok(v) => assert!(v),
            Err(e) => panic!("{}", e),
        }

        // Here we actually tune the password hashing algorithm to be *less* secure, not more, just
        // to make the test run faster 🤪
        let pwhash = crate::hash_password_enhanced(password, 65536, 1, 4);
        match crate::check_password(password, &pwhash) {
            Ok(v) => assert!(v),
            Err(e) => panic!("{}", e),
        }
    }
}
