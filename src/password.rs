use argon2::{self, Config, ThreadMode, Variant, Version};

// HashPassword turns a string into an Argon2 password hash. Set extra_strong to true if you're
// feeling particularly paranoid.
pub fn hash_password(password: &str, extra_strong: bool) -> String {
	let config = if extra_strong { 
		Config {
			// LUDICROUS SPEED! GO!
			variant: Variant::Argon2id,
			version: Version::Version13,
			mem_cost: 1073741824,
			time_cost: 10,
			thread_mode: ThreadMode::Parallel,
			lanes: 8,
			secret: &[],
			ad: &[],
			hash_length: 48
		};
	} else {
		Config {
			variant: Variant::Argon2id,
			version: Version::Version13,
			mem_cost: 65536,
			time_cost: 10,
			thread_mode: ThreadMode::Parallel,
			lanes: 4,
			secret: &[],
			ad: &[],
			hash_length: 32
		};
	};

	// TODO: finish hash_password

	String::from("unimplemented")
}
