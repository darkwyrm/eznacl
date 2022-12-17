
# EZNaCl

EZNaCl is an MIT-licensed library written in Rust that wraps around LibSodium and gets as close to push-button cryptography as a developer can feasibly be. At the same time, because it's cryptography, you still need to be very careful applying it.

No guarantees of any kind are provided with the library even though it has been written with care.

Also, please don't use this code to place important crypto keys in your code or embed backdoors. No one needs that kind of drama.

## Description

Cryptography is really hard. Any code which implements it is equally hard. Anything which touches the implementation code isn't much easier. NaCl and LibSodium made it a *lot* easier, but it's still kind of hard to figure out for newcomers to encryption. This library came from a need to work with crypto keys over a text-based protocol. It had the added benefit of easing debugging code which interacts with cryptography. 

## Usage

The library provides the following functionality:

- key generation for cryptographic signing and both secret key and public key encryption
- fast hashing with a variety of algorithms
- slow hashing for passwords using Argon2id

Full documentation for the library can be found at https://docs.rs/eznacl/latest/eznacl/

