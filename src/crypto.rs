use magic_crypt::*;
use sha3::{Digest, Sha3_256};

pub fn hash(s: &str) -> String {
    // lager sha256 instens
    let mut hasher = Sha3_256::new();
    // gjør passord til bytes og legger til i hasher
    hasher.update(s.as_bytes());
    // hasher passord
    let hashed_s = hasher.finalize();
    // formaterer og returnerer hashed som string i stedet for bytes
    return format!("{:x}", hashed_s);
}

pub fn encrypt(key: &str, s: &str) -> String {
    // lager mcrypt instens medm 256 bytes og oppretter key
    let mcrypt = new_magic_crypt!(key, 256);
    // krypterer string to base64
    let encrypted_s = mcrypt.encrypt_to_base64(s);
    // returnerer det som string
    return encrypted_s.to_string();
}

pub fn decrypt(key: &str, s: &str) -> String {
    // lager mcrypt instens med 256 bytes og oppretter key
    let mcrypt = new_magic_crypt!(&key, 256);
    // dekrypterer string til string
    let decrypted_s = mcrypt.decrypt_base64_to_string(&s).unwrap();
    // returnerer det som string
    return decrypted_s.to_string();
}
