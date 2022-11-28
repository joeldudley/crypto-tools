use crate::bitflips::xor::*;
use crate::scorers::english_scorers::*;

/// Cracks a ciphertext encoded using a single-byte XOR cipher.
pub fn crack_single_byte_xor_cipher(bytes: &[u8]) -> String {
    let mut plaintext = Vec::new();
    let mut max_score = 0.0;

    for i in 0u8..255 {
        let xored_bytes = xor(bytes, &i);
        let score = english_score(&xored_bytes);
        if score > max_score {
            plaintext = xored_bytes;
            max_score = score;
        }
    }

    return String::from_utf8_lossy(plaintext.as_slice()).to_string();
}

#[cfg(test)]
mod tests {
    use crate::crackers::xor_ciphers::*;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = "Cooking MC's like a pound of bacon";

        let ciphertext_bytes = hex::decode(ciphertext).expect("could not convert hex to bytes");
        let plaintext = crack_single_byte_xor_cipher(&ciphertext_bytes);
        assert_eq!(expected_plaintext, plaintext);
    }
}