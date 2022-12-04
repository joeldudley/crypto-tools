use crate::bitflips::xor::*;
use crate::scorers::english_scorers::*;

/// Returns the plaintext encoded using a single-byte XOR cipher. Works by selecting the XOR key
/// that results in the most "english-like" plaintext.
pub fn crack_single_byte_xor_cipher(ciphertext: &[u8]) -> String {
    let plaintext = (0u8..255)
        .map(|x| xor(ciphertext, &x))
        .max_by(|x, y| english_score(x).total_cmp(&english_score(y)))
        .expect("we know a value will be generated");

    return String::from_utf8_lossy(plaintext.as_slice()).to_string();
}

/// Returns the plaintext encoded using a single-byte XOR cipher among a list of possible
/// ciphertexts.
pub fn detect_and_crack_single_byte_xor_cipher(possible_ciphertexts: &[&[u8]]) -> Option<String> {
    return possible_ciphertexts
        .iter()
        .map(|x| crack_single_byte_xor_cipher(x))
        .max_by(|x, y| english_score(x.as_bytes()).total_cmp(&english_score(y.as_bytes())));
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use crate::crackers::xor_ciphers::*;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = "Cooking MC's like a pound of bacon";

        let ciphertext_bytes = hex::decode(ciphertext).expect("could not convert hex to bytes");
        let plaintext = crack_single_byte_xor_cipher(&ciphertext_bytes);
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 04.
    #[test]
    fn can_detect_and_crack_single_byte_xor_cipher() {
        let filename = "./src/crackers/4.txt";
        let file = File::open(filename).expect("could not read file");
        let ciphertexts = BufReader::new(file).lines();
        let expected_plaintext = "Now that the party is jumping\n";

        let ciphertexts_bytes_vec: Vec<Vec<u8>> = ciphertexts
            .map(|x| hex::decode(x.expect("could not read line"))
                .expect("could not convert hex to bytes"))
            .collect();
        let ciphertext_bytes: Vec<&[u8]> = ciphertexts_bytes_vec.iter().map(|x| &x[..]).collect();

        let plaintext = detect_and_crack_single_byte_xor_cipher(&ciphertext_bytes).expect("could not find plaintext");
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 06.
    #[test]
    fn can_detect_and_crack_repeating_key_xor_cipher() {
        let filename = "./src/crackers/6.txt";
        let file = File::open(filename).expect("could not read file");
        let ciphertexts = BufReader::new(file).lines();

        // TODO - Finish this test.
    }
}