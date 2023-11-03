use std::collections::HashSet;

use openssl::symm::{Cipher, Crypter};
use openssl::symm::Mode::Decrypt;

use crate::bitflips::xor::xor_vecs;

pub fn is_encoded_using_aes_ecb_mode(ciphertext: &[u8]) -> bool {
    let chunks = ciphertext.chunks(16);
    let mut chunks_seen = HashSet::new();

    // We use a `for` loop so that we can return early.
    for chunk in chunks {
        if chunks_seen.contains(chunk) {
            // We've seen this ciphertext before.
            return true;
        }
        chunks_seen.insert(chunk);
    }
    false
}

pub fn decrypt_ecb_mode(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = Cipher::aes_128_ecb().block_size();
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Decrypt,
        key,
        Some(iv)).unwrap();
    decrypter.pad(false);

    let mut cbc_ciphertext = vec![0; ciphertext.len() + block_size];
    let count = decrypter.update(ciphertext, &mut cbc_ciphertext).unwrap();
    decrypter.finalize(&mut cbc_ciphertext[count..]).unwrap();

    cbc_ciphertext
}

pub fn decrypt_cbc_mode(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = Cipher::aes_128_ecb().block_size();
    let cbc_ciphertext = decrypt_ecb_mode(ciphertext, iv, key);

    let mut plaintext = Vec::new();
    let mut pos = 0;

    while pos * 16 < ciphertext.len() {
        let previous_block= if pos == 0 {
            iv
        } else {
            &ciphertext[(pos - 1) * block_size..pos * block_size]
        };
        let plaintext_block = xor_vecs(&cbc_ciphertext[pos * block_size..(pos + 1) * block_size], previous_block);
        plaintext.push(plaintext_block);
        pos += 1
    }

    plaintext.concat()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use base64::Engine;
    use base64::engine::general_purpose;

    use crate::ciphers::aes_ciphers::{decrypt_cbc_mode, decrypt_ecb_mode, is_encoded_using_aes_ecb_mode};
    use crate::test_utils::io::read_hex_lines;

    // Solution to Cryptopals set 01 challenge 07.
    #[test]
    fn can_decrypt_ecb_mode() {
        let ciphertext_file = File::open("./data/7.txt").unwrap();
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.unwrap())
            .collect::<Vec<String>>()
            .join("");
        let ciphertext = general_purpose::STANDARD.decode(&ciphertext_base64).unwrap();

        let plaintext_file = File::open("./data/7_plaintext.txt").unwrap();
        let mut expected_plaintext = Vec::new();
        BufReader::new(plaintext_file).read_to_end(&mut expected_plaintext).unwrap();

        let plaintext = decrypt_ecb_mode(&ciphertext, b"", b"YELLOW SUBMARINE");
        assert_eq!(plaintext[0..plaintext.len() - 20], expected_plaintext);
    }

    // Solution to Cryptopals set 1 challenge 08.
    #[test]
    fn can_detect_ecb_mode() {
        let ciphertexts = read_hex_lines("./data/8.txt");
        let expected_ciphertext_hex = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

        let ecb_ciphertext = ciphertexts
            .iter()
            .find(|ciphertext| is_encoded_using_aes_ecb_mode(ciphertext))
            .unwrap();
        let ecb_ciphertext_hex = hex::encode(ecb_ciphertext);
        assert_eq!(ecb_ciphertext_hex, expected_ciphertext_hex);
    }

    // Solution to Cryptopals set 02 challenge 10.
    #[test]
    fn can_decrypt_cbc_mode() {
        let ciphertext_file = File::open("./data/10.txt").unwrap();
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.unwrap())
            .collect::<Vec<String>>()
            .join("");
        let ciphertext = general_purpose::STANDARD.decode(ciphertext_base64).unwrap();

        let plaintext_file = File::open("./data/7_plaintext.txt").unwrap();
        let mut expected_plaintext = Vec::new();
        BufReader::new(plaintext_file).read_to_end(&mut expected_plaintext).unwrap();

        let plaintext = decrypt_cbc_mode(
            &ciphertext,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"YELLOW SUBMARINE",
        );
        assert_eq!(plaintext[0..plaintext.len() - 4], expected_plaintext);
    }
}