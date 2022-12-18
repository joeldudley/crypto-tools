use std::collections::HashSet;
use std::str::from_utf8;

use openssl::symm::{Cipher, Crypter, decrypt};
use openssl::symm::Mode::Decrypt;

use crate::bitflips::xor::xor_vecs;

/// Indicates whether a ciphertext is likely encrypted with AES in ECB mode, by looking for 
/// repeating 16-byte ciphertext blocks.
pub fn is_aes_ecb_mode(ciphertext: &[u8]) -> bool {
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

/// todo - joel - describe
pub fn decrypt_cbc_mode(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let data_len = ciphertext.len();
    // todo - joel - use entire ciphertext
    let ciphertext = &ciphertext[..16];

    // Create a cipher context for decryption.
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Decrypt,
        key,
        Some(iv)).unwrap();
    decrypter.pad(false);
    let block_size = Cipher::aes_128_ecb().block_size();
    let mut plaintext = vec![0; data_len + block_size];

    let mut count = decrypter.update(ciphertext, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);

    // todo - joel - only xor against iv for first chunk
    let xored_chunk = xor_vecs(&plaintext, iv);
    return xored_chunk;
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use std::str::from_utf8;

    use openssl::symm::{Cipher, Crypter, decrypt, encrypt, Mode};
    use openssl::symm::Mode::Decrypt;

    use crate::ciphers::aes_ciphers::{decrypt_cbc_mode, is_aes_ecb_mode};
    use crate::test_utils::io::read_hex_lines;

    // Solution to Cryptopals set 1 challenge 07.
    #[test]
    fn can_decrypt_ecb_mode() {
        let ciphertext_file = File::open("./data/7.txt").expect("could not open file");
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.expect("could not read line"))
            .collect::<Vec<String>>()
            .join("");
        let plaintext_file = File::open("./data/7_plaintext.txt").expect("could not open file");
        let mut expected_plaintext = Vec::new();
        BufReader::new(plaintext_file).read_to_end(&mut expected_plaintext).expect("could not read file");

        let ciphertext = base64::decode(ciphertext_base64).expect("could not decode Base64 to bytes");
        let cipher = Cipher::aes_128_ecb();
        let key = b"YELLOW SUBMARINE";
        let plaintext = decrypt(cipher, key, None, &ciphertext).expect("could not decrypt ciphertext");
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 1 challenge 08.
    #[test]
    fn can_detect_ecb_mode() {
        let ciphertexts = read_hex_lines("./data/8.txt");
        let expected_ecb_ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

        let ecb_ciphertext = ciphertexts
            .iter()
            .find(|ciphertext| is_aes_ecb_mode(ciphertext))
            .expect("could not find ciphertext from AES in ECB mode");
        let ecb_ciphertext_hex = hex::encode(ecb_ciphertext);
        assert_eq!(ecb_ciphertext_hex, expected_ecb_ciphertext);
    }

    // Solution to Cryptopals set 2 challenge 10.
    #[test]
    fn can_decrypt_cbc_mode() {
        let ciphertext_file = File::open("./data/10.txt").expect("could not open file");
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.expect("could not read line"))
            .collect::<Vec<String>>()
            .join("");
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let key = b"YELLOW SUBMARINE";

        let ciphertext = base64::decode(ciphertext_base64).unwrap();
        let plaintext = decrypt_cbc_mode(&ciphertext, iv, key);

        println!("{}", from_utf8(&plaintext).unwrap())
    }
}