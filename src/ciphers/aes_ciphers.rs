use std::collections::HashSet;

/// Indicates whether a ciphertext is likely encrypted with AES in ECB mode, by looking for 
/// repeating 16-byte ciphertext blocks.
pub fn is_aes_ecb_mode(bytes: &[u8]) -> bool {
    let chunks = bytes.chunks(16);
    let mut chunks_seen = HashSet::new();
    
    // We use a `for` loop so that we can return early.
    for chunk in chunks {
        if chunks_seen.contains(chunk) {
            // We've seen this ciphertext before.
            return true;
        }
        chunks_seen.insert(chunk);
    }
    return false;
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use openssl::symm::{Cipher, decrypt};
    use crate::ciphers::aes_ciphers::is_aes_ecb_mode;

    // Solution to Cryptopals set 1 challenge 07.
    #[test]
    fn can_decrypt_aes_ecb_mode() {
        let ciphertext_file = File::open( "./data/7.txt").expect("could not open file");
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
    fn can_detect_aes_ecb_mode() {
        let file = File::open( "./data/8.txt").expect("could not open file");
        let ciphertexts = BufReader::new(file)
            .lines()
            .map(|x| hex::decode(x.expect("could not read line"))
                .expect("could not decode hex to bytes"))
            .collect::<Vec<Vec<u8>>>();
        let expected_ecb_ciphertext = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        
        let ecb_ciphertext = ciphertexts
            .iter()
            .find(|ciphertext| is_aes_ecb_mode(ciphertext))
            .expect("could not find ciphertext from AES in ECB mode");
        let ecb_ciphertext_hex = hex::encode(ecb_ciphertext);
        assert_eq!(ecb_ciphertext_hex, expected_ecb_ciphertext);
    }
}