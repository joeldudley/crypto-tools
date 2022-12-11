
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use openssl::symm::{Cipher, decrypt};

    // Solution to Cryptopals set 1 challenge 07.
    #[test]
    fn can_decrypt_aes_in_ecb_mode() {
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
}