
/// Encodes the plaintext using a repeating-key XOR cipher.
pub fn repeating_key_xor_cipher(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|x| x.1 ^ key[x.0 % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::ciphers::xor_ciphers::repeating_key_xor_cipher;

    // Solution to Cryptopals set 01 challenge 05.
    #[test]
    fn can_encrypt_with_repeating_key_xor() {
        let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";
        let expected_ciphertext_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let ciphertext = repeating_key_xor_cipher(plaintext, key);
        let expected_ciphertext = hex::decode(expected_ciphertext_hex).unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
    }
}