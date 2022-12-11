use crate::bitflips::xor::*;
use crate::ciphers::xor_ciphers::repeating_key_xor_cipher;
use crate::scorers::english_scorers::*;
use crate::scorers::hamming_distance::hamming_distance;

const MIN_KEYSIZE: usize = 2; // The smallest keysize checked for to crack an XOR cipher.
const MAX_KEYSIZE: usize = 40; // The largest keysize checked for to crack an XOR cipher.
const NUM_BLOCKS_AVG_DIST: usize = 10; // The number of blocks to calculate the average Hamming distance.

#[derive(Debug)]
pub struct EmptyArrayError;

/// Cracks a single-byte XOR cipher.
pub fn crack_single_byte_xor_cipher(ciphertext: &[u8]) -> Vec<u8> {
    let key = find_key_single_byte_xor_cipher(ciphertext);
    xor(ciphertext, &key)
}

/// Cracks a repeating-key XOR cipher.
pub fn crack_repeating_key_xor_cipher(ciphertext: &[u8]) -> Vec<u8> {
    let keysize = find_key_size_repeating_xor_cipher(ciphertext);
    let ciphertext_chunks: Vec<&[u8]> = ciphertext.chunks_exact(keysize).collect();
    let key: Vec<u8> = (0..keysize)
        .map(|i| {
            let chunks_ith_entries = ciphertext_chunks
                .iter()
                .map(|chunk| chunk[i])
                .collect::<Vec<u8>>();

            find_key_single_byte_xor_cipher(&chunks_ith_entries)
        })
        .collect();

    repeating_key_xor_cipher(ciphertext, &key)
}

/// Returns the plaintext encoded using a single-byte XOR cipher among a list of possible
/// ciphertexts.
pub fn detect_and_crack_single_byte_xor_cipher(possible_ciphertexts: &[&[u8]]) -> Result<Vec<u8>, EmptyArrayError> {
    if possible_ciphertexts.is_empty() {
        return Err(EmptyArrayError);
    }

    let plaintext = possible_ciphertexts
        .iter()
        .map(|x| xor(x, &find_key_single_byte_xor_cipher(x)))
        .max_by(|x, y| english_score(x).total_cmp(&english_score(y)))
        .expect("we know a maximum will be found")
        .to_vec();

    Ok(plaintext)
}

/// Returns the key that was used to encrypt a ciphertext under a single-byte XOR cipher.
fn find_key_single_byte_xor_cipher(ciphertext: &[u8]) -> u8 {
    (0u8..255)
        .max_by(|x, y| {
            // We XOR both potential keys against the ciphertext, and choose the one that generates
            // the most "english-like" plaintext.
            let xor_one = xor(ciphertext, x);
            let xor_two = xor(ciphertext, y);
            english_score(xor_one.as_slice()).total_cmp(&english_score(xor_two.as_slice()))
        })
        .expect("we know a maximum will be found")
}

/// Finds the key size (of between 2 and 40 bytes) used to encrypt a repeating XOR cipher.
fn find_key_size_repeating_xor_cipher(ciphertext: &[u8]) -> usize {
    let candidate_keysizes = MIN_KEYSIZE..MAX_KEYSIZE+1;
    candidate_keysizes
        .min_by(|x, y| average_hamming_distance(ciphertext, x)
            .total_cmp(&average_hamming_distance(ciphertext, y)))
        .expect("we know a minimum will be found")
}

/// Returns the average Hamming distance across consecutive blocks of the provided text.
fn average_hamming_distance(text: &[u8], block_size: &usize) -> f64 {
    let total_hamming_distance: usize = (0..NUM_BLOCKS_AVG_DIST)
        .map(|i| {
            let first_block = &text[block_size * i..block_size * (i+1)];
            let second_block = &text[block_size * (i+1)..block_size * (i+2)];
            hamming_distance(first_block, second_block)
        })
        .sum();

    // The result is normalised (by dividing by the block size) and averaged (by dividing by the
    // number of comparisons performed).
    (total_hamming_distance as f64) / (NUM_BLOCKS_AVG_DIST as f64 * *block_size as f64)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};

    use crate::crackers::xor_ciphers::*;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = b"Cooking MC's like a pound of bacon";

        let ciphertext = hex::decode(ciphertext_hex).expect("could not decode hex to bytes");
        let plaintext = crack_single_byte_xor_cipher(&ciphertext);
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 04.
    #[test]
    fn can_detect_and_crack_single_byte_xor_cipher() {
        let file = File::open("./data/4.txt").expect("could not open file");
        let ciphertexts = BufReader::new(file)
            .lines()
            .map(|x| hex::decode(x.expect("could not read line"))
                .expect("could not decode hex to bytes"))
            .collect::<Vec<Vec<u8>>>();
        let expected_plaintext = b"Now that the party is jumping\n";

        let ciphertexts_bytes = ciphertexts.iter().map(|x| &x[..]).collect::<Vec<&[u8]>>();
        let plaintext = detect_and_crack_single_byte_xor_cipher(&ciphertexts_bytes)
            .expect("could not find plaintext");
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 06.
    #[test]
    fn can_detect_and_crack_repeating_key_xor_cipher() {
        let ciphertext_file = File::open( "./data/6.txt").expect("could not open file");
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.expect("could not read line"))
            .collect::<Vec<String>>()
            .join("");
        let plaintext_file = File::open("./data/6_plaintext.txt").expect("could not open file");
        let mut expected_plaintext = Vec::new();
        BufReader::new(plaintext_file).read_to_end(&mut expected_plaintext).expect("could not read file");

        let ciphertext = base64::decode(ciphertext_base64).expect("could not decode Base64 to bytes");
        let plaintext = crack_repeating_key_xor_cipher(&ciphertext);
        assert_eq!(plaintext, expected_plaintext);
    }
}