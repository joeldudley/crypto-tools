use crate::bitflips::xor::*;
use crate::ciphers::xor_ciphers::repeating_key_xor_cipher;
use crate::scorers::english_scorers::*;
use crate::scorers::hamming_distance::hamming_distance;

const MIN_KEYSIZE: usize = 2; // The smallest keysize checked for to crack an XOR cipher.
const MAX_KEYSIZE: usize = 40; // The largest keysize checked for to crack an XOR cipher.
const NUM_BLOCKS_AVG_DIST: usize = 10; // The number of blocks to calculate the average Hamming distance.

#[derive(Debug)]
pub struct EmptyArrayError;

pub fn crack_single_byte_xor_cipher(ciphertext: &[u8]) -> Vec<u8> {
    let key = find_key_single_byte_xor_cipher(ciphertext);
    xor(ciphertext, &key)
}

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

fn find_key_size_repeating_xor_cipher(ciphertext: &[u8]) -> usize {
    let candidate_keysizes = MIN_KEYSIZE..MAX_KEYSIZE+1;
    candidate_keysizes
        .min_by(|x, y| average_hamming_distance(ciphertext, x)
            .total_cmp(&average_hamming_distance(ciphertext, y)))
        .expect("we know a minimum will be found")
}

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
    use crate::test_utils::io::read_hex_lines;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = b"Cooking MC's like a pound of bacon";

        let ciphertext = hex::decode(ciphertext_hex).unwrap();
        let plaintext = crack_single_byte_xor_cipher(&ciphertext);
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 04.
    #[test]
    fn can_detect_and_crack_single_byte_xor_cipher() {
        let ciphertexts = read_hex_lines("./data/4.txt");
        let expected_plaintext = b"Now that the party is jumping\n";

        let ciphertexts_bytes = ciphertexts.iter().map(|x| &x[..]).collect::<Vec<&[u8]>>();
        let plaintext = detect_and_crack_single_byte_xor_cipher(&ciphertexts_bytes).unwrap();
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 06.
    #[test]
    fn can_detect_and_crack_repeating_key_xor_cipher() {
        let ciphertext_file = File::open( "./data/6.txt").unwrap();
        let ciphertext_base64 = BufReader::new(ciphertext_file)
            .lines()
            .map(|line| line.unwrap())
            .collect::<Vec<String>>()
            .join("");
        let plaintext_file = File::open("./data/6_plaintext.txt").unwrap();
        let mut expected_plaintext = Vec::new();
        BufReader::new(plaintext_file).read_to_end(&mut expected_plaintext).unwrap();

        let ciphertext = base64::decode(ciphertext_base64).unwrap();
        let plaintext = crack_repeating_key_xor_cipher(&ciphertext);
        assert_eq!(plaintext, expected_plaintext);
    }
}