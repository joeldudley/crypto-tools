use crate::bitflips::xor::*;
use crate::scorers::english_scorers::*;
use crate::scorers::hamming_distance::hamming_distance;

#[derive(Debug)]
pub struct EmptyArrayError;

/// Returns the key that was used to encrypt a ciphertext under a single-byte XOR cipher.
pub fn find_key_single_byte_xor_cipher(ciphertext: &[u8]) -> u8 {
    (0u8..255)
        .max_by(|x, y| {
            // We XOR both potential keys against the ciphertext, and choose the one that generates
            // the most "english-like" plaintext.
            let xor_one = xor(ciphertext, &x);
            let xor_two = xor(ciphertext, &y);
            english_score(xor_one.as_slice()).total_cmp(&english_score(xor_two.as_slice()))
        })
        .expect("we know a maximum will be found")
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

/// Finds the key size (of between 2 and 40 bytes) used to encrypt a repeating XOR cipher.
pub fn find_key_size_repeating_xor_cipher(ciphertext: &[u8]) -> usize {
    let candidate_keysizes = 2..41;
    candidate_keysizes
        .min_by(|x, y| average_normalised_hamming_distance(ciphertext, x)
            .total_cmp(&average_normalised_hamming_distance(ciphertext, y)))
        .expect("we know a minimum will be found")
}

/// Returns the average, normalised Hamming distance between four blocks of the provided text.
fn average_normalised_hamming_distance(text: &[u8], block_size: &usize) -> f64 {
    // TODO - See if I can use itertools to do this more elegantly.
    let block_one = &text[0..*block_size];
    let block_two = &text[*block_size..*block_size * 2];
    let block_three = &text[block_size * 2..block_size * 3];
    let block_four = &text[block_size * 3..block_size * 4];

    let total_hamming_distance = hamming_distance(block_one, block_two)
        + hamming_distance(block_one, block_three)
        + hamming_distance(block_one, block_four)
        + hamming_distance(block_two, block_three)
        + hamming_distance(block_three, block_four);

    let number_of_comparisons = 5;

    // The result is normalised (by dividing by the block size) and averaged (by dividing by the
    // number of comparisons performed).
    (total_hamming_distance as f64) / (number_of_comparisons as f64 * *block_size as f64)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    use crate::crackers::xor_ciphers::*;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = "Cooking MC's like a pound of bacon".as_bytes();

        let ciphertext_bytes = hex::decode(ciphertext).expect("could not convert hex to bytes");
        let key = find_key_single_byte_xor_cipher(&ciphertext_bytes);
        let plaintext = xor(&ciphertext_bytes, &key);
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 04.
    #[test]
    fn can_detect_and_crack_single_byte_xor_cipher() {
        let filename = "./src/crackers/4.txt";
        let file = File::open(filename).expect("could not open file");
        let ciphertexts_bytes_vec = BufReader::new(file)
            .lines()
            .map(|x| hex::decode(x.expect("could not read line"))
                .expect("could not convert hex to bytes"))
            .collect::<Vec<Vec<u8>>>();
        let ciphertexts_bytes = ciphertexts_bytes_vec.iter().map(|x| &x[..]).collect::<Vec<&[u8]>>();
        let expected_plaintext = "Now that the party is jumping\n".as_bytes();

        let plaintext = detect_and_crack_single_byte_xor_cipher(&ciphertexts_bytes)
            .expect("could not find plaintext");
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 06.
    #[test]
    fn can_detect_and_crack_repeating_key_xor_cipher() {
        let filename = "./src/crackers/6.txt";
        let file = File::open(filename).expect("could not open file");
        let ciphertext = BufReader::new(file)
            .lines()
            .map(|x| x.expect(""))
            .collect::<Vec<String>>()
            .join("");

        // TODO - Is there a way to only convert to bytes once?
        let keysize = find_key_size_repeating_xor_cipher(ciphertext.as_bytes());
        println!("jjj keysize: {}", keysize);

        let chunks: Vec<&[u8]> = ciphertext.as_bytes().chunks(keysize).collect();

        // for n in 0..keysize {
        //     let y = chunks
        //         .iter()
        //         .map(|chunk| chunk[n])
        //         .collect::<Vec<u8>>();
        //
        //     let result = crack_single_byte_xor_cipher(y.as_slice());
        //     result
        // }

        // TODO - Finish writing this test.
    }
}