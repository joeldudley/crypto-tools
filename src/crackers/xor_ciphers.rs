use crate::bitflips::xor::*;
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
            let xor_one = xor(ciphertext, &x);
            let xor_two = xor(ciphertext, &y);
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
    use std::io::{BufRead, BufReader};
    use crate::ciphers::xor_ciphers::repeating_key_xor_cipher;

    use crate::crackers::xor_ciphers::*;

    // Solution to Cryptopals set 01 challenge 03.
    #[test]
    fn can_crack_single_byte_xor_cipher() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected_plaintext = "Cooking MC's like a pound of bacon".as_bytes();

        let ciphertext_bytes = hex::decode(ciphertext).expect("could not convert hex to bytes");
        let plaintext = crack_single_byte_xor_cipher(&ciphertext_bytes);
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 04.
    #[test]
    fn can_detect_and_crack_single_byte_xor_cipher() {
        let filename = "./src/crackers/4.txt";
        let file = File::open(filename).expect("could not open file");
        let ciphertexts = BufReader::new(file)
            .lines()
            .map(|x| hex::decode(x.expect("could not read line"))
                .expect("could not convert hex to bytes"))
            .collect::<Vec<Vec<u8>>>();
        let expected_plaintext = "Now that the party is jumping\n".as_bytes();

        let ciphertexts_bytes = ciphertexts.iter().map(|x| &x[..]).collect::<Vec<&[u8]>>();
        let plaintext = detect_and_crack_single_byte_xor_cipher(&ciphertexts_bytes)
            .expect("could not find plaintext");
        assert_eq!(plaintext, expected_plaintext);
    }

    // Solution to Cryptopals set 01 challenge 06.
    #[test]
    fn can_detect_and_crack_repeating_key_xor_cipher() {
        // todo - joel - clean up the empty expects
        let filename = "./src/crackers/6.txt";
        let file = File::open(filename).expect("could not open file");
        let ciphertext = BufReader::new(file)
            .lines()
            .map(|line| line.expect("could not read line"))
            .collect::<Vec<String>>()
            .join("");
        let expected_plaintext = "I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
".as_bytes();

        let ciphertext_bytes = base64::decode(ciphertext).expect("");

        let keysize = find_key_size_repeating_xor_cipher(&ciphertext_bytes);

        let chunks: Vec<&[u8]> = ciphertext_bytes.chunks_exact(keysize).collect();

        let key: Vec<u8> = (0..keysize)
            .map(|i| {
                let ith_chunk_entries = chunks
                    .iter()
                    .map(|chunk| chunk[i])
                    .collect::<Vec<u8>>();

                find_key_single_byte_xor_cipher(&ith_chunk_entries)
            })
            .collect();

        let plaintext = repeating_key_xor_cipher(&ciphertext_bytes, &key);

        assert_eq!(plaintext, expected_plaintext);
    }
}