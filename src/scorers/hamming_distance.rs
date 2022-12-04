use crate::converters::binary::plaintext_to_binary;

/// Returns the Hamming distance between two strings.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let a_binary = plaintext_to_binary(a);
    let b_binary = plaintext_to_binary(b);

    // The Hamming distance is the number of non-matching bits.
    a_binary.as_bytes().iter()
        .zip(b_binary.as_bytes().iter())
        .map(|(x, y)| x == y)
        .filter(|x| !(*x))
        .count()
}

#[cfg(test)]
mod tests {
    use crate::scorers::hamming_distance::hamming_distance;

    #[test]
    fn can_convert_hex_to_base_64() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        let expected_hamming_distance = 37;

        let hamming_distance = hamming_distance(a.as_ref(), b.as_ref());
        assert_eq!(hamming_distance, expected_hamming_distance)
    }
}