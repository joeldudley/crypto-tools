
/// Returns the Hamming distance between two strings.
pub fn hamming_distance(a: &str, b: &str) -> usize {
    // todo - joel - fold into method
    let a_binary = a
        .as_bytes()
        .iter()
        .map(|x| format!("{x:08b}"))
        .collect::<Vec<String>>()
        .join("");

    let b_binary = b
        .as_bytes()
        .iter()
        .map(|x| format!("{x:08b}"))
        .collect::<Vec<String>>()
        .join("");

    a_binary.as_bytes().iter()
        .zip(b_binary.as_bytes().iter())
        .map(|(x, y)| x == y)
        .filter(|x| *x == false)
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

        let hamming_distance = hamming_distance(a, b);
        assert_eq!(hamming_distance, expected_hamming_distance)
    }
}