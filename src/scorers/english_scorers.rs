use std::collections::HashMap;

/// Returns a score. The higher the score, the more likely the text is English.
pub fn english_score(bytes: &[u8]) -> f32 {
    // The frequency of each character in a sample of English-language texts, including spaces.
    let letter_frequency: HashMap<&char, f32> = [
        (&' ', 18.3), (&'e', 10.3), (&'t', 7.5), (&'a', 6.5), (&'o', 6.2), (&'n', 5.7), (&'i', 5.7), (&'s', 5.3), (&'r', 5.0),
        (&'h', 5.0), (&'l', 3.3), (&'d', 3.3), (&'u', 2.8), (&'c', 2.2), (&'m', 2.0), (&'f', 2.0), (&'w', 1.7), (&'g', 1.6),
        (&'p', 1.5), (&'y', 1.4), (&'b', 1.3), (&'v', 0.8), (&'k', 0.6), (&'x', 0.1), (&'j', 0.1), (&'q', 0.1), (&'z', 0.1)]
        .iter().cloned().collect();

    return bytes
        .iter()
        .filter_map(|x| letter_frequency.get(&(*x as char)))
        .sum();
}
