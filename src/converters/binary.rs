/// Converts a plaintext string to a binary string.
#[allow(dead_code)]
pub fn plaintext_to_binary(plaintext: &str) -> String {
    plaintext
        .as_bytes()
        .iter()
        .map(|x| format!("{x:08b}"))
        .collect::<Vec<String>>()
        .join("")
}