/// Converts a plaintext string to a binary string.
#[allow(dead_code)]
pub fn plaintext_to_binary(plaintext: &[u8]) -> String {
    plaintext
        .iter()
        .map(|x| format!("{x:08b}"))
        .collect::<Vec<String>>()
        .join("")
}