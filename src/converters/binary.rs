pub fn plaintext_to_binary(plaintext: &[u8]) -> String {
    plaintext
        .iter()
        .map(|x| format!("{x:08b}"))
        .collect::<Vec<String>>()
        .join("")
}