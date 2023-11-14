use std::num::TryFromIntError;

pub fn pad_pkcs7(input: &[u8], padded_len: usize) -> Result<Vec<u8>, TryFromIntError> {
    let padding_len = padded_len - input.len();
    let padding_byte = match u8::try_from(padding_len) {
        Err(e) => return Err(e),
        Ok(padding_byte) => padding_byte
    };
    let padding = vec![padding_byte; padding_len];

    let mut output = input.to_vec();
    output.extend(padding);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use crate::padding::pkcs7::pad_pkcs7;

    // Solution to Cryptopals set 02 challenge 09.
    #[test]
    fn can_add_pksc7_padding() {
        let unpadded_value = "YELLOW_SUBMARINE".as_bytes();
        let padded_len = 20;
        let mut expected_padded_value = unpadded_value.to_vec();
        expected_padded_value.extend(b"\x04\x04\x04\x04");

        let padded_value = pad_pkcs7(unpadded_value, padded_len);
        assert_eq!(padded_value, Ok(expected_padded_value));
    }
}