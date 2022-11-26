extern crate base64;
extern crate hex;

#[derive(Debug)]
pub struct ConversionError;

/// Converts a hex string to a Base64 string.
#[allow(dead_code)]
pub fn hex_to_base_64(hex: &str) -> Result<String, ConversionError> {
    let bytes_result = hex::decode(hex);
    return match bytes_result {
        Ok(bytes) => Ok(base64::encode(bytes)),
        Err(_) => Err(ConversionError),
    };
}

#[cfg(test)]
mod tests {
    use crate::converters::hex::*;

    /// Solution to Cryptopals s01c01.
    #[test]
    fn can_convert_hex_to_base_64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base_64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base_64 = hex_to_base_64(hex).expect("could not convert hex to base64");
        assert_eq!(base_64, expected_base_64);
    }
}