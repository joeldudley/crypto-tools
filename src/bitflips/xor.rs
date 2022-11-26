
/// XORs two byte vectors.
fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    return a
        .iter()
        .zip(b.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
}

#[cfg(test)]
mod tests {
    use crate::bitflips::xor::*;

    #[test]
    fn can_xor_two_byte_vectors() {
        let hex_a = "1c0111001f010100061a024b53535009181c";
        let hex_b = "686974207468652062756c6c277320657965";
        let expected_xor_hex = "746865206b696420646f6e277420706c6179";

        let bytes_a = hex::decode(hex_a).expect("could not convert hex to bytes");
        let bytes_b = hex::decode(hex_b).expect("could not convert hex to bytes");
        let expected_xor_bytes = hex::decode(expected_xor_hex).expect("could not convert hex to bytes");

        assert_eq!(xor(&bytes_a, &bytes_b), expected_xor_bytes)
    }
}