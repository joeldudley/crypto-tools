
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};

    use crate::crackers::xor_ciphers::*;
    use crate::test_utils::io::read_hex_lines;

    // Solution to Cryptopals set 02 challenge 09.
    #[test]
    fn can_add_pksc7_padding() {
        // TODO - Implement padding.
    }
}