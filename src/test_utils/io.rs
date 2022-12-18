use std::fs::File;
use std::io::{BufRead, BufReader};

/// Reads each line from the provided file, and decodes it from hex.
pub fn read_hex_lines(file_path: &str) -> Vec<Vec<u8>> {
    let file = File::open(file_path).unwrap();
    BufReader::new(file)
        .lines()
        .map(|line| hex::decode(line.unwrap()).unwrap())
        .collect::<Vec<Vec<u8>>>()
}