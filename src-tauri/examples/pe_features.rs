//! Prints the model's feature vector for each file listed in the given text file
//! (one path per line), as JSON lines. Used by `ml/parity.py`.

use std::io::Write;

fn main() {
    let list = std::env::args().nth(1).expect("usage: pe_features <file with paths>");
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for path in std::fs::read_to_string(list).expect("cannot read the list").lines() {
        let vector = match std::fs::read(path) {
            Ok(bytes) => defenser_lib::scanner::features::extract(&bytes).vector,
            Err(_) => Vec::new(),
        };
        writeln!(out, "{}", serde_json::to_string(&vector).unwrap()).unwrap();
    }
}
