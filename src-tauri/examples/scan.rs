//! Scans each file listed in the given text file (one path per line) and prints the results
//! as JSON lines. For checking the model outside the app.

use std::path::PathBuf;

fn main() {
    let list = std::env::args().nth(1).expect("usage: scan <file with paths>");
    let files: Vec<PathBuf> = std::fs::read_to_string(list).expect("cannot read the list").lines().map(PathBuf::from).collect();
    let scanner = defenser_lib::scanner::Scanner::new();
    if let Err(error) = scanner.info() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    let started = std::time::Instant::now();
    for result in scanner.scan_all(&files, |_| {}) {
        println!("{}", serde_json::to_string(&result).unwrap());
    }
    eprintln!("{} files in {:.1} s", files.len(), started.elapsed().as_secs_f32());
}
