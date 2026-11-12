//! Static file analysis: PE feature extraction and the local ML model.
//! Files are only read, never executed, and nothing leaves the computer.

pub mod features;
pub mod model;
pub mod pe;
pub mod signature;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::lock;
use model::{Model, ModelInfo};
use signature::Signature;

/// Larger files are not read into memory.
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
/// A folder scan stops collecting files at this many.
const MAX_FILES: usize = 20_000;
const WORKERS: usize = 4;
/// Batches up to this size get every program's signature verified.
const VERIFY_ALL_LIMIT: usize = 300;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    /// Not a Windows executable, so the model does not apply.
    NotExecutable,
    Error,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub verdict: Verdict,
    /// Model's probability that the file is malicious.
    pub score: Option<f32>,
    pub sha256: Option<String>,
    /// Windows' verdict on the file's signature; `None` until it has been verified.
    pub signature: Option<Signature>,
    pub max_section_entropy: Option<f32>,
    pub error: Option<String>,
}

struct Cached {
    size: u64,
    modified: Option<SystemTime>,
    result: ScanResult,
}

pub struct Scanner {
    model: Result<Model, String>,
    cache: Mutex<HashMap<PathBuf, Cached>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self { model: Model::load(), cache: Mutex::new(HashMap::new()) }
    }

    pub fn info(&self) -> Result<ModelInfo, String> {
        self.model.as_ref().map(|model| model.info.clone()).map_err(Clone::clone)
    }

    /// The cached result for a file, if the file has not changed since it was scanned.
    pub fn cached(&self, path: &Path) -> Option<ScanResult> {
        let metadata = std::fs::metadata(path).ok()?;
        let cache = lock(&self.cache);
        let entry = cache.get(path)?;
        (entry.size == metadata.len() && entry.modified == metadata.modified().ok()).then(|| entry.result.clone())
    }

    pub fn scan(&self, path: &Path) -> ScanResult {
        if let Some(result) = self.cached(path) {
            return result;
        }
        let metadata = std::fs::metadata(path);
        let mut result = ScanResult {
            path: path.to_string_lossy().into_owned(),
            name: path.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
            size: metadata.as_ref().map_or(0, |m| m.len()),
            verdict: Verdict::Error,
            score: None,
            sha256: None,
            signature: None,
            max_section_entropy: None,
            error: None,
        };
        match self.analyze(path, &mut result) {
            Ok(verdict) => result.verdict = verdict,
            Err(error) => result.error = Some(error),
        }
        if let Ok(metadata) = metadata {
            let entry = Cached { size: metadata.len(), modified: metadata.modified().ok(), result: result.clone() };
            lock(&self.cache).insert(path.to_path_buf(), entry);
        }
        result
    }

    fn analyze(&self, path: &Path, result: &mut ScanResult) -> Result<Verdict, String> {
        if result.size > MAX_FILE_SIZE {
            return Err("Файл больше 256 МБ, проверка пропущена.".to_string());
        }
        let bytes = std::fs::read(path).map_err(|e| format!("Не удалось прочитать файл: {e}"))?;
        result.sha256 = Some(Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect());

        let extracted = features::extract(&bytes);
        if extracted.pe.is_none() {
            return Ok(Verdict::NotExecutable);
        }
        result.max_section_entropy = Some(extracted.max_section_entropy as f32);

        let model = self.model.as_ref().map_err(Clone::clone)?;
        let score = model.score(extracted.vector)?;
        result.score = Some(score);
        Ok(if score >= model.info.malicious_threshold {
            Verdict::Malicious
        } else if score >= model.info.suspicious_threshold {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        })
    }

    /// Fills in the signature of scanned programs that do not have one yet. Verification is
    /// slow, so in a large batch only the files the model flagged are verified.
    fn verify_signatures(&self, results: &mut [ScanResult]) {
        let verify_all = results.len() <= VERIFY_ALL_LIMIT;
        let pending: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, r)| r.signature.is_none() && r.score.is_some())
            .filter(|(_, r)| verify_all || matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious))
            .map(|(index, _)| index)
            .collect();
        let paths: Vec<PathBuf> = pending.iter().map(|&index| PathBuf::from(&results[index].path)).collect();

        let mut cache = lock(&self.cache);
        for ((index, path), signature) in pending.into_iter().zip(&paths).zip(signature::verify(&paths)) {
            results[index].signature = Some(signature.clone());
            if let Some(entry) = cache.get_mut(path) {
                entry.result.signature = Some(signature);
            }
        }
    }

    /// Scans files on a few threads. `progress` gets the number of files finished so far.
    pub fn scan_all(&self, files: &[PathBuf], progress: impl Fn(usize) + Sync) -> Vec<ScanResult> {
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let results = Mutex::new(Vec::with_capacity(files.len()));
        std::thread::scope(|scope| {
            for _ in 0..WORKERS.min(files.len()) {
                scope.spawn(|| {
                    while let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let result = self.scan(path);
                        lock(&results).push(result);
                        progress(done.fetch_add(1, Ordering::Relaxed) + 1);
                    }
                });
            }
        });
        let mut results = results.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.verify_signatures(&mut results);
        // Most alarming first.
        results.sort_by(|a, b| b.score.unwrap_or(-1.0).total_cmp(&a.score.unwrap_or(-1.0)).then_with(|| a.path.cmp(&b.path)));
        results
    }
}

fn starts_with_mz(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 2];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut magic)).is_ok() && &magic == b"MZ"
}

/// Expands the user's selection: files are taken as they are, folders are searched
/// recursively for Windows executables.
pub fn collect_files(selection: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut folders = Vec::new();
    for path in selection.iter().map(PathBuf::from) {
        if path.is_dir() {
            folders.push(path);
        } else {
            files.push(path);
        }
    }
    while let Some(folder) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten() {
            if files.len() >= MAX_FILES {
                return files;
            }
            // `file_type` does not follow links, so a link loop cannot trap the walk.
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                folders.push(entry.path());
            } else if kind.is_file() && starts_with_mz(&entry.path()) {
                files.push(entry.path());
            }
        }
    }
    files
}
