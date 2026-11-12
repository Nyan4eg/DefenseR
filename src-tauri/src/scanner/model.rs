//! The file model: gradient-boosted trees trained by `ml/train.py`, run with ONNX Runtime.

use std::sync::Mutex;

use ort::environment::Environment;
use ort::session::Session;
use ort::value::Tensor;
use serde::{Deserialize, Serialize};

use super::features::FEATURE_COUNT;
use crate::lock;

static MODEL: &[u8] = include_bytes!("../../model/pe-model.onnx");
static INFO: &str = include_str!("../../model/pe-model.json");

/// How the model was trained and how it scored on the EMBER test set.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    pub feature_count: usize,
    pub dataset: String,
    pub trained: String,
    pub train_samples: u64,
    pub test_samples: u64,
    pub trees: u32,
    pub auc: f64,
    /// Scores at or above this are "suspicious".
    pub suspicious_threshold: f32,
    /// Scores at or above this are "malicious".
    pub malicious_threshold: f32,
    pub suspicious_detection: f64,
    pub suspicious_false_positives: f64,
    pub malicious_detection: f64,
    pub malicious_false_positives: f64,
}

pub struct Model {
    // A session cannot run two inferences at once.
    session: Mutex<Session>,
    _environment: Environment,
    pub info: ModelInfo,
}

impl Model {
    pub fn load() -> Result<Self, String> {
        let info: ModelInfo = serde_json::from_str(INFO).map_err(|e| format!("Описание модели повреждено: {e}"))?;
        if info.feature_count != FEATURE_COUNT {
            return Err(format!("Модель ждёт {} признаков, а приложение считает {FEATURE_COUNT}.", info.feature_count));
        }
        let failed = |e: String| format!("Не удалось загрузить модель: {e}");
        let environment = ort::init().build().map_err(|e| failed(e.to_string()))?;
        let session = Session::builder(&environment)
            .map_err(|e| failed(e.to_string()))?
            .with_intra_threads(1)
            .map_err(|e| failed(e.to_string()))?
            .commit_from_memory(MODEL)
            .map_err(|e| failed(e.to_string()))?;
        Ok(Self { session: Mutex::new(session), _environment: environment, info })
    }

    /// Probability, from 0 to 1, that the file with these features is malicious.
    pub fn score(&self, features: Vec<f32>) -> Result<f32, String> {
        let failed = |e: ort::Error| format!("Модель не смогла оценить файл: {e}");
        let input = Tensor::<f32>::from_array(([1, FEATURE_COUNT], features)).map_err(failed)?;
        let mut session = lock(&self.session);
        let outputs = session.run(ort::inputs![input]).map_err(failed)?;
        let (_, probabilities) = outputs["probabilities"].try_extract_tensor::<f32>().map_err(failed)?;
        probabilities.get(1).copied().ok_or_else(|| "Модель вернула неожиданный результат.".to_string())
    }
}
