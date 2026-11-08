// Types mirroring the PhishGuard backend API responses.

export interface FeatureValue {
  name: string;
  value: number;
  description: string;
}

export interface Probabilities {
  legitimate: number;
  phishing: number;
}

export interface ScanResult {
  url: string;
  model: string;
  model_display_name: string;
  is_phishing: boolean;
  label: string;
  confidence: number;
  probabilities: Probabilities;
  features: FeatureValue[];
}

export interface ModelMetrics {
  test_accuracy?: number;
  test_precision?: number;
  test_recall?: number;
  test_f1?: number;
  test_roc_auc?: number;
  cv5_accuracy_mean?: number;
  cv5_accuracy_std?: number;
  confusion_matrix?: number[][];
}

export interface ModelInfo {
  name: string;
  display_name: string;
  metrics: ModelMetrics;
  is_default: boolean;
}

export interface ModelsResponse {
  default_model: string;
  trained_at?: string;
  n_samples?: number;
  models: ModelInfo[];
}
