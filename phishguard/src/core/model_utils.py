from typing import Dict, List, Any
import numpy as np
import joblib
import os


def features_to_vector(features: Dict[str, Any], feature_names: List[str]) -> np.ndarray:
    """Convert feature dict to a numpy vector following the provided feature_names order."""
    vec = []
    for name in feature_names:
        val = features.get(name, 0)
        if isinstance(val, bool):
            val = 1 if val else 0
        elif val is None:
            val = 0
        vec.append(val)
    return np.array(vec, dtype=float)


def save_model_bundle(model: Any, feature_names: List[str], threshold: float, path: str) -> None:
    """Save model and metadata as a joblib bundle."""
    bundle = {
        "model": model,
        "feature_names": feature_names,
        "threshold": float(threshold),
        "version": 1,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(bundle, path)


def load_model_bundle(path: str):
    """Load model bundle if it exists, else return None."""
    if not os.path.exists(path):
        return None
    bundle = joblib.load(path)
    # Light validation
    if not isinstance(bundle, dict) or "model" not in bundle or "feature_names" not in bundle:
        return None
    if "threshold" not in bundle:
        bundle["threshold"] = 0.5
    return bundle
