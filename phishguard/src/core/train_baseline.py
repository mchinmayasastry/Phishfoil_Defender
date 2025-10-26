import os
import argparse
import pandas as pd
from typing import List
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from .feature_extractor import FeatureExtractor
from .model_utils import features_to_vector, save_model_bundle


def load_dataset(csv_path: str) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Expected columns: url,label (1=malicious,0=safe)")
    df = pd.read_csv(csv_path)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("CSV must contain 'url' and 'label' columns")
    return df


def build_features(urls: List[str], extractor: FeatureExtractor):
    X_dicts = [extractor.extract_features(u) for u in urls]
    feature_names = extractor.get_feature_names()
    import numpy as np
    X = np.vstack([features_to_vector(d, feature_names) for d in X_dicts])
    return X, feature_names


def main():
    parser = argparse.ArgumentParser(description="Train baseline phishing URL classifier")
    parser.add_argument("--data", default=os.path.join("data", "urls.csv"), help="Path to CSV dataset")
    parser.add_argument("--out", default=os.path.join("models", "Phishfoil_Defender_model.joblib"), help="Output model path")
    args = parser.parse_args()

    df = load_dataset(args.data)
    extractor = FeatureExtractor()

    X, feature_names = build_features(df["url"].tolist(), extractor)
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=300, max_depth=None, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_proba = clf.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)

    print(classification_report(y_test, y_pred, digits=4))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_proba))
    except Exception:
        pass

    # Save bundle with default threshold 0.5
    save_model_bundle(clf, feature_names, threshold=0.5, path=args.out)
    print(f"Saved model to {args.out}")


if __name__ == "__main__":
    main()

import os
import argparse
import pandas as pd
from typing import List
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from .feature_extractor import FeatureExtractor
from .model_utils import features_to_vector, save_model_bundle


def load_dataset(csv_path: str) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Expected columns: url,label (1=malicious,0=safe)")
    df = pd.read_csv(csv_path)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("CSV must contain 'url' and 'label' columns")
    return df


def build_features(urls: List[str], extractor: FeatureExtractor):
    X_dicts = [extractor.extract_features(u) for u in urls]
    feature_names = extractor.get_feature_names()
    import numpy as np
    X = np.vstack([features_to_vector(d, feature_names) for d in X_dicts])
    return X, feature_names


def main():
    parser = argparse.ArgumentParser(description="Train baseline phishing URL classifier")
    parser.add_argument("--data", default=os.path.join("data", "urls.csv"), help="Path to CSV dataset")
    parser.add_argument("--out", default=os.path.join("models", "phishguard_model.joblib"), help="Output model path")
    args = parser.parse_args()

    df = load_dataset(args.data)
    extractor = FeatureExtractor()

    X, feature_names = build_features(df["url"].tolist(), extractor)
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=300, max_depth=None, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_proba = clf.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)

    print(classification_report(y_test, y_pred, digits=4))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_proba))
    except Exception:
        pass

    # Save bundle with default threshold 0.5
    save_model_bundle(clf, feature_names, threshold=0.5, path=args.out)
    print(f"Saved model to {args.out}")


if __name__ == "__main__":
    main()
