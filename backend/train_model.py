"""
PhishGuard AI — Model Training, Preprocessing & Artifact Calibration Pipeline
=============================================================================
Trains and validates the 55-feature Multi-Layer Perceptron (MLP) Neural Network
(`mlp_model.joblib`), `ColumnTransformer` preprocessing pipeline (`preprocessor.joblib`),
feature schema (`feature_columns.json`), and clean TLD lookup metadata (`lookup_metadata.json`).
"""

from pathlib import Path
import json
import re
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"

NUMERIC_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasSocialNet",
    "HasSubmitButton",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
    "IsHTTPS",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasExternalFormSubmit",
    "HasHiddenFields",
    "HasPasswordField",
    "HSTSHeaderPresent",
    "ContentSecurityPolicyPresent",
    "SecurityFeatureSum",
    "PathLengthRatio",
    "HasSuspiciousKeywords",
]

CATEGORICAL_FEATURES = ["TLD"]

FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLD",
    *NUMERIC_FEATURES[3:],
]


def build_preprocessing_pipeline() -> ColumnTransformer:
    """Construct the scikit-learn ColumnTransformer for the 55 PhishGuard AI features."""
    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "ohe",
                OneHotEncoder(
                    handle_unknown="ignore",
                    min_frequency=50,
                    sparse_output=False,
                ),
            ),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("num", numeric_pipeline, NUMERIC_FEATURES),
            ("cat", categorical_pipeline, CATEGORICAL_FEATURES),
        ]
    )


def build_mlp_classifier() -> MLPClassifier:
    """Construct the Multi-Layer Perceptron (MLP) neural network architecture."""
    return MLPClassifier(
        hidden_layer_sizes=(64, 32),
        batch_size=256,
        early_stopping=True,
        max_iter=50,
        n_iter_no_change=5,
        random_state=42,
    )


def clean_lookup_metadata(meta_path: Path) -> dict:
    """Ensure lookup_metadata.json contains only valid IANA alphabetic/punycode TLDs."""
    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    raw_tld_map = metadata.get("tld_prob_map", {})
    cleaned_tld_map = {
        k.lower(): float(v)
        for k, v in raw_tld_map.items()
        if re.match(r"^([a-z]{2,}|xn--[a-z0-9]+)(\.[a-z]{2,})?$", k.lower()) and float(v) > 0.0
    }
    metadata["tld_prob_map"] = cleaned_tld_map

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def train_from_dataset(csv_path: Path) -> None:
    """
    Train the preprocessor and MLP neural network from a raw dataset CSV
    and export all 4 production artifacts into backend/artifacts/.
    """
    df = pd.read_csv(csv_path)

    # Engineer composite security & lexical features if not already present
    if "HSTSHeaderPresent" not in df.columns:
        df["HSTSHeaderPresent"] = df.get("HasHSTS", 0)
    if "ContentSecurityPolicyPresent" not in df.columns:
        df["ContentSecurityPolicyPresent"] = df.get("HasCSP", 0)
    if "SecurityFeatureSum" not in df.columns:
        df["SecurityFeatureSum"] = (
            df["IsHTTPS"].fillna(0)
            + df["HSTSHeaderPresent"].fillna(0)
            + df["ContentSecurityPolicyPresent"].fillna(0)
        )
    if "PathLengthRatio" not in df.columns:
        df["PathLengthRatio"] = (
            (df["URLLength"] - df["DomainLength"] - 8).clip(lower=0)
            / df["URLLength"].replace(0, np.nan)
        ).fillna(0.0)
    if "HasSuspiciousKeywords" not in df.columns:
        df["HasSuspiciousKeywords"] = (
            (df.get("Bank", 0) == 1)
            | (df.get("Pay", 0) == 1)
            | (df.get("Crypto", 0) == 1)
            | (df.get("HasPasswordField", 0) == 1)
        ).astype(int)

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    preprocessor = build_preprocessing_pipeline()
    X_train_proc = preprocessor.fit_transform(X_train)
    X_test_proc = preprocessor.transform(X_test)

    mlp_model = build_mlp_classifier()
    mlp_model.fit(X_train_proc, y_train)

    y_pred = mlp_model.predict(X_test_proc)
    y_prob = mlp_model.predict_proba(X_test_proc)[:, 1]

    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score : {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC  : {roc_auc_score(y_test, y_prob):.4f}")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(mlp_model, ARTIFACTS_DIR / "mlp_model.joblib")
    joblib.dump(preprocessor, ARTIFACTS_DIR / "preprocessor.joblib")
    with open(ARTIFACTS_DIR / "feature_columns.json", "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)


def verify_and_calibrate_artifacts() -> None:
    """Verify existing model artifacts and sanitize lookup metadata."""
    meta_path = ARTIFACTS_DIR / "lookup_metadata.json"
    cols_path = ARTIFACTS_DIR / "feature_columns.json"
    model_path = ARTIFACTS_DIR / "mlp_model.joblib"
    prep_path = ARTIFACTS_DIR / "preprocessor.joblib"

    metadata = clean_lookup_metadata(meta_path)
    with open(cols_path, "r", encoding="utf-8") as f:
        cols = json.load(f)

    mlp_model = joblib.load(model_path)
    preprocessor = joblib.load(prep_path)

    assert len(cols) == 55, f"Expected 55 features, got {len(cols)}"
    print(
        f"✅ Verified artifacts: {type(mlp_model).__name__} "
        f"(input dim={mlp_model.n_features_in_}), "
        f"{len(metadata['tld_prob_map'])} valid IANA TLDs."
    )


if __name__ == "__main__":
    verify_and_calibrate_artifacts()

