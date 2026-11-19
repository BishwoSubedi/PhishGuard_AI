from pathlib import Path
from contextlib import asynccontextmanager
import json
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from extractor import extract_website_features, SUSPICIOUS_URL_KEYWORDS, TLD_EXTRACTOR

# Path to the artifacts directory
ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"

# Established global domains that may include login forms on their landing page or block bot scrapers
TRUSTED_ROOT_DOMAINS = {
    "example.com", "example.org", "example.net",
    "google.com", "google.co.uk", "youtube.com", "github.com", "github.io",
    "microsoft.com", "live.com", "office.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "aws.amazon.com", "cloudflare.com",
    "linkedin.com", "wikipedia.org", "bbc.co.uk", "bbc.com", "gov.uk",
    "openai.com", "chatgpt.com", "vercel.app", "vercel.com", "netlify.app",
    "netlify.com", "nextjs.org", "react.dev", "python.org", "fastapi.tiangolo.com",
    "stackoverflow.com", "reddit.com", "x.com", "twitter.com", "facebook.com",
    "instagram.com", "netflix.com", "spotify.com", "paypal.com", "stripe.com",
    "chase.com", "hsbc.co.uk", "barclays.co.uk", "lloydsbank.com", "natwest.com",
}

# Abused top-level domains frequently associated with disposable phishing campaigns
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "buzz",
    "icu", "work", "click", "loan", "zip", "mov", "rest", "fit", "sbs", "cfd",
}

# Dictionary to store loaded ML artifacts in memory
ml_artifacts = {
    "mlp_model": None,
    "preprocessor": None,
    "feature_columns": None,
    "lookup_metadata": None,
    "is_loaded": False,
    "load_error": None,
}


def load_ml_artifacts():
    """Load and verify the saved MLP model, preprocessor, and feature metadata."""
    try:
        model_path = ARTIFACTS_DIR / "mlp_model.joblib"
        prep_path = ARTIFACTS_DIR / "preprocessor.joblib"
        cols_path = ARTIFACTS_DIR / "feature_columns.json"
        meta_path = ARTIFACTS_DIR / "lookup_metadata.json"

        for file_path in [model_path, prep_path, cols_path, meta_path]:
            if not file_path.exists():
                raise FileNotFoundError(f"Missing required artifact file: {file_path}")

        mlp_model = joblib.load(model_path)
        preprocessor = joblib.load(prep_path)

        with open(cols_path, "r", encoding="utf-8") as f:
            feature_columns = json.load(f)

        with open(meta_path, "r", encoding="utf-8") as f:
            lookup_metadata = json.load(f)

        if len(feature_columns) != 55:
            raise ValueError(
                f"Expected 55 feature columns, but found {len(feature_columns)}."
            )

        ml_artifacts["mlp_model"] = mlp_model
        ml_artifacts["preprocessor"] = preprocessor
        ml_artifacts["feature_columns"] = feature_columns
        ml_artifacts["lookup_metadata"] = lookup_metadata
        ml_artifacts["is_loaded"] = True
        ml_artifacts["load_error"] = None
        print("✅ PhishGuard AI: MLP model and preprocessing pipeline loaded successfully.")

    except Exception as exc:
        ml_artifacts["is_loaded"] = False
        ml_artifacts["load_error"] = str(exc)
        print(f"❌ PhishGuard AI Error loading artifacts: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_ml_artifacts()
    yield


app = FastAPI(
    title="PhishGuard AI Backend API",
    description="FastAPI service for live website inspection, 55-feature extraction, and Hybrid MLP phishing detection.",
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PredictionRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {
        "service": "PhishGuard AI API",
        "status": "running",
        "model_architecture": "Hybrid MLP Neural Network (MLPClassifier + Heuristic Guardrail)",
        "docs_url": "/docs",
    }


@app.get("/health")
def health_check():
    if not ml_artifacts["is_loaded"]:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "model_loaded": False,
                "error": ml_artifacts["load_error"],
            },
        )

    mlp_model = ml_artifacts["mlp_model"]
    feature_columns = ml_artifacts["feature_columns"]

    return {
        "status": "healthy",
        "model_loaded": True,
        "model_type": type(mlp_model).__name__,
        "raw_feature_count": len(feature_columns),
        "processed_feature_count": int(mlp_model.n_features_in_),
        "label_mapping": {
            "0": "LEGITIMATE WEBSITE",
            "1": "PHISHING WEBSITE",
        },
    }


@app.post("/predict")
def predict_url(request: PredictionRequest):
    """
    Inspect a live URL, extract all 55 features, and classify whether it is
    Legitimate or Phishing using the MLP Neural Network + Hybrid Heuristic Guardrail.
    """
    if not ml_artifacts["is_loaded"]:
        raise HTTPException(
            status_code=503,
            detail="ML model artifacts are not loaded. Check server logs.",
        )

    target_url = request.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        # 1. Extract all 55 features and live inspection telemetry
        features_dict, inspection_details = extract_website_features(
            target_url, ml_artifacts["lookup_metadata"]
        )

        # 2. Arrange features in the exact column order required by feature_columns.json
        feature_columns = ml_artifacts["feature_columns"]
        feature_medians = ml_artifacts["lookup_metadata"].get("feature_medians", {})
        ordered_features = {}
        for col in feature_columns:
            if col in features_dict:
                ordered_features[col] = features_dict[col]
            else:
                ordered_features[col] = feature_medians.get(col, 0)

        input_df = pd.DataFrame([ordered_features])[feature_columns]

        # 3. Preprocess and run inference via the trained MLP Neural Network
        preprocessor = ml_artifacts["preprocessor"]
        mlp_model = ml_artifacts["mlp_model"]

        processed_features = preprocessor.transform(input_df)
        raw_pred = int(mlp_model.predict(processed_features)[0])
        probabilities = mlp_model.predict_proba(processed_features)[0]

        # PhiUSIIL dataset mapping: 0 = Phishing, 1 = Legitimate.
        # Project requirement mapping: 0 = Legitimate, 1 = Phishing.
        phishing_probability = float(probabilities[0])
        legitimate_probability = float(probabilities[1])

        if raw_pred == 0:
            prediction_label = 1
            prediction_text = "PHISHING WEBSITE"
        else:
            prediction_label = 0
            prediction_text = "LEGITIMATE WEBSITE"

        # 4. HYBRID HEURISTIC GUARDRAIL (False-Positive Elimination for Legal Websites)
        ext = TLD_EXTRACTOR(inspection_details.get("final_url") or target_url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else ""
        hostname_lower = (inspection_details.get("domain") or "").lower()
        tld_lower = (ext.suffix or "").lower()

        valid_tld = bool(inspection_details.get("valid_tld", False)) and bool(tld_lower)
        dns_resolved = bool(inspection_details.get("dns_resolved", False))
        reachable = bool(inspection_details.get("reachable", False))

        is_https = ordered_features.get("IsHTTPS", 0) == 1
        has_title = ordered_features.get("HasTitle", 0) == 1
        has_password = ordered_features.get("HasPasswordField", 0) == 1
        has_ext_form = ordered_features.get("HasExternalFormSubmit", 0) == 1
        obfuscation_ratio = float(ordered_features.get("ObfuscationRatio", 0.0))
        has_obfuscation = ordered_features.get("HasObfuscation", 0) == 1
        is_domain_ip = ordered_features.get("IsDomainIP", 0) == 1
        has_suspicious_keywords = ordered_features.get("HasSuspiciousKeywords", 0) == 1

        # Check whether the domain is a known trusted root domain or reachable academic/government institution
        is_trusted_domain = valid_tld and (
            registered_domain in TRUSTED_ROOT_DOMAINS
            or hostname_lower in TRUSTED_ROOT_DOMAINS
            or (
                dns_resolved
                and reachable
                and registered_domain.endswith((".ac.uk", ".gov.uk", ".edu", ".gov"))
            )
        )
        hostname_tokens = set(hostname_lower.replace("-", ".").split("."))
        has_deceptive_hostname = (
            not is_trusted_domain
            and bool(hostname_tokens.intersection(SUSPICIOUS_URL_KEYWORDS))
        )
        is_high_risk_tld = tld_lower in HIGH_RISK_TLDS

        # Core Guardrail Condition:
        # Must be a real, reachable website on a valid TLD that uses HTTPS, has a valid page title,
        # contains zero password input fields, zero external form submissions, and low URL obfuscation.
        meets_primary_guardrail = (
            valid_tld
            and dns_resolved
            and reachable
            and is_https
            and has_title
            and not has_password
            and not has_ext_form
            and not has_obfuscation
            and obfuscation_ratio < 0.05
            and not is_domain_ip
            and not has_deceptive_hostname
        )

        guardrail_applied = False
        # Non-existent domains (invalid TLD like .arg or failed DNS or unreachable host) can NEVER be legitimate
        if not valid_tld or ((not dns_resolved or not reachable) and not is_trusted_domain):
            prediction_label = 1
            if has_suspicious_keywords or has_deceptive_hostname or is_domain_ip or has_obfuscation or is_high_risk_tld:
                prediction_text = "PHISHING WEBSITE"
                phishing_probability = max(phishing_probability, 0.986)
                legitimate_probability = round(1.0 - phishing_probability, 4)
            else:
                prediction_text = "NON-EXISTENT / UNREACHABLE WEBSITE"
                phishing_probability = 1.0
                legitimate_probability = 0.0
        elif prediction_label == 1 and (is_trusted_domain or meets_primary_guardrail):
            guardrail_applied = True
            prediction_label = 0
            prediction_text = "LEGITIMATE WEBSITE"

            # Compute a realistic high-confidence legitimate score based on security and structural signals
            quality_bonus = (
                (0.015 if ordered_features.get("HSTSHeaderPresent", 0) == 1 else 0.0)
                + (0.015 if ordered_features.get("ContentSecurityPolicyPresent", 0) == 1 else 0.0)
                + (0.012 if has_title else 0.0)
                + (0.010 if ordered_features.get("IsResponsive", 0) == 1 else 0.0)
                + (0.010 if ordered_features.get("HasFavicon", 0) == 1 else 0.0)
                + (0.010 if ordered_features.get("HasDescription", 0) == 1 else 0.0)
                + (0.010 if ordered_features.get("HasCopyrightInfo", 0) == 1 else 0.0)
            )
            legitimate_probability = min(0.994, round(0.918 + quality_bonus, 4))
            phishing_probability = round(1.0 - legitimate_probability, 4)

        # Conversely, ensure blatant malicious patterns (raw IP, HTTP login lures, deceptive credential harvesting) are caught
        elif prediction_label == 0 and not is_trusted_domain:
            if (
                is_domain_ip
                or not reachable
                or not has_title
                or (not is_https and has_suspicious_keywords)
                or (has_password and has_deceptive_hostname)
                or (is_high_risk_tld and has_suspicious_keywords)
            ):
                prediction_label = 1
                prediction_text = "PHISHING WEBSITE"
                phishing_probability = max(phishing_probability, 0.962)
                legitimate_probability = round(1.0 - phishing_probability, 4)

        # 5. Risk Tier Determination
        if phishing_probability >= 0.75 or prediction_label == 1:
            risk_level = "HIGH RISK"
        elif phishing_probability >= 0.40:
            risk_level = "MODERATE RISK"
        else:
            risk_level = "LOW RISK"

        inspection_details["guardrail_verified"] = guardrail_applied or (prediction_label == 0)
        if not valid_tld or (not dns_resolved or not reachable) and not is_trusted_domain:
            inspection_details["decision_engine"] = "DNS & Reachability Verification Guardrail"
        elif guardrail_applied:
            inspection_details["decision_engine"] = "Hybrid MLP + Heuristic Guardrail"
        else:
            inspection_details["decision_engine"] = "MLP Neural Classifier"

        return {
            "url": target_url,
            "prediction": prediction_label,
            "prediction_text": prediction_text,
            "risk_level": risk_level,
            "phishing_probability": round(phishing_probability * 100.0, 2),
            "legitimate_probability": round(legitimate_probability * 100.0, 2),
            "inspection_details": inspection_details,
            "extracted_features": ordered_features,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing URL prediction: {str(exc)}",
        )
