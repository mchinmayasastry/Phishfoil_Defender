from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
import joblib
import os
import logging
from pathlib import Path

# Import core components
from ..core.url_analyzer import URLAnalyzer
from ..core.feature_extractor import FeatureExtractor
from ..core.content_analyzer import analyze_page
from ..core.model_utils import load_model_bundle, features_to_vector

# Initialize FastAPI app
app = FastAPI(
    title="Phishfoil_Defender API",
    description="API for detecting phishing and malicious URLs using machine learning",
    version="1.0.0"
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
url_analyzer = URLAnalyzer()
feature_extractor = FeatureExtractor()

# Model bundle loaded at startup (if present)
model_bundle = None

class URLRequest(BaseModel):
    url: str
    analyze_content: bool = False

class AnalysisResponse(BaseModel):
    url: str
    is_malicious: bool
    confidence: float
    risk_score: float
    warnings: List[str]
    features: Dict[str, Any]

# Mount static files
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent.parent.parent / "web" / "static"),
    name="static"
)

templates = Jinja2Templates(directory=Path(__file__).parent.parent.parent / "web" / "templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_url(url_request: URLRequest):
    """
    Analyze a URL for potential phishing or malicious content.
    
    This endpoint performs a comprehensive analysis of the provided URL using
    multiple detection techniques including URL analysis, domain reputation,
    and machine learning classification.
    """
    try:
        # Basic URL analysis
        analysis = url_analyzer.analyze(url_request.url)
        
        # Extract features for ML model
        features = feature_extractor.extract_features(url_request.url)
        score_rule = float(analysis.get('risk_score', 0.0))

        # Optional lightweight content analysis
        content_warnings: List[str] = []
        if url_request.analyze_content:
            content_result = analyze_page(url_request.url)
            content_warnings.extend(content_result.get("warnings", []))

        # Use model prediction if available; else fallback to rule-based
        proba = None
        is_malicious = False
        confidence = 0.0
        if model_bundle is not None:
            try:
                vec = features_to_vector(features, model_bundle["feature_names"]).reshape(1, -1)
                proba = float(model_bundle["model"].predict_proba(vec)[:, 1][0])
                threshold = float(model_bundle.get("threshold", 0.5))
                is_malicious = proba >= threshold
                confidence = proba
            except Exception as _:
                # Fallback to rule-based on any model error
                is_malicious = score_rule > 0.6
                confidence = min(score_rule * 1.2, 1.0)
        else:
            is_malicious = score_rule > 0.6
            confidence = min(score_rule * 1.2, 1.0)

        # Prepare response
        response = {
            "url": url_request.url,
            "is_malicious": bool(is_malicious),
            "confidence": round(float(confidence), 4),
            # Prefer model probability if available; else rule-based risk
            "risk_score": round(float(proba if proba is not None else score_rule), 4),
            "warnings": (analysis.get('warnings', []) + content_warnings),
            "features": features
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=404,
        content={"detail": "The requested resource was not found"},
    )

@app.exception_handler(500)
async def server_error_exception_handler(request: Request, exc: Exception):
    logger.error(f"Server error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

# Load models on startup
@app.on_event("startup")
async def startup_event():
    """Initialize models and other resources."""
    global model_bundle

    # Resolve model path relative to project root (Phishfoil_Defender)
    project_root = Path(__file__).parent.parent.parent
    default_path = project_root / "models" / "Phishfoil_Defender_model.joblib"
    model_path = Path(os.getenv("MODEL_PATH", str(default_path)))

    bundle = load_model_bundle(str(model_path))
    if bundle is not None:
        model_bundle = bundle
        logger.info(f"Loaded model bundle from {model_path}")
    else:
        logger.warning("No pre-trained model found. Using rule-based analysis only.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
