# PhishGuard: AI-Powered Phishing & Malicious Link Analyzer

PhishGuard is a machine learning-based solution designed to detect and analyze phishing attempts and malicious links in real-time. It combines multiple detection techniques to provide accurate and explainable results.

## Features

- Real-time URL analysis
- Machine learning-based detection
- Explainable AI results
- Web interface for easy interaction
- REST API for integration
- Support for both URL and content analysis

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd phishguard
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Web Interface
```bash
uvicorn src.api.app:app --reload
```
Then open http://localhost:8000 in your browser.

### API Usage

```python
import requests

response = requests.post(
    "http://localhost:8000/api/analyze",
    json={"url": "https://example.com/suspicious"}
)
print(response.json())
```

## Project Structure

- `data/`: Datasets and training data
- `models/`: Trained model files
- `src/`: Source code
  - `api/`: FastAPI application and endpoints
  - `core/`: Core detection logic
  - `utils/`: Utility functions
- `tests/`: Test files
- `web/`: Web interface files
  - `static/`: Static files (CSS, JS)
  - `templates/`: HTML templates

## License

MIT License - See LICENSE for more details.
