import requests
from bs4 import BeautifulSoup
from typing import Dict, Any

DEFAULT_TIMEOUT = 4

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

def analyze_page(url: str) -> Dict[str, Any]:
    """
    Fetch and analyze basic HTML content for common phishing indicators.
    Safe and fast (short timeout, limited heuristics).
    """
    result: Dict[str, Any] = {
        "page_title": None,
        "num_forms": 0,
        "has_password_field": False,
        "external_forms": False,
        "scripts_with_eval": 0,
        "warnings": []
    }

    try:
        resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type:
            result["warnings"].append("Content is not HTML")
            return result

        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        result["page_title"] = title

        forms = soup.find_all("form")
        result["num_forms"] = len(forms)

        # Password fields or credential capture
        if soup.find("input", {"type": "password"}):
            result["has_password_field"] = True
            result["warnings"].append("Password field detected")

        # Forms posting to different origin
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        for f in forms:
            action = f.get("action") or ""
            if action:
                abs_action = urljoin(url, action)
                ap = urlparse(abs_action)
                if ap.netloc and ap.netloc != parsed.netloc:
                    result["external_forms"] = True
                    result["warnings"].append("Form submits to external domain")
                    break

        # Scripts using eval or obfuscation hints
        scripts = soup.find_all("script")
        for s in scripts:
            txt = s.string or ""
            if txt and ("eval(" in txt or "atob(" in txt or "document.write(" in txt):
                result["scripts_with_eval"] += 1
        if result["scripts_with_eval"]:
            result["warnings"].append("Suspicious inline scripts detected")

    except Exception:
        result["warnings"].append("Error fetching content")

    return result
