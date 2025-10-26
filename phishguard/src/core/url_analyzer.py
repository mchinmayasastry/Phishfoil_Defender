import re
import tldextract
import whois
import socket
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, Any, Optional

class URLAnalyzer:
    """
    Analyzes URLs for potential phishing and malicious indicators.
    """
    
    def __init__(self):
        self.suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site'}
        self.shortening_services = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 
            'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'cutt.ly'
        }
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential phishing indicators.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dict containing analysis results and risk score
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        result = {
            'url': url,
            'domain': '',
            'is_shortened': False,
            'has_ip': False,
            'has_port': False,
            'has_at_symbol': False,
            'is_https': False,
            'url_length': 0,
            'has_subdomain': False,
            'has_suspicious_tld': False,
            'domain_age_days': None,
            'features': {},
            'risk_score': 0,
            'warnings': []
        }
        
        try:
            parsed = urlparse(url)
            result['url_length'] = len(url)
            result['is_https'] = parsed.scheme == 'https'
            
            # Extract domain information
            domain_info = tldextract.extract(url)
            result['domain'] = f"{domain_info.domain}.{domain_info.suffix}"
            
            # Check for suspicious TLDs
            if domain_info.suffix in self.suspicious_tlds:
                result['has_suspicious_tld'] = True
                result['warnings'].append("Suspicious TLD detected")
            
            # Check for subdomains
            if domain_info.subdomain:
                result['has_subdomain'] = True
                if domain_info.subdomain.count('.') > 1:  # Multiple subdomains
                    result['warnings'].append("Multiple subdomains detected")
            
            # Check for IP address in domain
            try:
                socket.inet_aton(domain_info.domain)
                result['has_ip'] = True
                result['warnings'].append("IP address used in domain")
            except (socket.error, ValueError):
                pass
            
            # Check for port number
            if ':' in parsed.netloc and ']' not in parsed.netloc:  # Exclude IPv6
                result['has_port'] = True
                result['warnings'].append("Port number in URL")
            
            # Check for @ symbol
            if '@' in url:
                result['has_at_symbol'] = True
                result['warnings'].append("@ symbol in URL (possible credential phishing)")
            
            # Check for URL shortening services
            for service in self.shortening_services:
                if service in url:
                    result['is_shortened'] = True
                    result['warnings'].append(f"URL is shortened using {service}")
                    break
            
            # Get WHOIS information
            try:
                domain_info = whois.whois(result['domain'])
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    if creation_date:
                        age = (datetime.now() - creation_date).days
                        result['domain_age_days'] = age
                        if age < 30:  # Very new domain
                            result['warnings'].append(f"New domain (only {age} days old)")
            except Exception as e:
                pass
            
            # Calculate risk score (simplified for now)
            result['risk_score'] = self._calculate_risk_score(result)
            
        except Exception as e:
            result['error'] = str(e)
            result['warnings'].append(f"Error during analysis: {str(e)}")
        
        return result
    
    def _calculate_risk_score(self, features: Dict[str, Any]) -> float:
        """
        Calculate a risk score based on the extracted features.
        
        Args:
            features: Dictionary of features from URL analysis
            
        Returns:
            Risk score between 0 and 1
        """
        score = 0.0
        
        # Weights for different features
        weights = {
            'is_https': -0.1,  # HTTPS is good
            'has_ip': 0.5,
            'has_port': 0.3,
            'has_at_symbol': 0.7,
            'is_shortened': 0.4,
            'has_suspicious_tld': 0.6,
            'url_length': lambda x: min(0.5, x / 200),  # Longer URLs are more suspicious
            'domain_age_days': lambda x: 0.8 if x and x < 30 else 0.0,
        }
        
        for feature, weight in weights.items():
            if feature in features:
                if callable(weight):
                    score += weight(features[feature])
                elif isinstance(weight, (int, float)) and features[feature]:
                    score += weight
        
        # Cap the score between 0 and 1
        return max(0.0, min(1.0, score))
