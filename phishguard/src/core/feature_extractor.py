import re
import numpy as np
from urllib.parse import urlparse, parse_qs
import tldextract
from typing import Dict, List, Union
import ipaddress
import math

class FeatureExtractor:
    """
    Extracts features from URLs for phishing/malicious link detection.
    """
    
    def __init__(self):
        self.extractor = tldextract.TLDExtract()
        self.ip_pattern = re.compile(
            r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        )
        self.shortening_services = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 
            'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'cutt.ly'
        }
    
    def extract_features(self, url: str) -> Dict[str, Union[bool, int, float]]:
        """
        Extract features from a URL for classification.
        
        Args:
            url: The URL to extract features from
            
        Returns:
            Dictionary of feature names and their values
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            fragment = parsed.fragment
            
            # Extract domain components
            domain_parts = self.extractor(url)
            
            # Initialize feature dictionary
            features = {}
            
            # 1. URL-based features
            features['url_length'] = len(url)
            features['num_digits_url'] = sum(c.isdigit() for c in url)
            features['num_parameters'] = len(parse_qs(query))
            features['num_fragments'] = len(fragment) > 0
            features['num_subdomains'] = domain_parts.subdomain.count('.') + 1 if domain_parts.subdomain else 0
            features['has_port'] = ':' in domain
            features['has_at_symbol'] = '@' in url
            features['has_redirect'] = '//' in url[url.find('://') + 3:]
            
            # 2. Domain-based features
            features['domain_length'] = len(domain)
            features['is_ip'] = bool(self.ip_pattern.match(domain))
            features['is_shortened'] = any(service in domain for service in self.shortening_services)
            features['has_hyphen'] = '-' in domain
            features['has_underscore'] = '_' in domain
            
            # 3. Path-based features
            features['path_length'] = len(path)
            features['num_dirs'] = path.count('/')
            features['has_file_extension'] = bool(re.search(r'\.[a-zA-Z0-9]{1,5}$', path))
            
            # 4. Query-based features
            features['query_length'] = len(query)
            features['has_equals_in_query'] = '=' in query
            features['has_ampersand'] = '&' in query
            
            # 5. Special characters
            special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
            for char in special_chars:
                features[f'has_{char}'] = char in url
            
            # 6. Entropy calculation (higher entropy might indicate obfuscation)
            features['entropy'] = self._calculate_entropy(domain)
            
            # 7. TLD features
            features['tld_length'] = len(domain_parts.suffix) if domain_parts.suffix else 0
            features['has_uncommon_tld'] = domain_parts.suffix.lower() in {
                'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site', 'online', 'gdn', 'work', 'biz', 'info'
            }
            
            # 8. URL obfuscation
            features['has_hex_encoding'] = '%' in url
            features['has_unicode'] = any(ord(char) > 127 for char in url)
            
            # 9. Suspicious patterns
            features['has_suspicious_keywords'] = self._check_suspicious_keywords(url)
            
            return features
            
        except Exception as e:
            # Return default values in case of any error
            return {}
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not text:
            return 0.0
            
        entropy = 0.0
        for char in set(text.lower()):
            p = text.lower().count(char) / len(text)
            entropy -= p * math.log2(p)
            
        return entropy
    
    def _check_suspicious_keywords(self, url: str) -> bool:
        """Check for suspicious keywords in the URL."""
        suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking', 'paypal', 'ebay', 'amazon',
            'secure', 'update', 'password', 'confirm', 'billing', 'payment', 'alert',
            'urgent', 'suspended', 'limited', 'security', 'verification', 'service',
            'ebayisapi', 'webscr', 'login.jsp', 'login.php', 'login.asp', 'login.aspx'
        ]
        
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in suspicious_keywords)
    
    def get_feature_names(self) -> List[str]:
        """Get the list of feature names in the same order as the feature vector."""
        # This should match the features extracted in extract_features
        return [
            'url_length', 'num_digits_url', 'num_parameters', 'num_fragments',
            'num_subdomains', 'has_port', 'has_at_symbol', 'has_redirect',
            'domain_length', 'is_ip', 'is_shortened', 'has_hyphen', 'has_underscore',
            'path_length', 'num_dirs', 'has_file_extension', 'query_length',
            'has_equals_in_query', 'has_ampersand', 'has_@', 'has_?', 'has_-',
            'has_=', 'has_.', 'has_#', 'has_%', 'has_+', 'has_$', 'has_!', 'has_*',
            'has_,', 'has_//', 'entropy', 'tld_length', 'has_uncommon_tld',
            'has_hex_encoding', 'has_unicode', 'has_suspicious_keywords'
        ]
