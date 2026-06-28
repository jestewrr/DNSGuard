import re
from urllib.parse import urlparse
import dns.resolver
from database import is_blacklisted
import math
from collections import Counter
import requests

def extract_domain(url):
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return ""

def calculate_entropy(string):
    """Calculates the Shannon entropy of a string."""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def check_pattern(domain):
    """
    Checks if the domain matches suspicious patterns.
    Returns True if suspicious, False otherwise.
    """
    # Suspicious pattern 1: IP address instead of domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain):
        return True

    # Suspicious pattern 2: Too many hyphens
    if domain.count('-') > 3:
        return True
        
    # Suspicious pattern 3: Excessive subdomains (e.g., a.b.c.d.example.com)
    parts = domain.split('.')
    if len(parts) > 4:
        return True
        
    # Suspicious pattern 4: Known phishing keywords
    phishing_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'wallet', 'support', 'auth']
    if any(keyword in domain for keyword in phishing_keywords):
        # Additional risk if a phishing keyword is used in a non-standard TLD or deeply nested subdomain
        if len(parts) > 3 or parts[-1] not in ['com', 'org', 'net']:
            return True
            
    # Suspicious pattern 5: Random characters (high entropy)
    if len(parts) >= 2:
        main_domain = parts[-2]
        if len(main_domain) > 10 and calculate_entropy(main_domain) > 4.0:
            return True

    return False

def check_dns(domain):
    """
    Checks if the domain has valid DNS records (A or AAAA).
    Returns True if valid, False if it seems invalid/suspicious.
    """
    try:
        # Check A records
        dns.resolver.resolve(domain, 'A')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        pass
        
    try:
        # Check AAAA records if A fails
        dns.resolver.resolve(domain, 'AAAA')
        return True
    except Exception:
        return False

def check_domain_reputation(url):
    """
    Evaluate website trustworthiness using domain reputation services.
    Placeholder for Google Safe Browsing API or VirusTotal API.
    """
    # Note: In a real production environment, you would make an API call to a reputation service here.
    # Example for Google Safe Browsing API (requires API key):
    # api_key = 'YOUR_API_KEY'
    # api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    # payload = {
    #     "client": {"clientId": "dnsguard", "clientVersion": "1.0"},
    #     "threatInfo": {
    #         "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
    #         "platformTypes": ["ANY_PLATFORM"],
    #         "threatEntryTypes": ["URL"],
    #         "threatEntries": [{"url": url}]
    #     }
    # }
    # try:
    #     response = requests.post(api_url, json=payload, timeout=3)
    #     if response.json().get('matches'): 
    #         return "Malicious"
    # except Exception as e:
    #     print(f"Reputation API error: {e}")
    
    return "Safe"

def analyze_url(url):
    """
    Main analysis function.
    Returns a status: 'Safe', 'Suspicious', or 'Malicious'
    """
    domain = extract_domain(url)
    if not domain:
        return "Suspicious"

    # 1. Blacklist-Based Detection
    if is_blacklisted(domain):
        return "Malicious"

    # 2. Pattern-Based Detection
    if check_pattern(domain):
        return "Suspicious"

    # 3. Domain Reputation Analysis
    reputation = check_domain_reputation(url)
    if reputation != "Safe":
        return reputation

    # 4. & 5. Real-Time Threat Detection (DNS resolution checks)
    # If the domain doesn't resolve, we mark it as suspicious (could be a typo or malicious DGA)
    if not check_dns(domain):
        return "Suspicious"

    return "Safe"
