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
            
    # Suspicious pattern 5: Long or high-entropy subdomains (typical of popups/DGA/tracking)
    if len(parts) > 2:
        subdomains = parts[:-2] # Get everything before registered_domain.tld
        for sub in subdomains:
            # Subdomains longer than 15 chars are highly suspicious
            if len(sub) > 15:
                return True
            # Subdomains with high entropy (random looking)
            if len(sub) > 8 and calculate_entropy(sub) > 3.8:
                return True
    elif len(parts) == 2:
        # Check primary domain part
        main_domain = parts[0]
        if len(main_domain) > 15:
            return True
        if len(main_domain) > 10 and calculate_entropy(main_domain) > 4.0:
            return True

    # Suspicious pattern 6: Ad/Popup related keywords in subdomains
    if len(parts) > 2:
        ad_popup_keywords = ['pop', 'ad', 'click', 'track', 'affiliate', 'serve', 'banner', 'redir']
        subdomains = parts[:-2]
        for sub in subdomains:
            if any(keyword == sub or sub.startswith(keyword + '-') or sub.endswith('-' + keyword) for keyword in ad_popup_keywords):
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

def check_ad_network(domain):
    """
    Checks if the domain belongs to known popup or ad networks.
    """
    ad_networks = ['doubleclick.net', 'popads.net', 'propellerads.com', 'adtech.de', 'advertising.com', 'admob.com']
    return any(ad in domain for ad in ad_networks)

def analyze_url(url):
    """
    Main analysis function.
    Returns a tuple: (status, breakdown_dict)
    """
    breakdown = {}
    
    domain = extract_domain(url)
    breakdown['url_monitoring'] = f"Extracted domain: {domain}" if domain else "Failed to extract domain"
    
    if not domain:
        return "Suspicious", breakdown

    # 1. Blacklist-Based Detection
    is_black = is_blacklisted(domain)
    breakdown['blacklist'] = "Failed (Found in blacklist)" if is_black else "Passed"

    # 2. Pattern-Based Detection
    is_pattern = check_pattern(domain)
    breakdown['pattern'] = "Failed (Suspicious patterns found)" if is_pattern else "Passed"

    # 3. Domain Reputation Analysis
    reputation = check_domain_reputation(url)
    breakdown['reputation'] = reputation

    # 4. & 5. Real-Time Threat Detection (DNS resolution checks)
    is_dns_valid = check_dns(domain)
    breakdown['dns'] = "Passed (Valid IP)" if is_dns_valid else "Failed (No resolution)"
    
    # 6. Pop-Up / Ad Detection
    is_ad = check_ad_network(domain)
    breakdown['ad_detection'] = "Failed (Known Ad/Popup Network)" if is_ad else "Passed"

    # Final Status Logic
    if is_black:
        status = "Malicious"
    elif is_pattern or not is_dns_valid:
        status = "Suspicious"
    elif is_ad:
        status = "Suspicious" # We can flag ad networks as Suspicious
    elif reputation != "Safe":
        status = reputation
    else:
        status = "Safe"

    return status, breakdown
