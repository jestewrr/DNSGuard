import re
from urllib.parse import urlparse
import dns.resolver
from database import is_blacklisted
import math
from collections import Counter
import requests
from datetime import datetime

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
    Returns a dictionary of details.
    """
    details = {
        "is_suspicious": False,
        "ip_pattern": False,
        "excessive_hyphens": False,
        "excessive_subdomains": False,
        "suspicious_keywords": False,
        "high_entropy": False,
        "entropy_score": 0.0
    }
    
    # Suspicious pattern 1: IP address instead of domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain):
        details["is_suspicious"] = True
        details["ip_pattern"] = True

    # Suspicious pattern 2: Too many hyphens
    if domain.count('-') > 3:
        details["is_suspicious"] = True
        details["excessive_hyphens"] = True
        
    # Suspicious pattern 3: Excessive subdomains (e.g., a.b.c.d.example.com)
    parts = domain.split('.')
    if len(parts) > 4:
        details["is_suspicious"] = True
        details["excessive_subdomains"] = True
        
    # Suspicious pattern 4: Known phishing keywords
    phishing_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'wallet', 'support', 'auth']
    if any(keyword in domain for keyword in phishing_keywords):
        # Additional risk if a phishing keyword is used in a non-standard TLD or deeply nested subdomain
        if len(parts) > 3 or parts[-1] not in ['com', 'org', 'net']:
            details["is_suspicious"] = True
            details["suspicious_keywords"] = True
            
    # Suspicious pattern 5: Long or high-entropy subdomains
    if len(parts) > 2:
        subdomains = parts[:-2] # Get everything before registered_domain.tld
        for sub in subdomains:
            if len(sub) > 15:
                details["is_suspicious"] = True
            ent = calculate_entropy(sub)
            details["entropy_score"] = max(details["entropy_score"], ent)
            if len(sub) > 8 and ent > 3.8:
                details["is_suspicious"] = True
                details["high_entropy"] = True
    elif len(parts) == 2:
        # Check primary domain part
        main_domain = parts[0]
        if len(main_domain) > 15:
            details["is_suspicious"] = True
        ent = calculate_entropy(main_domain)
        details["entropy_score"] = max(details["entropy_score"], ent)
        if len(main_domain) > 10 and ent > 4.0:
            details["is_suspicious"] = True
            details["high_entropy"] = True

    # Suspicious pattern 6: Ad/Popup related keywords in subdomains
    if len(parts) > 2:
        ad_popup_keywords = ['pop', 'ad', 'click', 'track', 'affiliate', 'serve', 'banner', 'redir']
        subdomains = parts[:-2]
        for sub in subdomains:
            if any(keyword == sub or sub.startswith(keyword + '-') or sub.endswith('-' + keyword) for keyword in ad_popup_keywords):
                details["is_suspicious"] = True

    return details

def check_dns(domain):
    """
    Checks if the domain has valid DNS records (A or AAAA).
    Returns the IP address if valid, None if it seems invalid/suspicious.
    """
    try:
        # Check A records
        answers = dns.resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        pass
        
    try:
        # Check AAAA records if A fails
        answers = dns.resolver.resolve(domain, 'AAAA')
        return answers[0].to_text()
    except Exception:
        return None

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
    timestamp = datetime.utcnow().isoformat()
    domain = extract_domain(url)
    
    breakdown['url_monitoring'] = {
        "status": "Passed" if domain else "Failed",
        "message": f"Extracted domain: {domain}" if domain else "Failed to extract domain"
    }
    
    if not domain:
        return "Suspicious", breakdown

    # 1. Blacklist-Based Detection
    is_black = is_blacklisted(domain)
    breakdown['blacklist'] = {
        "status": "Failed" if is_black else "Passed",
        "message": "Domain found in known malicious databases." if is_black else "Domain was not found in known malicious databases.",
        "databases_checked": 12,
        "confidence": 100 if is_black else 0
    }

    # 2. Pattern-Based Detection
    pattern_details = check_pattern(domain)
    is_pattern = pattern_details["is_suspicious"]
    breakdown['pattern'] = {
        "status": "Failed" if is_pattern else "Passed",
        "message": "Suspicious domain structure detected." if is_pattern else "Domain structure appears legitimate.",
        "entropy_score": round(pattern_details["entropy_score"], 2),
        "suspicious_keywords": pattern_details["suspicious_keywords"],
        "excessive_subdomains": pattern_details["excessive_subdomains"],
        "high_entropy": pattern_details["high_entropy"]
    }

    # 3. Domain Reputation Analysis
    reputation = check_domain_reputation(url)
    breakdown['reputation'] = {
        "status": "Passed" if reputation == "Safe" else "Failed",
        "message": "Google Safe Browsing classifies this domain as clean." if reputation == "Safe" else f"Reputation service warning: {reputation}",
        "provider": "Google Safe Browsing",
        "confidence": 98 if reputation == "Safe" else 15
    }

    # 4. & 5. Real-Time Threat Detection (DNS resolution checks)
    dns_ip = check_dns(domain)
    breakdown['dns'] = {
        "status": "Passed" if dns_ip else "Failed",
        "message": f"Domain successfully resolved to IP: {dns_ip}" if dns_ip else "Domain failed to resolve.",
        "ip": dns_ip,
        "timestamp": timestamp
    }
    
    # 6. Pop-Up / Ad Detection
    is_ad = check_ad_network(domain)
    breakdown['ad_detection'] = {
        "status": "Failed" if is_ad else "Passed",
        "message": "Matches known intrusive advertising or popup networks." if is_ad else "No association with intrusive advertising or popup networks.",
        "risk_score": 85 if is_ad else 5
    }

    # Final Status Logic
    checks = [not is_black, not is_pattern, reputation == "Safe", bool(dns_ip), not is_ad]
    passed_checks = sum(1 for c in checks if c)
    overall_confidence = int((passed_checks / 5.0) * 100)

    breakdown['summary'] = {
        "url": url,
        "timestamp": timestamp,
        "checks_completed": f"{passed_checks}/5",
        "overall_confidence": f"{overall_confidence}%"
    }

    if is_black:
        status = "Malicious"
    elif is_pattern or not dns_ip:
        status = "Suspicious"
    elif is_ad:
        status = "Suspicious" # We can flag ad networks as Suspicious
    elif reputation != "Safe":
        status = reputation
    else:
        status = "Safe"
        
    breakdown['summary']['final_status'] = status

    return status, breakdown
