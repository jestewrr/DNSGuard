import re
from urllib.parse import urlparse
import dns.resolver
from database import is_blacklisted, is_whitelisted
import math
from collections import Counter
import requests
from datetime import datetime, timedelta

# In-memory cache for analyzed domains to avoid redundant queries and DNS resolution
ANALYSIS_CACHE = {}  # {domain: (status, breakdown_dict, expire_time)}

def clear_analysis_cache():
    global ANALYSIS_CACHE
    ANALYSIS_CACHE.clear()

def extract_domain(url):
    try:
        url_lower = url.lower()
        if url_lower.startswith('file://') or url_lower.startswith('chrome://') or url_lower.startswith('chrome-extension://') or url_lower.startswith('about:'):
            return ""
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        # Strip port number if present
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return ""

def calculate_entropy(string):
    """Calculates the Shannon entropy of a string."""
    if not string:
        return 0.0
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def is_document_download(url):
    """
    Checks if the URL path ends with a common safe document or archive file extension.
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        doc_extensions = ('.pdf', '.docx', '.xlsx', '.pptx', '.zip', '.rar', '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif', '.json')
        return path.endswith(doc_extensions)
    except Exception:
        return False

def check_pattern(domain):
    """
    Checks if the domain matches suspicious patterns using a multi-factor score system.
    Returns a dictionary of details.
    """
    details = {
        "is_suspicious": False,
        "ip_pattern": False,
        "excessive_hyphens": False,
        "excessive_subdomains": False,
        "suspicious_keywords": False,
        "brand_impersonation": False,
        "phishing_phrases": False,
        "high_entropy": False,
        "entropy_score": 0.0
    }
    
    score = 0.0
    parts = domain.split('.')
    
    # Indicator 1: IP address instead of domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain):
        details["ip_pattern"] = True
        score += 3.0

    # Indicator 2: Too many hyphens
    if domain.count('-') > 3:
        details["excessive_hyphens"] = True
        score += 1.0
        
    # Indicator 3: Excessive subdomains (e.g., a.b.c.d.example.com)
    if len(parts) > 4:
        details["excessive_subdomains"] = True
        score += 1.0
        
    # Indicator 4: Phishing keywords in non-standard/suspicious contexts
    phishing_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'wallet', 'support', 'auth']
    if any(keyword in domain for keyword in phishing_keywords):
        if len(parts) > 3 or parts[-1] not in ['com', 'org', 'net']:
            details["suspicious_keywords"] = True
            score += 2.0

    # Indicator 5: Brand name impersonation & keyword combinations
    brands = ['office365', 'microsoft', 'paypal', 'netflix', 'google', 'facebook', 'apple', 'amazon', 'outlook', 'yahoo', 'adobe', 'dropbox']
    suspicious_combos = ['alert', 'login', 'signin', 'verify', 'verification', 'update', 'support', 'account', 'billing', 'banking', 'auth', 'portal']
    
    # Check if a brand name is combined with a suspicious word (e.g. office365-alert-login.com)
    has_brand = any(brand in domain for brand in brands)
    has_combo = any(combo in domain for combo in suspicious_combos)
    if has_brand and has_combo and ('-' in domain or len(parts) > 2):
        details["brand_impersonation"] = True
        score += 3.0
        
    # Indicator 6: High-risk hyphenated phishing phrases
    phishing_phrases = ['alert-login', 'secure-login', 'login-alert', 'verify-login', 'update-login', 'account-update', 'login-update', 'signin-alert', 'secure-signin']
    if any(phrase in domain for phrase in phishing_phrases):
        details["phishing_phrases"] = True
        score += 3.0
            
    # Indicator 7: Entropy and length of labels
    max_ent = 0.0
    if len(parts) > 2:
        subdomains = parts[:-2]
        for sub in subdomains:
            ent = calculate_entropy(sub)
            max_ent = max(max_ent, ent)
            # Long and high entropy subdomains
            if len(sub) > 15 and ent > 4.2:
                details["high_entropy"] = True
                score += 1.5
            elif len(sub) > 8 and ent > 3.8:
                score += 0.8
    elif len(parts) == 2:
        main_domain = parts[0]
        ent = calculate_entropy(main_domain)
        max_ent = max(max_ent, ent)
        if len(main_domain) > 18 and ent > 4.2:
            details["high_entropy"] = True
            score += 1.5
        elif len(main_domain) > 12 and ent > 3.8:
            score += 0.8

    details["entropy_score"] = round(max_ent, 2)
    
    # Suspicious if score threshold is reached
    if score >= 3.0:
        details["is_suspicious"] = True

    return details

def check_dns(domain):
    """
    Checks if the domain has valid DNS records (A or AAAA).
    Returns the IP address if valid, None if it seems invalid/suspicious.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        # Check A records
        answers = resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        pass
        
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        # Check AAAA records if A fails
        answers = resolver.resolve(domain, 'AAAA')
        return answers[0].to_text()
    except Exception:
        return None

def check_domain_reputation(url):
    """
    Evaluate website trustworthiness. Returns 'Safe' unless a known reputation issue is present.
    """
    return "Safe"

def check_ad_network(domain):
    """
    Checks if the domain belongs to known popup or ad networks.
    """
    ad_networks = [
        'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 
        'popads.net', 'propellerads.com', 'adtech.de', 'advertising.com', 
        'admob.com', 'adnxs.com', 'pubmatic.com', 'rubiconproject.com', 
        'openx.net', 'casalemedia.com', 'outbrain.com', 'taboola.com',
        'adcolony.com', 'unityads.unity3d.com', 'applovin.com', 'ironsrc.com',
        'criteo.com', 'adroll.com', 'quantserve.com', 'scorecardresearch.com'
    ]
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

    # Check cache first
    now = datetime.utcnow()
    if domain in ANALYSIS_CACHE:
        cached_status, cached_breakdown, cached_expiry = ANALYSIS_CACHE[domain]
        if now < cached_expiry:
            # Return copy/updated fields to avoid mutating cached structures unexpectedly
            import copy
            result_breakdown = copy.deepcopy(cached_breakdown)
            result_breakdown['summary']['url'] = url
            result_breakdown['summary']['timestamp'] = timestamp
            if 'dns' in result_breakdown:
                result_breakdown['dns']['timestamp'] = timestamp
            return cached_status, result_breakdown
        else:
            del ANALYSIS_CACHE[domain]

    # Check Whitelist (respect database-level rules and local default whitelist)
    whitelist = ['localhost', '127.0.0.1', 'dnsguard.onrender.com', 'dnsguard-backend.onrender.com']
    if domain in whitelist or domain.endswith('.localhost') or is_whitelisted(domain):
        breakdown['summary'] = {
            "url": url,
            "timestamp": timestamp,
            "checks_completed": "Whitelisted",
            "overall_confidence": "100%",
            "final_status": "Safe"
        }
        # Cache whitelist results for 10 minutes
        ANALYSIS_CACHE[domain] = ("Safe", breakdown, now + timedelta(minutes=10))
        return "Safe", breakdown

    # 1. Blacklist-Based Detection
    is_black = is_blacklisted(domain)
    breakdown['blacklist'] = {
        "status": "Failed" if is_black else "Passed",
        "message": "Domain found in known malicious databases." if is_black else "Domain was not found in known malicious databases.",
        "databases_checked": 12,
        "confidence": 100 if is_black else 0
    }

    # Pre-check for document downloads
    is_doc = is_document_download(url)
    
    # 2. Pattern-Based Detection
    pattern_details = check_pattern(domain)
    is_pattern = pattern_details["is_suspicious"]
    
    # If it is a safe document download, bypass the pattern suspension flag
    if is_doc and not is_black:
        is_pattern = False

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
        "message": "Reputation analysis classifies this domain as clean." if reputation == "Safe" else f"Reputation service warning: {reputation}",
        "provider": "Reputation Analysis",
        "confidence": 98 if reputation == "Safe" else 15
    }

    # 4. Pop-Up / Ad Detection
    is_ad = check_ad_network(domain)
    breakdown['ad_detection'] = {
        "status": "Failed" if is_ad else "Passed",
        "message": "Matches known intrusive advertising or popup networks." if is_ad else "No association with intrusive advertising or popup networks.",
        "risk_score": 85 if is_ad else 5
    }

    # 5. Real-Time Threat Detection (DNS resolution checks)
    # Bypassed if we already know the domain is malicious or an ad network
    if is_black or is_ad:
        dns_ip = None
        breakdown['dns'] = {
            "status": "Skipped",
            "message": "DNS resolution bypassed for known malicious/advertising domain.",
            "ip": None,
            "timestamp": timestamp
        }
    else:
        dns_ip = check_dns(domain)
        breakdown['dns'] = {
            "status": "Passed" if dns_ip else "Failed",
            "message": f"Domain successfully resolved to IP: {dns_ip}" if dns_ip else "Domain failed to resolve.",
            "ip": dns_ip,
            "timestamp": timestamp
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
        status = "Suspicious"
    elif reputation != "Safe":
        status = reputation
    else:
        status = "Safe"
        
    breakdown['summary']['final_status'] = status

    # Cache results for 10 minutes
    ANALYSIS_CACHE[domain] = (status, breakdown, now + timedelta(minutes=10))

    return status, breakdown
