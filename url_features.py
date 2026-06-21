import re
import tldextract as te
from urllib.parse import urlparse

sus_words=["login","verify","secure","confirm","password","bank","account","update","security"]

sus_tld=["xyz","click","site","online","shop","click","live","cm","tk","ml","cf","buzz","top","host"]

def analyze_url(url):
    checks={}

    # parse url
    parsed = urlparse(url)
    ext = te.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    full_domain = ext.top_domain_under_public_suffix

    # basic features
    checks["url_length"] = len(url)
    checks["num_hyphens"] = url.count("-")
    checks["num_dots"] = url.count(".")
    checks["num_digits"] = len(re.findall(r"\d+",url))

    # domain features
    checks["has_ip"] = bool(re.search(r"\d+\.\d+\.\d+\.\d+",url))
    checks["has_@"] = "@" in url
    checks["num_subdomain"] = len(subdomain.split(".")) if subdomain else 0   

    # sus things
    checks["num_sus_word"] = sum(1 for word in sus_words if word in url.lower())
    checks["sus_tld"] = suffix in sus_tld

    checks["domain"] = domain
    checks["full_domain"] = full_domain
    checks["path_length"] = len(parsed.path)

    checks["has_hex_encoding"] = bool(re.search(r"%[0-9A-fa-f]{2}",url))
    checks["uses_https"] = parsed.scheme == "https"

    # final score
    score = 0
    if checks["url_length"]>75: score+=1
    
    if checks["url_length"]>=55: score+=1

    if checks["num_hyphens"]>=3: score+=2
    elif checks["num_hyphens"]==2: score+=1

    if checks["num_dots"]>4: score+=2
    elif checks["num_dots"]>2: score+=1

    if checks["num_digits"]>6: score+=2
    elif checks["num_digits"]>=4: score+=1

    if checks["has_ip"]: score+=3

    if checks["has_@"]: score+=3

    if checks["num_subdomain"]>3: score+=2
    elif checks["num_subdomain"]>=2: score+=1

    if checks["num_sus_word"]>3: score+=2
    elif checks["num_sus_word"]>=1: score+=1

    if checks["sus_tld"]: score+=2

    if checks["path_length"]>40: score+=2
    elif checks["path_length"]>=20: score+=1

    if checks["has_hex_encoding"]: score+=3

    if not checks["uses_https"]: score+=3

    checks["risk_score"] = score

    if score<=7:
        checks["label"] = "SAFE"
    elif score<=14:
        checks["label"] = "SUSPICIOUS"
    else:
        checks["label"] = "PHISHING"

    return checks

url = input("Enter URL to check: ")
res = analyze_url(url)
    
print("Result:",res["label"])