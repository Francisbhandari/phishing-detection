import re
import tldextract as te
from urllib.parse import urlparse
import math

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

    checks = {
    #basic features
        "url_length": len(url),
        "num_hyphens": url.count("-"),
        "num_dots": url.count("."),
        "num_digits": len(re.findall(r"\d+", url)),

    #domain features
        "has_ip": bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)),
        "has_@": "@" in url,
        "num_subdomain": len(subdomain.split(".")) if subdomain else 0,

    #suspicious things
        "num_sus_word": sum(1 for word in sus_words if word in url.lower()),
        "sus_tld": suffix in sus_tld,

        "domain": domain,
        "full_domain": full_domain,
        "path_length": len(parsed.path),

        "has_hex_encoding": bool(re.search(r"%[0-9A-Fa-f]{2}", url)),
        "uses_https": parsed.scheme == "https",
    }
    #suspicious words
    for word in sus_words:
        checks["contains_"+word]=word in url.lower()
    return checks

# final score
def lex_score(checks : dict) -> float:
    score = 0
    if checks["url_length"]>75: score+=2
    elif checks["url_length"]>=55: score+=1

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

    return score/28;


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())
