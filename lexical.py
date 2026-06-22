import re
import tldextract as te
from urllib.parse import urlparse, parse_qs
import math

sus_words=["login","verify","secure","confirm","password","bank","account","update","security"]

sus_tld=["xyz","click","site","online","shop","click","live","cm","tk","ml","cf","buzz","top","host"]

brand_words=["paypal","google","facebook","microsoft","apple","amazon","netflix","instagram","twitter","linkedin"]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IP_IN_URL_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
PORT_RE = re.compile(r":\d{2,5}(/|$)")
def analyze_url(url):
    # parse url
    parsed = urlparse(url)
    ext = te.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    full_domain = ext.top_domain_under_public_suffix
    hostname = parsed.hostname or ""
    path = parsed.path
    url_lower = url.lower()

    # path segments (non-empty)
    path_segments = [s for s in path.split("/") if s]
    first_dir = path_segments[0] if path_segments else ""

    # query params
    query_params = parse_qs(parsed.query)
    query_values = [v for vals in query_params.values() for v in vals]
    avg_query_value_len = (sum(len(v) for v in query_values) / len(query_values)) if query_values else 0.0

    # character counts across full url
    letters = re.findall(r"[a-zA-Z]", url)
    digits = re.findall(r"\d", url)
    special_chars = re.findall(r"[^a-zA-Z0-9]", url)

    checks = {
        # --- length features ---
        "url_length":           len(url),
        "domain_length":        len(domain),
        "hostname_length":      len(hostname),
        "path_length":          len(path),
        "first_dir_length":     len(first_dir),
        "tld_length":           len(suffix),

        # --- structural features ---
        "path_segments_count":  len(path_segments),
        "num_digits":           len(digits),
        "num_letters":          len(letters),
        "num_special_chars":    len(special_chars),
        "num_dots":             url.count("."),
        "num_hyphens":          url.count("-"),
        "num_at":               url.count("@"),
        "num_percent":          url.count("%"),
        "num_equals":           url.count("="),
        "num_question":         url.count("?"),
        "num_ampersand":        url.count("&"),
        "num_hash":             url.count("#"),
        "num_underscore":       url.count("_"),
        "num_special":          len(re.findall(r"[^a-zA-Z0-9._\-/:]", url)),
        "num_slash":            url.count("/"),
        "num_params":           len(query_params),

        # --- ratio features ---
        "uppercase_ratio":      sum(1 for c in url if c.isupper()) / len(url) if url else 0.0,
        "lowercase_ratio":      sum(1 for c in url if c.islower()) / len(url) if url else 0.0,

        # --- domain/IP features ---
        "is_ip_address":        bool(IP_IN_URL_RE.search(url)),
        "starts_with_ip":       bool(IP_RE.match(hostname)),
        "uses_https":           parsed.scheme == "https",
        "has_www":              subdomain == "www" or subdomain.startswith("www."),
        "multiple_http":        url_lower.count("http") > 1,
        "contains_port_number": bool(PORT_RE.search(url)),

        # --- encoding features ---
        "path_has_encoded_chars": bool(re.search(r"%[0-9A-Fa-f]{2}", path)),
        "query_has_base64":     any(re.search(r"[A-Za-z0-9+/]{20,}={0,2}$", v) for v in query_values),

        # --- suspicious keyword features ---
        "contains_login":       "login"   in url_lower,
        "contains_secure":      "secure"  in url_lower,
        "contains_verify":      "verify"  in url_lower,
        "contains_account":     "account" in url_lower,
        "contains_update":      "update"  in url_lower,
        "contains_bank":        "bank"    in url_lower,
        "contains_cloud":       "cloud"   in url_lower,
        "contains_brand":       any(b in url_lower for b in brand_words),

        # --- query features ---
        "query_key_count":          len(query_params),
        "query_value_length_avg":   avg_query_value_len,

        # --- preserved legacy fields (used by lex_score) ---
        "has_ip":               bool(IP_IN_URL_RE.search(url)),
        "has_@":                "@" in url,
        "num_subdomain":        len(subdomain.split(".")) if subdomain else 0,
        "num_sus_word":         sum(1 for word in sus_words if word in url_lower),
        "sus_tld":              suffix in sus_tld,
        "has_hex_encoding":     bool(re.search(r"%[0-9A-Fa-f]{2}", url)),
        "domain":               domain,
        "full_domain":          full_domain,
    }

    # legacy per-word flags (for lex_score compatibility)
    for word in sus_words:
        key = "contains_" + word
        if key not in checks:
            checks[key] = word in url_lower

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
