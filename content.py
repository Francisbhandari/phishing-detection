import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PhishDetector/1.0)"}
def fetch_page(url: str, timeout: int = 5) -> dict:
    result = {
            'reachable': False, 'final_url': url, 'redirect_count': 0, 'tls_valid': False, 'status_code': 0, 'html': ""}
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True, verify=True)
        result.update({
            'reachable': True,
            'final_url': resp.url,
            'redirect_count': len(resp.history),
            'uses_https': resp.url.startswith('https'),
            'status_code': resp.status_code,
            'html': resp.text[:50_000]
        })
    except requests.exceptions.SSLError:
        result['uses_https'] = False
        result['reachable'] = True
    except Exception:
        pass
    return result

def content_features(page: dict) -> dict:
    html = page.get('html', "")
    soup = bs(html, 'html.parser') if html else None

    features = {
        "redirected_cross_domain": False,
        "redirect_count": page.get("redirect_count", 0),
        "has_password_field": False,
        "form_action_offsite": False,
        "favicon_offsite": False,
        "low_link_ratio": False,
        "has_copyright": False,
        "disabled_right_click": False,
    }

    if not soup:
        return features

    orig_domain = urlparse(page['final_url']).netloc

    if soup.find('input', {'type': 'password'}):
        features['has_password_field'] = True

    for form in soup.find_all('form'):
        action = form.get('action', '')
        if action and urlparse(urljoin(page['final_url'], action)).netloc != orig_domain:
            features['form_action_offsite'] = True
            break

    favicon_tag = soup.find('link', rel=lambda r: r and 'icon' in r)
    if favicon_tag:
    	href = favicon_tag.get("href", "")
    	fav_domain = urlparse(urljoin(page["final_url"], href)).netloc
        if fav_domain and fav_domain != orig_domain:
            features["favicon_offsite"] = True
            
	all_links = soup.find_all("a", href=True)
    if all_links:
        offsite = sum(
            1 for a in all_links
            if urlparse(urljoin(page["final_url"], a["href"])).netloc not in ("", orig_domain)
        )
        features["low_link_ratio"] = (offsite / len(all_links)) > 0.70


	if "©" in html or "copyright" in html.lower():
        features["has_copyright"] = True
        
    if "contextmenu" in html.lower() and "return false" in html.lower():
        features["disabled_right_click"] = True
        
	return features
	
	
def content_score(features: dict) -> float:
    score = 0.0
    if features["has_password_field"]:       score += 0.10
    if features["form_action_offsite"]:      score += 0.35
    if features["favicon_offsite"]:          score += 0.15
    if features["low_link_ratio"]:           score += 0.20
    if features["redirect_count"] > 2:       score += 0.10
    if features["disabled_right_click"]:     score += 0.15
    if not features["has_copyright"]:        score += 0.05
    return min(score, 1.0)
