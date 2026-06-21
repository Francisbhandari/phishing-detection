import whois
import dns.resolver as dr
from datetime import datetime, timezone

def whois_features(domain: str) -> dict:
    try:
        w = whois.whois(domain)
    except:
        return {"whois_available":False, "domain_age_days":-1, "registrar": ""}

    creation = w.creation_date
    if isinstance(creation, list):
        creation = creation[0]

    age = -1

    if creation:
        try:
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now-creation).days
        except Exception:
            pass

    return {
            'whois_available': True,
            'domain_age_days': age,
            'registrar': str(w.registrar or ''),
            }

def dns_features(domain: str) -> dict:
    results = {
    "has_mx_record": False,
    "has_txt_record": False,
    "has_spf" = False,
    "a_record_count": 0,
    "ttl": -1
    }

    try:
        answers = dr.resolve(domain, 'A')
        results['a_record_count'] = len(answers)
        results['ttl'] = answers.rrset.ttl
    except Exception:
        pass

    try:
        dr.resolve(domain, 'MX')
        results['has_mx'] = True
    except Exception:
        pass

    try:
        txt = dr.resolve(domain, 'TXT')
        results["has_txt_record"] = True
        for rdata in txt:
            txt_record = ''.join(
                s.decode() if isinstance(s, bytes) else str(s)
                for s in rdata.strings
            )

            if 'v=spf1' in txt_record.lower():
                results['has_spf'] = True
                break
    except Exception:
        pass

    return results


def net_score(whois_f: dict, dns_f: dict) -> float:
    score = 0.0

    if not whois_f.get('whois_available', False):
        score += 0.25

    age = whois_f.get('domain_age_days', -1)

    if 0 < age < 30:
        score += 0.40
    elif 30 <= age < 90:
        score += 0.20
    elif age < 0:
        score += 0.15

    if dns_f.get('ttl', 9999) < 300:
        score += 0.15

    if not dns_f.get('has_mx', False):
        score += 0.05

    if not dns_f.get('has_spf', False):
        score += 0.05

    return min(score, 1.0)
