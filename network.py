import whois
import dns.resolver as dr
import ipaddress
from datetime import datetime, timezone

def whois_features(domain: str) -> dict:
    FAIL = {
        'whois_success':                 False,
        'whois_missing':                 True,
        'domain_age_days':               -1,
        'expiration_days':               -1,
        'creation_year':                 -1,
        'domain_is_recent':              False,
        'domain_registered_before_2020': False,
        'registrar':                     '',
        'registrar_valid':               False,
        'name_servers_count':            0,
        'is_privacy_protected':          False,
    }

    try:
        w = whois.whois(domain)
    except Exception:
        return FAIL

    now = datetime.now(timezone.utc)

    def _normalise(dt):
        if isinstance(dt, list):
            dt = dt[0]
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    creation   = _normalise(w.creation_date)
    expiration = _normalise(w.expiration_date)

    age_days = int((now - creation).days)   if creation   else -1
    exp_days = int((expiration - now).days) if expiration else -1

    creation_year                = creation.year if creation else -1
    domain_is_recent             = 0 < age_days < 180
    domain_registered_before_2020 = 0 < creation_year < 2020

    registrar       = str(w.registrar or '')
    registrar_valid = bool(registrar)

    ns = w.name_servers or []
    if isinstance(ns, str):
        ns = [ns]
    name_servers_count = len(set(ns_entry.lower() for ns_entry in ns))

    privacy_keywords = ("privacy", "proxy", "protect", "whoisguard", "redacted")
    is_privacy_protected = any(k in str(w).lower() for k in privacy_keywords)

    return {
        'whois_success':                 True,
        'whois_missing':                 False,
        'domain_age_days':               age_days,
        'expiration_days':               exp_days,
        'creation_year':                 creation_year,
        'domain_is_recent':              domain_is_recent,
        'domain_registered_before_2020': domain_registered_before_2020,
        'registrar':                     registrar,
        'registrar_valid':               registrar_valid,
        'name_servers_count':            name_servers_count,
        'is_privacy_protected':          is_privacy_protected,
    }


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def dns_features(domain: str) -> dict:
    results = {
        "success":                False,
        "dns_resolves":           False,
        "has_mx_record":          False,
        "has_txt_record":         False,
        "has_ns_record":          False,
        "has_spf":                False,
        "ttl_value":              -1,
        "ip_count":               0,
        "resolves_to_private_ip": False,
    }

    try:
        answers = dr.resolve(domain, 'A')
        ips = [r.address for r in answers]
        results['success']      = True
        results['dns_resolves'] = True
        results['ip_count']     = len(ips)
        results['ttl_value']    = answers.rrset.ttl
        results['resolves_to_private_ip'] = any(_is_private_ip(ip) for ip in ips)
    except Exception:
        pass

    try:
        dr.resolve(domain, 'MX')
        results['has_mx_record'] = True
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

    try:
        dr.resolve(domain, 'NS')
        results['has_ns_record'] = True
    except Exception:
        pass

    return results


def net_score(whois_f: dict, dns_f: dict) -> float:
    score = 0.0

    if not whois_f.get('whois_success', False):
        score += 0.25
    else:
        age = whois_f.get('domain_age_days', -1)
        if 0 < age < 30:
            score += 0.40
        elif 30 <= age < 90:
            score += 0.20
        elif age < 0:
            score += 0.15

    if dns_f.get('ttl_value', 9999) < 300:
        score += 0.15

    if not dns_f.get('has_mx_record', False):
        score += 0.05

    if not dns_f.get('has_spf', False):
        score += 0.05

    return min(score, 1.0)
