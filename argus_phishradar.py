import html
import sys
import re

# =========================================================
# ARGUS Threat-Intel Edition (STRICT + LIVE + CLASSIFIER)
# Discovery + Pivot + Campaign Graph
# Keeps original Argus commands untouched.
# New command:
#   python <script>.py --campaign-intel BRAND [--live-only]
# =========================================================

import requests
import subprocess
import socket
import ssl
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import mmh3
except Exception:
    mmh3 = None

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except Exception:
    PYVIS_AVAILABLE = False

OFFICIAL_ROOTS = {
    "microsoft.com","microsoftonline.com","office.com","bing.com","azure.com",
    "live.com","xbox.com","windows.com","outlook.com","sharepoint.com","skype.com"
}

OFFICIAL_SUBSTRINGS = [
    "microsoftonline","sharepoint","office365","office","azure","bing","outlook",
    "xbox","windows","live","skype","passport","msn"
]

NOISE_KEYWORDS = [
    "corp","internal","test","ppe","beta","lab","partners","extranet","staging",
    "stage","uat","dev","prod","sandbox","api","cdn","static","status","docs","learn"
]

SUSPICIOUS_PATTERNS = [
    "{brand}-login","login-{brand}",
    "{brand}-secure","secure-{brand}",
    "{brand}-account","account-{brand}",
    "{brand}-verify","verify-{brand}",
    "{brand}-support","support-{brand}",
    "{brand}-auth","auth-{brand}",
    "{brand}-password","password-{brand}",
]

COMMON_TLDS = ["com","net","org","co","info"]


PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "secure", "verify", "verification",
    "account", "update", "auth", "password", "support", "billing",
    "payment", "wallet", "recover", "restore", "unlock", "confirm",
    "security", "help", "service", "webscr", "checkpoint", "sso"
}

ACTION_TOKENS = {
    "login", "signin", "sign-in", "verify", "verification", "confirm",
    "unlock", "restore", "recover", "reset", "review", "validate",
    "authenticate", "reauth", "resume", "check", "update"
}

ACCOUNT_TOKENS = {
    "account", "profile", "security", "password", "credential", "credentials",
    "identity", "access", "wallet", "billing", "payment", "invoice",
    "member", "customer", "client", "portal"
}

CASEWORK_TOKENS = {
    "resolution", "center", "centre", "case", "dispute", "claim", "appeal",
    "limitation", "limited", "restriction", "restricted", "hold", "suspended",
    "suspend", "restore", "confirm", "review", "compliance", "kyc", "remedy"
}

DELIVERY_TOKENS = {
    "support", "service", "help", "desk", "member", "customer", "client",
    "portal", "care", "assist", "notice", "alert"
}

INFRA_SUSPICION_TOKENS = {
    "auth", "sso", "secure", "webscr", "session", "token", "gateway",
    "validation", "validate", "update"
}

LOW_SIGNAL_CONTEXT_TOKENS = {
    "about", "community", "blog", "news", "press", "media", "help",
    "docs", "developer", "developers", "events", "careers", "careers",
    "status", "learn", "academy", "supportcenter"
}

PARTNER_MARKETING_TOKENS = {
    "partners", "partner", "community", "events", "promo", "marketing", "campaign",
    "affiliate", "loyalty", "rewards", "offers", "offer", "newsroom", "press"
}

REMEDIATION_HINT_TOKENS = {
    "about", "info", "community", "help", "status", "support", "notice",
    "security", "response", "incident", "trust", "safe", "protection"
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "site", "online", "info", "live", "shop",
    "support", "cloud", "rest", "icu", "buzz", "monster", "cam", "cfd"
}

OFFICIAL_PARTNER_LIKE_ROOTS = {
    "paypal.at",
    "paypalcredit.com",
    "paypalgivingfund.org",
    "paypal.me",
}

OFFICIAL_PARTNER_LIKE_PREFIXES = (
    "business.paypal.",
    "merchant.paypal.",
    "m.paypal.",
    "donate.paypal.",
    "www.paypal.",
)

INCOHERENT_BRAND_TOKENS = {
    "casino", "casinos", "bet", "bets", "gambling", "poker", "slots",
    "dating", "adult", "porn", "sex", "xxx", "escort", "loan", "forex"
}

def _ti_tokenize_label(value: str) -> list[str]:
    return [x for x in re.split(r"[^a-z0-9]+", (value or "").lower()) if x]

def _ti_brand_forms(brand: str) -> set[str]:
    brand = (brand or "").lower().strip()
    if not brand:
        return set()
    forms = {brand}
    compact = re.sub(r"[^a-z0-9]", "", brand)
    if compact:
        forms.add(compact)
    if len(compact) > 4:
        forms.add(compact.replace("o", "0"))
        forms.add(compact.replace("l", "1"))
    return {x for x in forms if x}

def _ti_domain_semantic_profile(domain: str, brand: str) -> dict:
    d = _ti_normalize_domain(domain)
    reg = _ti_get_registrable_domain(d)
    reg_no_tld = _ti_get_reg_no_tld(d)
    tokens = set(_ti_tokenize_label(reg_no_tld))
    brand_forms = _ti_brand_forms(brand)
    tld = reg.rsplit(".", 1)[-1].lower() if "." in reg else ""
    brand_hit = any(b and b in reg_no_tld for b in brand_forms)
    typoish = any(
        b and (
            b + b[-1] in reg_no_tld or
            (reg_no_tld.replace("0", "o") != reg_no_tld and b in reg_no_tld.replace("0", "o")) or
            (reg_no_tld.replace("1", "l") != reg_no_tld and b in reg_no_tld.replace("1", "l"))
        )
        for b in brand_forms if len(b) >= 3
    )
    action_hits = tokens & ACTION_TOKENS
    account_hits = tokens & ACCOUNT_TOKENS
    casework_hits = tokens & CASEWORK_TOKENS
    delivery_hits = tokens & DELIVERY_TOKENS
    infra_hits = tokens & INFRA_SUSPICION_TOKENS
    low_signal_hits = tokens & LOW_SIGNAL_CONTEXT_TOKENS
    partner_hits = tokens & PARTNER_MARKETING_TOKENS
    remediation_hits = tokens & REMEDIATION_HINT_TOKENS
    phishing_hits = tokens & PHISHING_KEYWORDS
    suspicious_tld = tld in SUSPICIOUS_TLDS
    separator_style = "-" in reg_no_tld or d.count(".") >= 2
    strong_signal = bool(action_hits or account_hits or casework_hits or infra_hits or phishing_hits)
    medium_signal_count = sum(bool(x) for x in [delivery_hits, suspicious_tld, typoish, separator_style])
    likely_noise = bool(low_signal_hits or partner_hits) and not strong_signal
    return {
        "domain": d,
        "reg": reg,
        "reg_no_tld": reg_no_tld,
        "tokens": tokens,
        "tld": tld,
        "brand_hit": brand_hit,
        "typoish": typoish,
        "action_hits": action_hits,
        "account_hits": account_hits,
        "casework_hits": casework_hits,
        "delivery_hits": delivery_hits,
        "infra_hits": infra_hits,
        "low_signal_hits": low_signal_hits,
        "partner_hits": partner_hits,
        "remediation_hits": remediation_hits,
        "phishing_hits": phishing_hits,
        "suspicious_tld": suspicious_tld,
        "separator_style": separator_style,
        "strong_signal": strong_signal,
        "medium_signal_count": medium_signal_count,
        "likely_noise": likely_noise,
    }

def plausible_dynamic_campaign_domain(domain: str, brand: str) -> bool:
    d = _ti_normalize_domain(domain)
    if not d or "@" in d or " " in d or "/" in d or "." not in d:
        return False
    if "\n" in d or "\r" in d or "," in d:
        return False
    if not _ti_looks_like_fqdn(d):
        return False

    profile = _ti_domain_semantic_profile(d, brand)
    reg = profile["reg"]
    reg_no_tld = profile["reg_no_tld"]
    tokens = profile["tokens"]

    official_extra = {
        "paypalobjects.com",
        "paypalcorp.com",
        "paypal-media.com",
    }

    if reg in OFFICIAL_ROOTS:
        return False
    if d.endswith(".paypal.com") or d == "paypal.com":
        return False
    if reg in official_extra or any(d.endswith("." + x) for x in official_extra):
        return False
    if reg in OFFICIAL_PARTNER_LIKE_ROOTS:
        return False
    if any(d.startswith(p) for p in OFFICIAL_PARTNER_LIKE_PREFIXES):
        return False
    if any(k in d for k in NOISE_KEYWORDS):
        return False
    if any(s in reg_no_tld for s in OFFICIAL_SUBSTRINGS):
        return False
    if not profile["brand_hit"]:
        return False
    if tokens & INCOHERENT_BRAND_TOKENS:
        return False

    if profile["likely_noise"] and not profile["typoish"] and not profile["suspicious_tld"]:
        return False

    strong_signal = profile["strong_signal"]
    weak_combo = profile["medium_signal_count"] >= 2
    finance_casework_combo = bool(profile["casework_hits"] and (profile["delivery_hits"] or profile["account_hits"]))

    return strong_signal or weak_combo or finance_casework_combo

def query_urlscan_domains(keyword: str, limit: int = 50) -> list[str]:
    print(f"[ARGUS URLSCAN] Searching urlscan for: {keyword}")
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    queries = [
        f"domain:{keyword}",
        f'page.domain:"{keyword}"',
        f'task.url:"{keyword}"'
    ]
    found = set()
    for q in queries:
        try:
            url = f"https://urlscan.io/api/v1/search/?q={requests.utils.quote(q)}&size={int(max(1, min(limit, 100)))}"
            r = requests.get(url, timeout=25, headers=headers)
            if r.status_code != 200:
                continue
            data = r.json() or {}
            for item in data.get("results", [])[:limit]:
                for key in ("page", "task"):
                    block = item.get(key) or {}
                    for field in ("domain", "apexDomain"):
                        d = _ti_normalize_domain(block.get(field, ""))
                        if d:
                            found.add(d)
                for entry in (item.get("domains") or []):
                    d = _ti_normalize_domain(entry)
                    if d:
                        found.add(d)
        except Exception as e:
            print(f"[ARGUS URLSCAN] query failed for {q}: {e}")
    print(f"[ARGUS URLSCAN] Results: {len(found)} raw domains")
    return sorted(found)

def query_domain_age_days(domain: str):
    """
    Best-effort RDAP age check.
    Returns age in days if creation/registration date is available, else None.
    """
    d = _ti_normalize_domain(domain)
    if not d:
        return None

    urls = [
        f"https://rdap.org/domain/{d}",
        f"https://rdap.verisign.com/com/v1/domain/{d}" if d.endswith(".com") else None,
        f"https://rdap.verisign.com/net/v1/domain/{d}" if d.endswith(".net") else None,
    ]
    urls = [u for u in urls if u]

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }

    for url in urls:
        try:
            r = requests.get(url, timeout=20, headers=headers)
            if r.status_code != 200:
                continue
            data = r.json() or {}

            candidates = []

            for ev in data.get("events", []) or []:
                action = str(ev.get("eventAction", "")).lower()
                date_str = ev.get("eventDate")
                if action in {"registration", "registered", "creation"} and date_str:
                    candidates.append(date_str)

            for key in ("creationDate", "created", "registered"):
                if data.get(key):
                    candidates.append(data[key])

            for ds in candidates:
                try:
                    ds = str(ds).replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ds)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - dt).days
                    if age >= 0:
                        return age
                except Exception:
                    pass
        except Exception:
            pass

    return None


def score_dynamic_candidate(domain: str, brand: str):
    d = _ti_normalize_domain(domain)
    profile = _ti_domain_semantic_profile(d, brand)
    reg = profile["reg"]
    reg_no_tld = profile["reg_no_tld"]
    tokens = profile["tokens"]
    tld = profile["tld"]

    reasons = []
    score = 0
    intent_score = 0
    abuse_score = 0
    context_penalty = 0

    official_extra = {
        "paypalobjects.com",
        "paypalcorp.com",
        "paypal-media.com",
    }

    if not _ti_looks_like_fqdn(d):
        return {
            "domain": d,
            "score": -100,
            "reasons": ["invalid fqdn"],
            "age_days": None,
            "intent_score": 0,
            "abuse_score": -100,
            "operational_score": 0,
        }

    if (
        reg in OFFICIAL_ROOTS
        or d.endswith(".paypal.com")
        or d == "paypal.com"
        or reg in official_extra
        or any(d.endswith("." + x) for x in official_extra)
        or reg in OFFICIAL_PARTNER_LIKE_ROOTS
        or any(d.startswith(p) for p in OFFICIAL_PARTNER_LIKE_PREFIXES)
    ):
        return {
            "domain": d,
            "score": -50,
            "reasons": ["official asset"],
            "age_days": None,
            "intent_score": 0,
            "abuse_score": -50,
            "operational_score": 0,
        }

    if profile["brand_hit"]:
        abuse_score += 20
        reasons.append("brand exact")

    if profile["phishing_hits"]:
        intent_score += 18
        reasons.append("phishing tokens")

    if profile["action_hits"]:
        intent_score += 12
        reasons.append("action tokens")

    if profile["account_hits"]:
        intent_score += 10
        reasons.append("account tokens")

    if profile["casework_hits"]:
        intent_score += 20
        reasons.append("casework tokens")

    if profile["delivery_hits"]:
        intent_score += 6
        reasons.append("service tokens")

    if profile["infra_hits"]:
        intent_score += 8
        reasons.append("infra/auth tokens")

    if profile["casework_hits"] and (profile["delivery_hits"] or profile["account_hits"]):
        intent_score += 10
        reasons.append("casework+account combo")

    if profile["suspicious_tld"]:
        abuse_score += 10
        reasons.append("suspicious tld")

    incoherent_hits = tokens & INCOHERENT_BRAND_TOKENS
    if incoherent_hits:
        context_penalty -= 25
        reasons.append("incoherent brand context")

    if profile["typoish"]:
        abuse_score += 15
        reasons.append("brand typo")

    if profile["separator_style"] and (profile["strong_signal"] or profile["suspicious_tld"]):
        abuse_score += 4
        reasons.append("crafted separator style")

    if profile["low_signal_hits"] and not profile["strong_signal"]:
        context_penalty -= 10
        reasons.append("low-signal brand context")

    if profile["partner_hits"] and not profile["strong_signal"]:
        context_penalty -= 12
        reasons.append("partner/marketing context")

    age_days = query_domain_age_days(d)
    operational_score = 0
    if age_days is not None:
        if age_days <= 7:
            operational_score += 25
            reasons.append(f"very new domain ({age_days}d)")
        elif age_days <= 30:
            operational_score += 18
            reasons.append(f"new domain ({age_days}d)")
        elif age_days <= 90:
            operational_score += 10
            reasons.append(f"recent domain ({age_days}d)")

    if not profile["strong_signal"] and age_days is None and tld not in SUSPICIOUS_TLDS:
        context_penalty -= 10
        reasons.append("weak phishing context")

    score = intent_score + abuse_score + operational_score + context_penalty

    return {
        "domain": d,
        "score": score,
        "reasons": reasons,
        "age_days": age_days,
        "intent_score": intent_score,
        "abuse_score": abuse_score + context_penalty,
        "operational_score": operational_score,
    }

def dynamic_campaign_discovery(keyword: str, limit: int = 50) -> dict:
    brand = (keyword or "").strip().lower()
    ct_domains = ct_discovery(brand)
    urlscan_domains = query_urlscan_domains(brand, limit=limit)
    combined = sorted(set(ct_domains) | set(urlscan_domains))

    scored = []
    filtered = []
    rejected = 0
    for d in combined:
        if plausible_dynamic_campaign_domain(d, brand):
            filtered.append(_ti_normalize_domain(d))
            scored.append(score_dynamic_candidate(d, brand))
        else:
            rejected += 1

    scored.sort(key=lambda x: x.get("score", 0), reverse=True)

    return {
        "ct_domains": sorted(set(ct_domains)),
        "urlscan_domains": sorted(set(urlscan_domains)),
        "combined": combined,
        "filtered": sorted(set(filtered)),
        "scored": scored,
        "rejected": rejected,
    }


def _ti_normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.replace("*.", "").strip(".")
    d = d.split("/")[0]
    d = d.split("\\n")[0].split("\n")[0].strip()
    d = d.split(",")[0].strip()
    d = d.replace(" ", "")
    return d

def _ti_looks_like_fqdn(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if "." not in domain:
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    return bool(re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain))

def _ti_get_registrable_domain(domain: str) -> str:
    d = _ti_normalize_domain(domain)
    parts = d.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return d

def _ti_get_reg_no_tld(domain: str) -> str:
    reg = _ti_get_registrable_domain(domain)
    if "." in reg:
        return reg.rsplit(".", 1)[0]
    return reg

def ct_discovery(keyword):
    print(f"[ARGUS CT] Searching CT logs for: {keyword}")
    url_json = f"https://crt.sh/?q=%25{keyword}%25&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json,text/plain,*/*"
    }

    try:
        r = requests.get(url_json, timeout=30, headers=headers)
        text = r.text.strip()
        if text:
            try:
                data = r.json()
            except Exception:
                data = None
                if text.startswith("{") and "}{" in text:
                    try:
                        fixed = "[" + text.replace("}\r\n{", "},{").replace("}\n{", "},{").replace("}{", "},{") + "]"
                        data = requests.models.complexjson.loads(fixed)
                    except Exception:
                        data = None
            if data:
                domains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for d in str(name).split("\\n"):
                        d = _ti_normalize_domain(d)
                        if d:
                            domains.add(d)
                print(f"[ARGUS CT] JSON results: {len(domains)} raw domains")
                return sorted(domains)
    except Exception as e:
        print("[ARGUS CT] JSON query failed:", e)

    try:
        url_html = f"https://crt.sh/?q=%25{keyword}%25"
        r = requests.get(url_html, timeout=30, headers=headers)
        html = r.text
        found = set()
        pattern = r'([a-zA-Z0-9*.-]*' + re.escape(keyword) + r'[a-zA-Z0-9.-]*\.[a-zA-Z]{2,})'
        for m in re.findall(pattern, html, re.I):
            d = _ti_normalize_domain(m)
            if d:
                found.add(d)
        print(f"[ARGUS CT] HTML fallback results: {len(found)} raw domains")
        return sorted(found)
    except Exception as e:
        print("[ARGUS CT] fallback failed:", e)
        return []

def generate_typosquat_candidates(brand):
    out = set()
    for pattern in SUSPICIOUS_PATTERNS:
        base = pattern.format(brand=brand)
        out.add(base)
        out.add(base.replace("-", ""))
    final = set()
    for base in out:
        for tld in COMMON_TLDS:
            final.add(f"{base}.{tld}")
    return sorted(final)

def plausible_phishing(domain, brand):
    d = _ti_normalize_domain(domain)
    if not d or "@" in d or " " in d or "/" in d or "." not in d:
        return False

    reg = _ti_get_registrable_domain(d)
    reg_no_tld = _ti_get_reg_no_tld(d)

    if reg in OFFICIAL_ROOTS:
        return False
    if any(k in d for k in NOISE_KEYWORDS):
        return False
    if any(s in reg_no_tld for s in OFFICIAL_SUBSTRINGS):
        return False
    if brand not in reg_no_tld:
        return False

    suspicious_markers = {p.format(brand=brand) for p in SUSPICIOUS_PATTERNS}
    suspicious_markers |= {x.replace("-", "") for x in suspicious_markers}
    return reg_no_tld in suspicious_markers

def check_http_alive(domain, timeout=4):
    domain = _ti_normalize_domain(domain)
    out = {
        "domain": domain,
        "status": None,
        "final_url": None,
        "class_hint": None,
        "scheme": None,
        "dns_ips": [],
        "peer_ip": None,
        "server": None,
        "location": None,
        "ok": False,
        "redirect_chain": [],
    }

    try:
        infos = socket.getaddrinfo(domain, None)
        seen_ips = []
        for item in infos:
            ip = item[4][0]
            if ip not in seen_ips:
                seen_ips.append(ip)
        out["dns_ips"] = seen_ips[:8]
    except Exception:
        out["dns_ips"] = []

    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0"}
    for scheme in ("https://", "http://"):
        url = scheme + domain
        try:
            r = session.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False, stream=True)
            out["redirect_chain"] = [resp.url for resp in (list(r.history) + [r]) if getattr(resp, "url", None)]
            status = int(r.status_code)
            out["status"] = status
            out["final_url"] = r.url
            out["scheme"] = scheme.rstrip(":/")
            out["server"] = r.headers.get("Server")
            out["location"] = r.headers.get("Location")
            out["ok"] = 200 <= status < 400
            try:
                conn = getattr(r.raw, "_connection", None)
                sock = getattr(conn, "sock", None) if conn else None
                if sock and hasattr(sock, "getpeername"):
                    peer = sock.getpeername()
                    if isinstance(peer, tuple) and peer:
                        out["peer_ip"] = peer[0]
            except Exception:
                pass
            try:
                r.close()
            except Exception:
                pass
            if out["ok"]:
                return out
        except Exception:
            continue
    return out

def classify_final_url(domain: str, final_url: str, brand: str) -> str:
    """
    active_phishing_candidate
    redirect_official_clean
    redirect_official_possible_remediation
    redirect_official_possible_brand_protection
    parking_or_generic
    likely_partner_or_campaign_site
    brand_abuse_unclear
    """
    analyzed = _ti_normalize_domain(domain)
    if not final_url:
        return "parking_or_generic"

    parsed = urlparse(final_url.strip())
    final_host = _ti_normalize_domain(parsed.netloc or "")
    final_url_l = final_url.strip().lower()
    domain_profile = _ti_domain_semantic_profile(analyzed, brand)
    final_profile = _ti_domain_semantic_profile(final_host, brand) if final_host else {
        "tokens": set(), "remediation_hits": set(), "partner_hits": set(), "low_signal_hits": set(),
        "strong_signal": False
    }

    generic_markers = [
        "sedo", "bodis", "dan.com", "afternic", "for-sale",
        "buy-this-domain", "coming-soon", "parking"
    ]
    if any(m in final_url_l for m in generic_markers):
        return "parking_or_generic"

    if final_host == analyzed:
        if domain_profile["partner_hits"] and not domain_profile["strong_signal"]:
            return "likely_partner_or_campaign_site"
        if domain_profile["low_signal_hits"] and not domain_profile["strong_signal"]:
            return "brand_abuse_unclear"
        return "active_phishing_candidate"

    redirects_to_official = (
        final_host in OFFICIAL_ROOTS
        or any(final_host.endswith("." + x) for x in OFFICIAL_ROOTS)
        or f"support.{brand}.com" in final_host
        or final_host == f"www.{brand}.com"
        or final_host == f"{brand}.com"
        or any(s in final_host for s in OFFICIAL_SUBSTRINGS)
    )

    if redirects_to_official:
        if domain_profile["partner_hits"] or final_profile.get("partner_hits"):
            return "redirect_official_clean"
        if domain_profile["remediation_hits"] or final_profile.get("remediation_hits"):
            return "redirect_official_possible_remediation"
        if domain_profile["low_signal_hits"] and not domain_profile["strong_signal"]:
            return "redirect_official_possible_brand_protection"
        return "redirect_official_clean"

    if domain_profile["partner_hits"] and not domain_profile["strong_signal"]:
        return "likely_partner_or_campaign_site"
    if domain_profile["low_signal_hits"] and not domain_profile["strong_signal"]:
        return "brand_abuse_unclear"

    return "active_phishing_candidate"

def favicon_hash(url):
    if not mmh3:
        print("[ARGUS] mmh3 not installed, skipping favicon pivot")
        return None

    try:
        fav = url.rstrip("/") + "/favicon.ico"
        r = requests.get(fav, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code == 200:
            h = mmh3.hash(r.content)
            print("[ARGUS] favicon hash:", h)
            return h
    except Exception:
        pass
    return None

def cluster_infrastructure(domains):
    clusters = defaultdict(list)
    for item in domains:
        if isinstance(item, dict):
            d = _ti_normalize_domain(item.get("domain") or item.get("host") or "")
            ip = item.get("peer_ip") or ((item.get("dns_ips") or [None])[0])
        elif isinstance(item, (list, tuple)) and item:
            d = _ti_normalize_domain(item[0])
            ip = None
        else:
            d = _ti_normalize_domain(str(item or ""))
            ip = None

        if not d:
            continue
        if not ip:
            try:
                ip = socket.gethostbyname(d)
            except Exception:
                ip = None
        if ip:
            if d not in clusters[ip]:
                clusters[ip].append(d)
    return clusters

def generate_graph(clusters, outfile="argus_campaign_graph.html"):
    if not clusters:
        print("[ARGUS] No infrastructure data to graph")
        return
    if not PYVIS_AVAILABLE:
        print("[ARGUS] pyvis not installed, skipping graph")
        return

    net = Network(height="800px", width="100%", bgcolor="#0e1117", font_color="white")
    for ip, doms in clusters.items():
        net.add_node(ip, label=ip, color="red")
        for d in doms:
            net.add_node(d, label=d, color="orange")
            net.add_edge(ip, d)

    net.write_html(outfile, open_browser=False)
    print("[ARGUS] Graph saved:", outfile)

def argus_campaign_intel(keyword, live_only=False, auto_analyze=False, open_reports=False, dynamic_discovery=True, dynamic_limit=50):
    brand = keyword.strip().lower()

    ct_domains = ct_discovery(brand)
    generated = generate_typosquat_candidates(brand)

    dynamic = {
        "ct_domains": [],
        "urlscan_domains": [],
        "combined": [],
        "filtered": [],
        "rejected": 0,
    }
    if dynamic_discovery:
        try:
            dynamic = dynamic_campaign_discovery(brand, limit=dynamic_limit)
        except Exception as e:
            print(f"[ARGUS DYNAMIC] discovery failed: {e}")

    raw = sorted(set(ct_domains) | set(generated) | set(dynamic.get("combined", [])))

    filtered = []
    rejected = 0
    for d in raw:
        if plausible_phishing(d, brand) or plausible_dynamic_campaign_domain(d, brand):
            filtered.append(_ti_normalize_domain(d))
        else:
            rejected += 1
    filtered = sorted(set(filtered))

    live_results = []
    suspicious_live = []
    redirect_live = []
    parking_live = []
    context_live = []

    if live_only:
        print("\n[ARGUS] Probing plausible phishing domains...\n")
        for d in filtered:
            probe = check_http_alive(d)
            status = probe.get("status")
            final_url = probe.get("final_url")
            if status:
                cls = classify_final_url(d, final_url, brand)
                item = {
                    "domain": d,
                    "status": status,
                    "final_url": final_url,
                    "class": cls,
                    "peer_ip": probe.get("peer_ip"),
                    "dns_ips": probe.get("dns_ips") or [],
                    "scheme": probe.get("scheme"),
                    "redirect_chain": probe.get("redirect_chain") or [],
                }
                live_results.append(item)
                if cls == "active_phishing_candidate":
                    suspicious_live.append(item)
                elif cls.startswith("redirect_official"):
                    redirect_live.append(item)
                elif cls in {"parking_or_generic"}:
                    parking_live.append(item)
                else:
                    context_live.append(item)

    print(f"\n[ARGUS] Raw domains from CT: {len(ct_domains)}")
    print(f"[ARGUS] Dynamic CT/urlscan candidates: {len(dynamic.get('combined', []))}")
    print(f"[ARGUS] Dynamic filtered candidates: {len(dynamic.get('filtered', []))}")
    print(f"[ARGUS] Generated typosquat candidates: {len(generated)}")
    print(f"[ARGUS] Combined candidates: {len(raw)}")
    print(f"[ARGUS] Rejected as legit/noise: {rejected}")
    print(f"[ARGUS] Plausible phishing domains: {len(filtered)}\n")

    if not filtered:
        print("None found")
    else:
        for d in filtered:
            print(" -", d)

    if dynamic.get("scored"):
        print("\n[ARGUS] Top dynamic candidates\n")
        for item in dynamic.get("scored", [])[:15]:
            print(f" - {item['domain']} | score={item['score']} | age={item.get('age_days')} | reasons: {', '.join(item.get('reasons', []))}")

    if live_only:
        print("\n[ARGUS] Live suspicious domains\n")
        if not suspicious_live:
            print("None")
        else:
            for item in suspicious_live:
                ip_note = item.get("peer_ip") or ", ".join(item.get("dns_ips") or []) or "no-ip"
                print(f" - {item['domain']} [{item['status']}] -> {item['final_url']} | ip={ip_note}")

        print("\n[ARGUS] Redirect to official / remediation / protection\n")
        if not redirect_live:
            print("None")
        else:
            for item in redirect_live:
                ip_note = item.get("peer_ip") or ", ".join(item.get("dns_ips") or []) or "no-ip"
                print(f" - {item['domain']} [{item['status']}] -> {item['final_url']} | {item['class']} | ip={ip_note}")

        print("\n[ARGUS] Brand-context / partner / unclear\n")
        if not context_live:
            print("None")
        else:
            for item in context_live:
                ip_note = item.get("peer_ip") or ", ".join(item.get("dns_ips") or []) or "no-ip"
                print(f" - {item['domain']} [{item['status']}] -> {item['final_url']} | {item['class']} | ip={ip_note}")

        print("\n[ARGUS] Parking / generic\n")
        if not parking_live:
            print("None")
        else:
            for item in parking_live:
                ip_note = item.get("peer_ip") or ", ".join(item.get("dns_ips") or []) or "no-ip"
                print(f" - {item['domain']} [{item['status']}] -> {item['final_url']} | ip={ip_note}")

    cluster_input = suspicious_live if live_only else filtered
    clusters = cluster_infrastructure(cluster_input)

    print("\n[ARGUS] Infrastructure clusters\n")
    if not clusters:
        print("No resolved suspicious domains")
    else:
        for ip, doms in clusters.items():
            print(ip, "->", len(doms), "domains")
            for d in doms:
                print("   ", d)

    if live_only and suspicious_live:
        try:
            print("\n[ARGUS] Favicon pivot (first suspicious live)\n")
            favicon_hash(suspicious_live[0].get("final_url"))
        except Exception:
            pass

    generate_graph(clusters)

    if auto_analyze:
        auto_analyze_suspicious_domains(suspicious_live, open_reports=open_reports)



def auto_analyze_suspicious_domains(suspicious_live, *, open_reports=False, max_domains=10):
    """
    Launch normal Argus analysis on suspicious live domains using the same script,
    without modifying the normal CLI behavior.
    """
    if not suspicious_live:
        print("[ARGUS] No suspicious live domains to auto-analyze")
        return

    print("\n[ARGUS] Auto-analyzing suspicious live domains\n")
    from pathlib import Path
    script_path = Path(__file__).resolve()

    count = 0
    for item in suspicious_live[:max_domains]:
        if isinstance(item, dict):
            d = item.get("domain")
            final_url = item.get("final_url")
        else:
            d, status, final_url, _cls = item
        target_url = final_url or f"http://{d}"
        cmd = [
            sys.executable,
            str(script_path),
            "--url", target_url,
        ]
        if open_reports:
            cmd.append("--open")

        print(f"[ARGUS] analyzing {target_url}")
        try:
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"[ARGUS] analysis failed for {target_url}: {e}")
        count += 1

    print(f"\n[ARGUS] Auto-analysis completed for {count} domains\n")

# -----------------------------
# CLI Hook
# -----------------------------

if "--campaign-intel" in sys.argv:
    try:
        keyword = sys.argv[sys.argv.index("--campaign-intel")+1]
    except Exception:
        print("Usage: --campaign-intel <brand> [--live-only] [--auto-analyze] [--open-reports] [--no-dynamic] [--dynamic-limit N]")
        sys.exit()

    live_only = "--live-only" in sys.argv
    auto_analyze = "--auto-analyze" in sys.argv
    open_reports = "--open-reports" in sys.argv
    dynamic_discovery = "--no-dynamic" not in sys.argv
    dynamic_limit = 50
    if "--dynamic-limit" in sys.argv:
        try:
            dynamic_limit = int(sys.argv[sys.argv.index("--dynamic-limit") + 1])
        except Exception:
            dynamic_limit = 50

    argus_campaign_intel(
        keyword,
        live_only=live_only,
        auto_analyze=auto_analyze,
        open_reports=open_reports,
        dynamic_discovery=dynamic_discovery,
        dynamic_limit=dynamic_limit
    )
    sys.exit()

    live_only = "--live-only" in sys.argv
    argus_campaign_intel(keyword, live_only=live_only)
    sys.exit()


def clean_detections(detections, input_types=None, page_width=None, page_height=None):
    if not detections:
        return []
    cleaned = []
    input_types = [str(x).lower() for x in (input_types or [])]
    for d in detections:
        try:
            conf = float(d.get("confidence", d.get("conf", 0.0)))
            if conf <= 0.0 or conf > 1.0:
                continue
            xyxy = d.get("xyxy")
            if xyxy and len(xyxy) == 4:
                x1, y1, x2, y2 = map(float, xyxy)
            else:
                box = d.get("box") or d.get("bbox")
                if not box or len(box) != 4:
                    continue
                x1, y1, x2, y2 = map(float, box)
                d["xyxy"] = [x1, y1, x2, y2]
            if x2 <= x1 or y2 <= y1:
                continue
            bw = x2 - x1
            bh = y2 - y1
            if page_width and page_height:
                if x1 < 0 or y1 < 0:
                    continue
                if x2 > float(page_width) or y2 > float(page_height):
                    continue
                area_ratio = (bw * bh) / max(1.0, float(page_width) * float(page_height))
                name = str(d.get("name", "")).lower()
                if name in {"login_button","username_field","password_field","forgot_password_link","remember_me_checkbox"}:
                    if area_ratio > 0.40:
                        continue
                    if bw > float(page_width) * 0.95 or bh > float(page_height) * 0.60:
                        continue
            name = str(d.get("name", "")).lower()
            if name == "password_field" and "password" not in input_types and conf < 0.35:
                continue
            d["conf"] = conf
            cleaned.append(d)
        except Exception:
            continue
    return cleaned
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARGUS PhishRadar — Visual Phishing Detection Engine
By Neurone4444

Scatta uno screenshot "live" di una URL (desktop o mobile) e lo passa a YOLO.
Fix principali:
- viewport configurabile (default DESKTOP 1366x768)
- screenshot full-page opzionale
- wait configurabile
- headless on/off
- user-agent configurabile (utile contro interstitial/anti-bot)
- imgsz YOLO configurabile (default 640)

Dipendenze:
  pip install ultralytics playwright
  python -m playwright install chromium

Esempio:
  python argus_phishradar.py --url "https://example.com" --yolo-model "best.pt" --fullpage --wait 3 --open
"""
import html
import argparse
import os
import sys
import time
import webbrowser
import tempfile
import hashlib
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
import urllib.request
import urllib.error
import socket
import ssl
import html
from difflib import SequenceMatcher

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL = BASE_DIR / "models" / "best.pt"
DEFAULT_OUTPUT = BASE_DIR / "output"
MODEL_URL = "https://github.com/Neurone4444/Neurone4444-argus-phishradar/releases/download/v1.0/best.pt"


def ensure_default_model() -> str:
    """Ensure the default YOLO model exists locally. Download it from GitHub Releases if missing."""
    safe_mkdir(DEFAULT_MODEL.parent)

    if DEFAULT_MODEL.exists():
        return str(DEFAULT_MODEL)

    print(f"[ARGUS] YOLO model not found at: {DEFAULT_MODEL}")
    print("[ARGUS] Downloading best.pt from GitHub Release...")

    try:
        urllib.request.urlretrieve(MODEL_URL, str(DEFAULT_MODEL))
    except Exception as e:
        raise RuntimeError(
            f"Unable to download YOLO model automatically from {MODEL_URL}. "
            f"Download it manually and place it in models/best.pt. Error: {e}"
        ) from e

    if not DEFAULT_MODEL.exists():
        raise RuntimeError("Model download completed but models/best.pt was not found.")

    print(f"[ARGUS] Model downloaded successfully: {DEFAULT_MODEL}")
    return str(DEFAULT_MODEL)

try:
    import mmh3
    MMH3_AVAILABLE = True
except Exception:
    MMH3_AVAILABLE = False


# Optional: OCR selettivo sui box YOLO (fallback semantico)
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except Exception:
    PYTESSERACT_AVAILABLE = False

# Optional: per annotare lo screenshot con box/circle/label
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# Optional: metriche visive (palette, hash, confronti)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False

# Optional: CLIP brand recognition (zero-shot). Richiede download pesi la prima volta.
try:
    import torch
    from transformers import CLIPProcessor, CLIPModel
    CLIP_AVAILABLE = True
except Exception:
    CLIP_AVAILABLE = False

_CLIP_MODEL = None
_CLIP_PROCESSOR = None
_CLIP_MODEL_ID = "openai/clip-vit-base-patch32"

def banner():
    b = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""
    print(b)
    print("ARGUS PhishRadar — Visual Phishing Detection Engine")
    print("By Neurone4444\n")

def now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def is_probably_interstitial(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    needles = [
        "suspected phishing",
        "cloudflare ray id",
        "performance & security by cloudflare",
        "attention required",
        "ddos protection by cloudflare",
        "verify you are human",
        "checking your browser",
    ]
    return any(n in t for n in needles)

def take_screenshot_playwright(url: str, out_png: Path, *, headless: bool, width: int, height: int,
                               wait: float, fullpage: bool, user_agent: str | None,
                               bypass_csp: bool = True) -> dict:
    """
    Ritorna meta: {title, final_url, status_hint, interstitial_hint, html_title, screenshot_path}
    Nota: senza API esterne; si basa su what we can read dal DOM.
    """
    meta = {
        "title": None,
        "final_url": url,
        "status_hint": None,
        "interstitial_hint": False,
        "screenshot_path": str(out_png),
        "dom_signals": {},
        "load_state": None,
        "redirect_chain": [url],
        "popup_urls": [],
    }
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("Playwright non disponibile. Installa: pip install playwright && python -m playwright install chromium") from e

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-dev-shm-usage"])
        context_kwargs = {
            "viewport": {"width": width, "height": height},
            "bypass_csp": bypass_csp,
        }
        if user_agent:
            context_kwargs["user_agent"] = user_agent

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        # best-effort: riduce chance di "blank" su siti con lazy-load
        page.set_default_timeout(45000)

        resp = None
        try:
            resp = page.goto(url, wait_until="domcontentloaded")
            # prova a far finire il caricamento di rete; fallback su sleep
            try:
                page.wait_for_load_state("networkidle", timeout=max(1500, int(wait * 1000)))
                meta["load_state"] = "networkidle"
            except Exception:
                meta["load_state"] = "domcontentloaded"
                if wait and wait > 0:
                    time.sleep(wait)

            try:
                page.wait_for_timeout(max(800, int(wait * 400)))
            except Exception:
                pass

            # prova a ottenere title e url finale
            try:
                meta["final_url"] = page.url
                if meta["final_url"] and meta["final_url"] not in meta["redirect_chain"]:
                    meta["redirect_chain"].append(meta["final_url"])
            except Exception:
                pass

            try:
                for pop in popup_pages[:10]:
                    try:
                        pop.wait_for_load_state("domcontentloaded", timeout=3000)
                    except Exception:
                        pass
                    try:
                        purl = str(pop.url)
                        if purl and purl not in meta["popup_urls"]:
                            meta["popup_urls"].append(purl)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                meta["title"] = page.title()
            except Exception:
                meta["title"] = None

            # heuristic interstitial
            body_text = ""
            try:
                body_text = page.inner_text("body")[:5000]
            except Exception:
                body_text = ""
            meta["interstitial_hint"] = is_probably_interstitial(body_text) or is_probably_interstitial(meta["title"] or "")

            # se sembra interstitial, aspetta un filo di più (spesso appare dopo 1-2s)
            if meta["interstitial_hint"] and wait < 2.5:
                time.sleep(2.5)

            # estrazione segnali DOM utili al mapping visuale
            try:
                dom_signals = {
                    "password_inputs": [],
                    "text_inputs": [],
                    "email_inputs": [],
                    "buttons": [],
                }
                def _bbox_for_all(selector: str):
                    out = []
                    try:
                        els = page.query_selector_all(selector)
                    except Exception:
                        els = []
                    for el in els[:10]:
                        try:
                            bb = el.bounding_box()
                            if bb:
                                out.append({
                                    "x": round(float(bb.get("x", 0.0)), 2),
                                    "y": round(float(bb.get("y", 0.0)), 2),
                                    "w": round(float(bb.get("width", 0.0)), 2),
                                    "h": round(float(bb.get("height", 0.0)), 2),
                                })
                        except Exception:
                            pass
                    return out

                dom_signals["password_inputs"] = _bbox_for_all('input[type="password"]')
                dom_signals["text_inputs"] = _bbox_for_all('input[type="text"]')
                dom_signals["email_inputs"] = _bbox_for_all('input[type="email"]')
                dom_signals["buttons"] = _bbox_for_all('button, input[type="submit"], input[type="button"]')
                try:
                    dom_signals["forms"] = page.locator("form").count()
                except Exception:
                    dom_signals["forms"] = 0
                meta["dom_signals"] = dom_signals
            except Exception:
                meta["dom_signals"] = {}

            # screenshot
            out_png.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(out_png), full_page=fullpage)
            meta["status_hint"] = getattr(resp, "status", None) if resp is not None else None

        finally:
            context.close()
            browser.close()

    return meta


def capture_live_session(url: str, out_png: Path, *, headless: bool, width: int, height: int,
                         wait: float, fullpage: bool, user_agent: str | None,
                         bypass_csp: bool = True,
                         step2_email: str | None = None,
                         step2_click_selectors: str | None = None) -> tuple[dict, dict, dict]:
    """
    Sessione Playwright unica: screenshot + meta + DOM intelligence + step2.
    Ritorna (meta, dom_intel, step2_info)
    """
    meta = {
        "title": None,
        "final_url": url,
        "status_hint": None,
        "interstitial_hint": False,
        "screenshot_path": str(out_png),
        "dom_signals": {},
        "load_state": None,
        "redirect_chain": [],
        "popup_urls": [],
        "navigation_error": None,
        "navigation_error_type": None,
        "reachable": False,
        "used_ignore_https_errors": True,
    }
    dom_intel = {}
    step2_info = {}

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("Playwright non disponibile. Installa: pip install playwright && python -m playwright install chromium") from e

    def _save_failure_placeholder(message: str):
        out_png.parent.mkdir(parents=True, exist_ok=True)
        if PIL_AVAILABLE:
            try:
                img = Image.new("RGB", (max(640, width), max(360, height)), (18, 24, 38))
                draw = ImageDraw.Draw(img)
                draw.multiline_text((24, 24), message[:3000], fill=(230, 238, 247), spacing=6)
                img.save(out_png, format="PNG")
                return
            except Exception:
                pass
        try:
            out_png.write_bytes(b"")
        except Exception:
            pass

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-dev-shm-usage"])
        context_kwargs = {
            "viewport": {"width": width, "height": height},
            "bypass_csp": bypass_csp,
            "ignore_https_errors": True,
        }
        if user_agent:
            context_kwargs["user_agent"] = user_agent

        context = browser.new_context(**context_kwargs)
        popup_pages = []
        page = context.new_page()
        page.set_default_timeout(45000)

        def _track_frame(frame):
            try:
                if frame == page.main_frame:
                    current = frame.url
                    if current and current not in meta["redirect_chain"]:
                        meta["redirect_chain"].append(current)
            except Exception:
                pass

        def _track_popup(new_page):
            try:
                popup_pages.append(new_page)
                if getattr(new_page, "url", None):
                    val = str(new_page.url)
                    if val and val not in meta["popup_urls"]:
                        meta["popup_urls"].append(val)
            except Exception:
                pass

        page.on("framenavigated", _track_frame)
        context.on("page", _track_popup)
        resp = None
        try:
            try:
                resp = page.goto(url, wait_until="domcontentloaded")
                meta["reachable"] = True
            except Exception as e:
                err = str(e)
                meta["navigation_error"] = err
                meta["navigation_error_type"] = type(e).__name__
                try:
                    meta["final_url"] = page.url or url
                except Exception:
                    meta["final_url"] = url
                if meta["final_url"] and meta["final_url"] not in meta["redirect_chain"]:
                    meta["redirect_chain"].append(meta["final_url"])
                _save_failure_placeholder(
                    "ARGUS - Navigation failed\n\n"
                    f"URL: {url}\n\n"
                    f"Error type: {meta['navigation_error_type']}\n\n"
                    f"Error: {err}"
                )
                return meta, dom_intel, step2_info

            try:
                page.wait_for_load_state("networkidle", timeout=max(1500, int(wait * 1000)))
                meta["load_state"] = "networkidle"
            except Exception:
                meta["load_state"] = "domcontentloaded"
                if wait and wait > 0:
                    time.sleep(wait)

            if step2_email:
                step2_info = advance_to_step2(page, step2_email, step2_click_selectors or "")
                try:
                    if step2_info.get("clicked") or step2_info.get("email_filled"):
                        try:
                            page.wait_for_load_state("networkidle", timeout=7000)
                        except Exception:
                            pass
                except Exception:
                    pass

            try:
                meta["final_url"] = page.url
            except Exception:
                pass
            if meta["final_url"] and meta["final_url"] not in meta["redirect_chain"]:
                meta["redirect_chain"].append(meta["final_url"])
            try:
                meta["title"] = page.title()
            except Exception:
                meta["title"] = None

            body_text = ""
            try:
                body_text = page.inner_text("body")[:5000]
            except Exception:
                body_text = ""
            meta["interstitial_hint"] = is_probably_interstitial(body_text) or is_probably_interstitial(meta["title"] or "")
            if meta["interstitial_hint"] and wait < 2.5:
                time.sleep(2.5)

            try:
                dom_signals = {
                    "password_inputs": [],
                    "text_inputs": [],
                    "email_inputs": [],
                    "buttons": [],
                }
                def _bbox_for_all(selector: str):
                    out = []
                    try:
                        els = page.query_selector_all(selector)
                    except Exception:
                        els = []
                    for el in els[:10]:
                        try:
                            bb = el.bounding_box()
                            if bb:
                                out.append({
                                    "x": round(float(bb.get("x", 0.0)), 2),
                                    "y": round(float(bb.get("y", 0.0)), 2),
                                    "w": round(float(bb.get("width", 0.0)), 2),
                                    "h": round(float(bb.get("height", 0.0)), 2),
                                })
                        except Exception:
                            pass
                    return out

                dom_signals["password_inputs"] = _bbox_for_all('input[type="password"]')
                dom_signals["text_inputs"] = _bbox_for_all('input[type="text"]')
                dom_signals["email_inputs"] = _bbox_for_all('input[type="email"]')
                dom_signals["buttons"] = _bbox_for_all('button, input[type="submit"], input[type="button"]')
                try:
                    dom_signals["forms"] = page.locator("form").count()
                except Exception:
                    dom_signals["forms"] = 0
                meta["dom_signals"] = dom_signals
            except Exception:
                meta["dom_signals"] = {}

            try:
                dom_intel = extract_dom_intelligence(page)
            except Exception:
                dom_intel = {}

            out_png.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(out_png), full_page=fullpage)
            meta["status_hint"] = getattr(resp, "status", None) if resp is not None else None
        finally:
            context.close()
            browser.close()

    return meta, dom_intel, step2_info


def annotate_screenshot(screenshot_png: Path, detections: list[dict], out_png: Path) -> bool:
    """
    Crea un PNG annotato sullo screenshot originale:
      - rettangolo (bbox)
      - cerchio centrato sul bbox (utile per evidenziare anche su UI dense)
      - label + conf
    Ritorna True se salvato, False se non possibile.
    """
    if not PIL_AVAILABLE:
        return False
    try:
        img = Image.open(screenshot_png).convert("RGBA")
        draw = ImageDraw.Draw(img)

        # font best-effort (evita dipendenze)
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None

        for d in detections:
            xyxy = d.get("xyxy") or []
            if len(xyxy) != 4:
                continue
            x1, y1, x2, y2 = map(float, xyxy)
            name = str(d.get("name", "obj"))
            conf = float(d.get("conf", 0.0))

            # bbox
            draw.rectangle([x1, y1, x2, y2], outline=(0, 255, 0, 255), width=3)

            # circle around bbox center
            cx = (x1 + x2) / 2.0
            cy = (y1 + y2) / 2.0
            w = max(1.0, (x2 - x1))
            h = max(1.0, (y2 - y1))
            r = max(w, h) / 2.0
            pad = max(6.0, r * 0.08)
            rr = r + pad
            draw.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=(255, 215, 0, 255), width=3)

            # label box
            label = f"{name} {conf:.2f}"
            tx = x1
            ty = max(0, y1 - 16)
            # background for readability
            draw.rectangle([tx, ty, tx + 8 + 7 * len(label), ty + 16], fill=(0, 0, 0, 160))
            draw.text((tx + 4, ty + 2), label, fill=(255, 255, 255, 255), font=font)

        out_png.parent.mkdir(parents=True, exist_ok=True)
        img = img.convert("RGB")
        img.save(out_png, format="PNG")
        return True
    except Exception:
        return False


def compute_palette(image_path: Path, k: int = 6) -> list[str]:
    """
    Estrae una palette (k colori) in HEX dallo screenshot.
    Usa quantizzazione PIL (senza sklearn).
    """
    if not PIL_AVAILABLE:
        return []
    try:
        img = Image.open(image_path).convert("RGB")
        # Riduci per velocità
        img_small = img.resize((max(64, img.width // 4), max(64, img.height // 4)))
        q = img_small.quantize(colors=max(2, min(16, k)), method=2)
        pal = q.getpalette()  # list
        # Conta colori usati
        colors = q.getcolors()
        if not colors:
            return []
        colors = sorted(colors, key=lambda x: x[0], reverse=True)[:k]
        hexes = []
        for _, idx in colors:
            r, g, b = pal[idx*3:idx*3+3]
            hexes.append(f"#{r:02x}{g:02x}{b:02x}")
        # Unici mantenendo ordine
        out = []
        for h in hexes:
            if h not in out:
                out.append(h)
        return out[:k]
    except Exception:
        return []

def compute_ahash(image_path: Path, hash_size: int = 8) -> str | None:
    """
    Average-hash (aHash) robusto e leggero. Ritorna stringa esadecimale.
    """
    if not (PIL_AVAILABLE and NUMPY_AVAILABLE):
        return None
    try:
        img = Image.open(image_path).convert("L").resize((hash_size, hash_size))
        arr = np.array(img, dtype=np.float32)
        mean = arr.mean()
        bits = (arr > mean).astype(np.uint8).flatten()
        # pack bits into hex string
        h = 0
        hex_out = []
        for i, b in enumerate(bits):
            h = (h << 1) | int(b)
            if (i + 1) % 4 == 0:
                hex_out.append(format(h, "x"))
                h = 0
        return "".join(hex_out)
    except Exception:
        return None

def hamming_hex(a: str | None, b: str | None) -> int | None:
    if not a or not b or len(a) != len(b):
        return None
    try:
        # Each hex nibble = 4 bits
        dist = 0
        for ca, cb in zip(a, b):
            va = int(ca, 16)
            vb = int(cb, 16)
            dist += bin(va ^ vb).count("1")
        return dist
    except Exception:
        return None

def compare_yolo_positions(dets_a: list[dict], dets_b: list[dict], *, w: int, h: int, tol: float = 0.06) -> dict:
    """
    Confronta posizioni (centro bbox) tra due screenshot per classi comuni.
    tol = soglia su distanza normalizzata per contare mismatch.
    Ritorna {common, mismatched, mismatch_rate, details[]}
    """
    # prendi detection migliore per classe (conf max)
    def best_by_class(dets):
        best = {}
        for d in dets:
            name = d.get("name")
            conf = float(d.get("conf", 0))
            if not name or "xyxy" not in d:
                continue
            if name not in best or conf > best[name]["conf"]:
                best[name] = {"conf": conf, "xyxy": d["xyxy"]}
        return best

    A = best_by_class(dets_a)
    B = best_by_class(dets_b)
    common = sorted(set(A.keys()) & set(B.keys()))
    details = []
    mism = 0
    for c in common:
        ax1, ay1, ax2, ay2 = map(float, A[c]["xyxy"])
        bx1, by1, bx2, by2 = map(float, B[c]["xyxy"])
        acx, acy = (ax1+ax2)/2, (ay1+ay2)/2
        bcx, bcy = (bx1+bx2)/2, (by1+by2)/2
        dx = (acx - bcx) / max(1.0, float(w))
        dy = (acy - bcy) / max(1.0, float(h))
        d = (dx*dx + dy*dy) ** 0.5
        is_mismatch = d > tol
        mism += 1 if is_mismatch else 0
        details.append({
            "class": c,
            "dist_norm": round(d, 4),
            "mismatch": bool(is_mismatch),
            "a_conf": round(float(A[c]["conf"]), 3),
            "b_conf": round(float(B[c]["conf"]), 3),
        })
    rate = (mism / len(common)) if common else 0.0
    return {
        "common": len(common),
        "mismatched": mism,
        "mismatch_rate": round(rate, 3),
        "tol": tol,
        "details": details,
    }


def clip_brand_recognition(image_path: Path, brands: list[str], *, device: str = "cpu") -> dict:
    """
    Zero-shot brand recognition via CLIP su uno o più crop dello screenshot.
    Ritorna:
      {
        "available": bool,
        "device": "cpu/cuda",
        "top_brand": str|None,
        "top_score": float|None,
        "scores": [{"brand":..,"score":..},...],
        "crops_used": int
      }
    Note:
      - richiede: pip install transformers torch
      - la prima volta scarica il modello (internet)
    """
    out = {"available": False, "device": device, "top_brand": None, "top_score": None, "scores": [], "crops_used": 0}
    if not (CLIP_AVAILABLE and PIL_AVAILABLE):
        return out
    if not brands:
        return out
    try:
        global _CLIP_MODEL, _CLIP_PROCESSOR
        if _CLIP_MODEL is None or _CLIP_PROCESSOR is None:
            _CLIP_MODEL = CLIPModel.from_pretrained(_CLIP_MODEL_ID)
            _CLIP_PROCESSOR = CLIPProcessor.from_pretrained(_CLIP_MODEL_ID)
        model = _CLIP_MODEL
        proc = _CLIP_PROCESSOR
        dev = device
        if dev == "cuda" and torch.cuda.is_available():
            model = model.to("cuda")
            dev = "cuda"
        else:
            model = model.to("cpu")
            dev = "cpu"
        out["device"] = dev

        img = Image.open(image_path).convert("RGB")
        W, H = img.size

        # Crop euristiche dove spesso sta il logo (top-left / top-center) + centro card
        crops = []
        # top-left
        crops.append(img.crop((0, 0, int(W * 0.45), int(H * 0.35))))
        # top-center
        crops.append(img.crop((int(W * 0.2), 0, int(W * 0.8), int(H * 0.35))))
        # center (per card login)
        crops.append(img.crop((int(W * 0.2), int(H * 0.15), int(W * 0.8), int(H * 0.75))))

        texts = [f"logo of {b}" for b in brands] + [f"{b} login page" for b in brands]
        # Per evitare duplicati enormi
        # Calcolo score massimo per brand su tutti i prompt e crop
        brand_scores = {b: -1e9 for b in brands}

        model.eval()
        with torch.no_grad():
            for cimg in crops:
                inputs = proc(text=texts, images=cimg, return_tensors="pt", padding=True)
                if dev == "cuda":
                    inputs = {k: v.to("cuda") for k, v in inputs.items()}
                outputs = model(**inputs)
                logits = outputs.logits_per_image[0]  # shape [num_texts]
                probs = logits.softmax(dim=0).detach().cpu().numpy().tolist()

                # Map prompts back to brands (2 prompts per brand)
                for i, b in enumerate(brands):
                    p1 = probs[i]  # "logo of b"
                    p2 = probs[i + len(brands)]  # "b login page"
                    brand_scores[b] = max(brand_scores[b], float(max(p1, p2)))

        scores = [{"brand": b, "score": round(float(brand_scores[b]), 4)} for b in brands]
        scores.sort(key=lambda x: x["score"], reverse=True)

        out["available"] = True
        out["scores"] = scores
        out["crops_used"] = len(crops)
        if scores:
            out["top_brand"] = scores[0]["brand"]
            out["top_score"] = scores[0]["score"]
        return out
    except Exception:
        return out



def build_layout_fingerprint(detections: list[dict], *, width: int, height: int) -> dict:
    """
    Costruisce una fingerprint del layout usando le detection YOLO.
    """
    if not detections or width <= 0 or height <= 0:
        return {"elements": [], "relations": [], "signature": None, "summary": ""}

    best = {}
    for d in detections:
        name = d.get("name")
        xyxy = d.get("xyxy")
        conf = float(d.get("conf", 0.0))
        if not name or not xyxy or len(xyxy) != 4:
            continue
        if name not in best or conf > best[name]["conf"]:
            best[name] = {"conf": conf, "xyxy": xyxy}

    elements = []
    for name, item in best.items():
        x1, y1, x2, y2 = map(float, item["xyxy"])
        cx = ((x1 + x2) / 2.0) / float(width)
        cy = ((y1 + y2) / 2.0) / float(height)
        w = max(0.0, (x2 - x1)) / float(width)
        h = max(0.0, (y2 - y1)) / float(height)
        area = w * h
        elements.append({
            "class": name,
            "conf": round(float(item["conf"]), 3),
            "cx": round(cx, 4),
            "cy": round(cy, 4),
            "w": round(w, 4),
            "h": round(h, 4),
            "area": round(area, 4),
        })

    elements.sort(key=lambda x: x["class"])

    relations = []
    for i in range(len(elements)):
        for j in range(i + 1, len(elements)):
            a = elements[i]
            b = elements[j]
            dx = b["cx"] - a["cx"]
            dy = b["cy"] - a["cy"]
            dist = (dx * dx + dy * dy) ** 0.5
            relations.append({
                "pair": f'{a["class"]}->{b["class"]}',
                "dx": round(dx, 4),
                "dy": round(dy, 4),
                "dist": round(dist, 4),
            })

    relations.sort(key=lambda x: x["pair"])

    summary_parts = [
        f'{e["class"]}@{e["cx"]:.3f},{e["cy"]:.3f}:{e["w"]:.3f}x{e["h"]:.3f}'
        for e in elements
    ]
    relation_parts = [
        f'{r["pair"]}:{r["dx"]:.3f},{r["dy"]:.3f},{r["dist"]:.3f}'
        for r in relations
    ]
    summary = "|".join(summary_parts + relation_parts)
    signature = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:24]

    return {
        "elements": elements,
        "relations": relations,
        "summary": summary,
        "signature": signature,
        "n_elements": len(elements),
        "n_relations": len(relations),
    }

def compare_layout_fingerprints(fp_a: dict | None, fp_b: dict | None) -> dict:
    out = {
        "common_classes": 0,
        "position_shift_avg": None,
        "size_shift_avg": None,
        "same_signature": False,
    }
    if not fp_a or not fp_b:
        return out
    a_elems = {e["class"]: e for e in (fp_a.get("elements") or [])}
    b_elems = {e["class"]: e for e in (fp_b.get("elements") or [])}
    common = sorted(set(a_elems) & set(b_elems))
    out["common_classes"] = len(common)
    if common:
        pos_shifts = []
        size_shifts = []
        for c in common:
            a = a_elems[c]
            b = b_elems[c]
            pos = ((a["cx"] - b["cx"]) ** 2 + (a["cy"] - b["cy"]) ** 2) ** 0.5
            size = (abs(a["w"] - b["w"]) + abs(a["h"] - b["h"])) / 2.0
            pos_shifts.append(pos)
            size_shifts.append(size)
        out["position_shift_avg"] = round(sum(pos_shifts) / len(pos_shifts), 4)
        out["size_shift_avg"] = round(sum(size_shifts) / len(size_shifts), 4)
    out["same_signature"] = bool(fp_a.get("signature") and fp_a.get("signature") == fp_b.get("signature"))
    return out


TELEGRAM_URL_NEEDLES = ["t.me/", "telegram.me/", "tg://", "telegram.org/"]


def extract_urls_from_text(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        s = str(value)
    except Exception:
        return []
    patterns = [
        r'https?://[^\s"\'<>]+',
        r'tg://[^\s"\'<>]+',
    ]
    found = []
    for pat in patterns:
        try:
            found.extend(re.findall(pat, s, flags=re.I))
        except Exception:
            pass
    out = []
    for u in found:
        u = str(u).strip().rstrip(";,)]}\"'")
        if u and u not in out:
            out.append(u)
    return out


def collect_telegram_targets(dom_intel: dict | None = None, meta: dict | None = None) -> dict:
    dom_intel = dom_intel or {}
    meta = meta or {}
    tg = (dom_intel.get("telegram_indicators") or {})
    out = {
        "all": [],
        "from_links": [],
        "from_meta_refresh": [],
        "from_inline_js": [],
        "from_onclick": [],
        "from_text": [],
        "from_redirect_chain": [],
        "from_popups": [],
    }

    def _push(bucket: str, value: str | None):
        if not value:
            return
        val = str(value).strip()
        if not val:
            return
        if not any(n in val.lower() for n in TELEGRAM_URL_NEEDLES):
            return
        if val not in out[bucket]:
            out[bucket].append(val)
        if val not in out["all"]:
            out["all"].append(val)

    for x in tg.get("telegram_links") or []:
        _push("from_links", x)

    for item in tg.get("telegram_meta_refresh") or []:
        if isinstance(item, dict):
            for u in extract_urls_from_text(item.get("content")):
                _push("from_meta_refresh", u)
        else:
            for u in extract_urls_from_text(item):
                _push("from_meta_refresh", u)

    for item in tg.get("telegram_inline_hits") or []:
        for u in extract_urls_from_text(item):
            _push("from_inline_js", u)

    for item in tg.get("telegram_onclick_hits") or []:
        for u in extract_urls_from_text(item):
            _push("from_onclick", u)

    for item in tg.get("telegram_text_hits") or []:
        for u in extract_urls_from_text(item):
            _push("from_text", u)

    for item in meta.get("redirect_chain") or []:
        _push("from_redirect_chain", item)

    for item in meta.get("popup_urls") or []:
        _push("from_popups", item)

    return out


def looks_like_blank_redirect_landing(meta: dict | None = None, dom_intel: dict | None = None, detections: list[dict] | None = None, visual_metrics: dict | None = None) -> bool:
    meta = meta or {}
    dom_intel = dom_intel or {}
    detections = detections or []
    visual_metrics = visual_metrics or {}

    if detections:
        return False

    title = str(meta.get("title") or "").strip()
    links = dom_intel.get("links") or []
    forms = dom_intel.get("form_actions") or []
    scripts = dom_intel.get("scripts") or []
    body_sample = str(dom_intel.get("page_text_sample") or "").strip()
    palette = visual_metrics.get("palette_hex") or []
    ahash = str(visual_metrics.get("ahash") or "")

    pale_palette = bool(palette) and all(str(c).lower() in {"#ffffff", "#fefefe", "#fcfcfc", "#fafafa"} for c in palette[:3])
    emptyish_text = (not body_sample) or (len(body_sample) < 40)
    no_dom = (not links) and (not forms) and (not scripts)
    no_title = not title
    zero_hash = ahash == "0000000000000000"
    return (no_title and no_dom and emptyish_text) or (zero_hash and pale_palette and no_dom)


def detect_telegram_indicators(page) -> dict:
    out = {
        "telegram_links": [],
        "telegram_meta_refresh": [],
        "telegram_inline_hits": [],
        "telegram_text_hits": [],
        "telegram_onclick_hits": [],
        "telegram_popup_urls": [],
        "telegram_redirect_urls": [],
    }

    telegram_needles = TELEGRAM_URL_NEEDLES
    redirect_needles = [
        "window.location", "location.href", "location.replace",
        "window.open", "top.location", "document.location", "location.assign"
    ]

    try:
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        out["telegram_links"] = [x for x in links if any(n in str(x).lower() for n in telegram_needles)][:50]
    except Exception:
        pass

    try:
        metas = page.eval_on_selector_all(
            'meta[http-equiv]',
            """els => els.map(e => ({
                equiv: e.getAttribute('http-equiv') || '',
                content: e.getAttribute('content') || ''
            }))"""
        )
        for m in metas:
            equiv = str(m.get("equiv", "")).lower()
            content = str(m.get("content", "")).lower()
            if equiv == "refresh" and any(n in content for n in telegram_needles):
                out["telegram_meta_refresh"].append(m)
    except Exception:
        pass

    try:
        inline_scripts = page.eval_on_selector_all(
            "script:not([src])",
            "els => els.map(e => e.textContent || '')"
        )
        for s in inline_scripts[:100]:
            sl = str(s).lower()
            if any(n in sl for n in telegram_needles) or any(k in sl for k in redirect_needles):
                out["telegram_inline_hits"].append(str(s)[:1200])
    except Exception:
        pass

    try:
        onclicks = page.eval_on_selector_all(
            "[onclick]",
            "els => els.map(e => e.getAttribute('onclick') || '')"
        )
        for s in onclicks[:100]:
            sl = str(s).lower()
            if any(n in sl for n in telegram_needles) or any(k in sl for k in redirect_needles):
                out["telegram_onclick_hits"].append(str(s)[:600])
    except Exception:
        pass

    try:
        body_text = page.inner_text("body")[:12000]
        bl = str(body_text).lower()
        if any(n in bl for n in telegram_needles):
            out["telegram_text_hits"].append(str(body_text)[:1200])
    except Exception:
        pass

    return out


def extract_dom_intelligence(page):
    """
    Estrae informazioni utili dal DOM per analisi phishing:
    - link presenti
    - form action
    - input types
    - possibili endpoint di esfiltrazione
    - meta refresh / script inline / onclick / segnali Telegram
    """
    intel = {
        "links": [],
        "form_actions": [],
        "input_types": [],
        "scripts": [],
        "favicon_links": [],
        "meta_refresh": [],
        "inline_script_hits": [],
        "onclick_hits": [],
        "page_text_sample": "",
        "telegram_indicators": {},
        "semantic_candidates": [],
    }

    try:
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        intel["links"] = list(dict.fromkeys(links))[:150]
    except Exception:
        pass

    try:
        forms = page.eval_on_selector_all("form", "els => els.map(e => e.action)")
        intel["form_actions"] = list(dict.fromkeys(forms))[:100]
    except Exception:
        pass

    try:
        inputs = page.eval_on_selector_all("input", "els => els.map(e => e.type)")
        intel["input_types"] = list(dict.fromkeys(inputs))[:100]
    except Exception:
        pass

    try:
        scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
        intel["scripts"] = list(dict.fromkeys(scripts))[:100]
    except Exception:
        pass

    try:
        favicons = page.eval_on_selector_all("link[rel*='icon'][href]", "els => els.map(e => e.href)")
        intel["favicon_links"] = list(dict.fromkeys(favicons))[:10]
    except Exception:
        intel["favicon_links"] = []

    try:
        metas = page.eval_on_selector_all(
            'meta[http-equiv]',
            """els => els.map(e => ({
                equiv: e.getAttribute('http-equiv') || '',
                content: e.getAttribute('content') || ''
            }))"""
        )
        intel["meta_refresh"] = metas[:30]
    except Exception:
        intel["meta_refresh"] = []

    try:
        inline_scripts = page.eval_on_selector_all(
            "script:not([src])",
            "els => els.map(e => e.textContent || '')"
        )
        interesting = []
        needles = [
            "window.location", "location.href", "location.replace", "location.assign",
            "window.open", "top.location", "document.location",
            "t.me/", "telegram.me/", "tg://", "telegram.org/",
            "mailto:", "api.telegram.org", "webhook", "discord", "emailjs", "smtpjs"
        ]
        for s in inline_scripts[:120]:
            sl = str(s).lower()
            if any(n in sl for n in needles):
                interesting.append(str(s)[:1200])
        intel["inline_script_hits"] = interesting[:40]
    except Exception:
        intel["inline_script_hits"] = []

    try:
        onclicks = page.eval_on_selector_all(
            "[onclick]",
            "els => els.map(e => e.getAttribute('onclick') || '')"
        )
        interesting = []
        needles = [
            "window.location", "location.href", "location.replace", "location.assign",
            "window.open", "top.location", "document.location",
            "t.me/", "telegram.me/", "tg://", "telegram.org/"
        ]
        for s in onclicks[:120]:
            sl = str(s).lower()
            if any(n in sl for n in needles):
                interesting.append(str(s)[:800])
        intel["onclick_hits"] = interesting[:40]
    except Exception:
        intel["onclick_hits"] = []

    try:
        intel["page_text_sample"] = str(page.inner_text("body")[:4000])
    except Exception:
        intel["page_text_sample"] = ""

    try:
        intel["telegram_indicators"] = detect_telegram_indicators(page)
    except Exception:
        intel["telegram_indicators"] = {}

    try:
        js = r"""els => els.map((e, idx) => {
            const r = e.getBoundingClientRect();
            const style = window.getComputedStyle(e);
            const safe = (v) => (v || '').toString().trim();
            const txt = safe((e.innerText || e.textContent || '')).replace(/\s+/g, ' ').slice(0, 160);
            const tag = (e.tagName || '').toLowerCase();
            let role = safe(e.getAttribute('role')).toLowerCase();
            const type = safe(e.getAttribute('type')).toLowerCase();
            const placeholder = safe(e.getAttribute('placeholder'));
            const aria = safe(e.getAttribute('aria-label'));
            const name = safe(e.getAttribute('name'));
            const eid = safe(e.getAttribute('id'));
            const title = safe(e.getAttribute('title'));
            const href = safe(e.getAttribute('href'));
            const alt = safe(e.getAttribute('alt'));
            const value = safe(e.getAttribute('value'));
            const autocomplete = safe(e.getAttribute('autocomplete')).toLowerCase();
            const visible = !(style.visibility === 'hidden' || style.display === 'none' || r.width < 6 || r.height < 6);
            if (!visible) return null;
            return {
                idx, tag, role, type, placeholder, aria_label: aria, name, id: eid, title, href, alt, value, autocomplete,
                text: txt,
                x: Math.round(r.x * 100) / 100,
                y: Math.round(r.y * 100) / 100,
                w: Math.round(r.width * 100) / 100,
                h: Math.round(r.height * 100) / 100
            };
        }).filter(Boolean)"""
        candidates = page.eval_on_selector_all("input, button, a, label, textarea, select, [role='button'], [role='link'], img, div, span", js)
        intel["semantic_candidates"] = (candidates or [])[:200]
    except Exception:
        intel["semantic_candidates"] = []

    return intel




def _box_iou_xywh_xyxy(candidate: dict, det_xyxy: list[float]) -> float:
    try:
        cx1 = float(candidate.get("x", 0.0))
        cy1 = float(candidate.get("y", 0.0))
        cx2 = cx1 + float(candidate.get("w", 0.0))
        cy2 = cy1 + float(candidate.get("h", 0.0))
        dx1, dy1, dx2, dy2 = map(float, det_xyxy)
        ix1 = max(cx1, dx1)
        iy1 = max(cy1, dy1)
        ix2 = min(cx2, dx2)
        iy2 = min(cy2, dy2)
        iw = max(0.0, ix2 - ix1)
        ih = max(0.0, iy2 - iy1)
        inter = iw * ih
        if inter <= 0:
            return 0.0
        a1 = max(1.0, (cx2 - cx1) * (cy2 - cy1))
        a2 = max(1.0, (dx2 - dx1) * (dy2 - dy1))
        return float(inter / max(1.0, a1 + a2 - inter))
    except Exception:
        return 0.0


def _center_distance_norm(candidate: dict, det_xyxy: list[float], width: int, height: int) -> float:
    try:
        ccx = float(candidate.get("x", 0.0)) + float(candidate.get("w", 0.0)) / 2.0
        ccy = float(candidate.get("y", 0.0)) + float(candidate.get("h", 0.0)) / 2.0
        dx1, dy1, dx2, dy2 = map(float, det_xyxy)
        dcx = (dx1 + dx2) / 2.0
        dcy = (dy1 + dy2) / 2.0
        nx = (ccx - dcx) / max(1.0, float(width))
        ny = (ccy - dcy) / max(1.0, float(height))
        return float((nx * nx + ny * ny) ** 0.5)
    except Exception:
        return 999.0


def _semantic_expected_for_class(class_name: str) -> dict:
    cls = str(class_name or "").lower()
    if cls == "password_field":
        return {"keywords": ["password", "passcode", "пароль", "senha", "mot de passe", "contraseña"], "types": ["password"], "tags": ["input"]}
    if cls == "username_field":
        return {"keywords": ["email", "e-mail", "username", "user", "phone", "mobile", "account", "login", "identifier"], "types": ["email", "text", "tel"], "tags": ["input", "textarea"]}
    if cls == "login_button":
        return {"keywords": ["sign in", "log in", "login", "continue", "next", "accedi", "entra", "submit", "verify"], "types": ["submit", "button"], "tags": ["button", "a", "input"], "roles": ["button", "link"]}
    if cls == "forgot_password_link":
        return {"keywords": ["forgot", "reset", "recover", "password dimenticata", "forgot password"], "tags": ["a", "button"], "roles": ["link", "button"]}
    if cls == "remember_me_checkbox":
        return {"keywords": ["remember", "ricorda", "stay signed", "keep me"], "types": ["checkbox"], "tags": ["input", "label"]}
    if cls == "2fa_field":
        return {"keywords": ["code", "otp", "2fa", "two-factor", "verification", "security code", "authenticator"], "types": ["text", "tel", "number"], "tags": ["input"]}
    if cls == "captcha":
        return {"keywords": ["captcha", "robot", "human", "verify you are human", "recaptcha"], "tags": ["div", "iframe", "span", "input"]}
    if cls == "security_alert":
        return {"keywords": ["security", "alert", "warning", "suspicious", "verify", "protect", "unusual"], "tags": ["div", "span", "p", "section"]}
    if cls == "suspicious_banner":
        return {"keywords": ["alert", "warning", "security", "verify", "notice", "important"], "tags": ["div", "span", "p", "section"]}
    return {"keywords": [], "types": [], "tags": [], "roles": []}


def _ocr_text_from_crop(image_path: Path, xyxy: list[float]) -> str:
    if not (PYTESSERACT_AVAILABLE and PIL_AVAILABLE):
        return ""
    try:
        img = Image.open(image_path).convert("RGB")
        x1, y1, x2, y2 = [int(max(0, round(v))) for v in xyxy]
        x2 = min(img.width, max(x1 + 1, x2))
        y2 = min(img.height, max(y1 + 1, y2))
        crop = img.crop((x1, y1, x2, y2))
        crop = crop.resize((max(60, crop.width * 2), max(24, crop.height * 2)))
        text = pytesseract.image_to_string(crop, config='--psm 6')
        return re.sub(r'\s+', ' ', str(text or '')).strip()[:160]
    except Exception:
        return ""


def semantic_rescore_detections(detections: list[dict], dom_intel: dict | None, image_path: Path, *, width: int, height: int) -> tuple[list[dict], list[dict], dict]:

    # ARGUS CLEAN PATCH (safe)
    try:
        detections = clean_detections(
            detections,
            input_types=dom_intel.get("input_types", []) if isinstance(dom_intel, dict) else [],
            page_width=width,
            page_height=height
        )
    except Exception:
        pass
    dom_intel = dom_intel or {}
    candidates = list(dom_intel.get("semantic_candidates") or [])
    info = {
        "enabled": True,
        "candidates": len(candidates),
        "validated": [],
        "suppressed": [],
        "ocr_available": bool(PYTESSERACT_AVAILABLE),
    }
    if not detections:
        return detections, [], info

    kept = []
    suppressed = []

    for d in detections:
        cls = str(d.get("name", ""))
        xyxy = d.get("xyxy") or []
        original_conf = float(d.get("conf", 0.0))
        if len(xyxy) != 4:
            kept.append(d)
            continue

        spec = _semantic_expected_for_class(cls)
        best = None
        best_score = -999.0
        for cand in candidates:
            iou = _box_iou_xywh_xyxy(cand, xyxy)
            dist = _center_distance_norm(cand, xyxy, width, height)
            if iou <= 0.0 and dist > 0.16:
                continue
            texts = " ".join([
                str(cand.get("text") or ""),
                str(cand.get("placeholder") or ""),
                str(cand.get("aria_label") or ""),
                str(cand.get("name") or ""),
                str(cand.get("id") or ""),
                str(cand.get("title") or ""),
                str(cand.get("alt") or ""),
                str(cand.get("value") or ""),
                str(cand.get("autocomplete") or ""),
            ]).lower()
            tag = str(cand.get("tag") or "").lower()
            role = str(cand.get("role") or "").lower()
            ctype = str(cand.get("type") or "").lower()
            semantic = 0.0
            if spec.get("keywords") and any(k in texts for k in spec["keywords"]):
                semantic += 0.75
            if spec.get("types") and ctype in spec["types"]:
                semantic += 0.85
            if spec.get("tags") and tag in spec["tags"]:
                semantic += 0.25
            if spec.get("roles") and role in spec["roles"]:
                semantic += 0.20
            if cls == "username_field" and any(bad in texts for bad in ["search", "cerca", "newsletter", "coupon"]):
                semantic -= 0.90
            if cls == "login_button" and any(bad in texts for bad in ["learn more", "discover", "shop", "subscribe", "buy now"]):
                semantic -= 0.80
            score = semantic + (iou * 1.40) - (dist * 1.20)
            if score > best_score:
                best_score = score
                best = {
                    "tag": tag, "type": ctype, "role": role,
                    "text": texts[:160],
                    "iou": round(iou, 4),
                    "dist": round(dist, 4),
                    "score": round(score, 4),
                }

        ocr_text = ""
        ocr_hits = 0
        if (best is None or best_score < 0.35) and cls in {"username_field", "password_field", "login_button", "forgot_password_link", "2fa_field", "captcha"}:
            ocr_text = _ocr_text_from_crop(image_path, xyxy).lower()
            if ocr_text:
                hits = spec.get("keywords") or []
                ocr_hits = sum(1 for k in hits if k in ocr_text)
                best_score = max(best_score, 0.55 + min(0.25, 0.08 * ocr_hits))

        adjusted = original_conf
        verdict = "neutral"
        if best_score >= 0.95:
            adjusted = min(0.99, original_conf + 0.18)
            verdict = "confirmed"
        elif best_score >= 0.55:
            adjusted = min(0.99, original_conf + 0.08)
            verdict = "supported"
        elif best_score <= 0.05:
            adjusted = max(0.05, original_conf - 0.28)
            verdict = "weak"
        elif best_score < 0.35:
            adjusted = max(0.05, original_conf - 0.16)
            verdict = "unclear"

        enriched = dict(d)
        enriched["original_conf"] = round(original_conf, 4)
        enriched["conf"] = round(adjusted, 4)
        enriched["semantic_validation"] = {
            "verdict": verdict,
            "best_score": round(best_score, 4),
            "dom_match": best,
            "ocr_text": ocr_text[:160] if ocr_text else "",
            "ocr_hits": ocr_hits,
        }

        suppress = False
        if cls in {"security_alert", "suspicious_banner", "captcha", "forgot_password_link", "remember_me_checkbox"} and best_score < 0.0:
            suppress = True
        if cls in {"username_field", "password_field", "login_button", "2fa_field"} and adjusted < 0.18 and best_score < 0.0:
            suppress = True

        if suppress:
            suppressed.append({**enriched, "filtered_reason": "semantic_validator"})
            info["suppressed"].append({"class": cls, "score": round(best_score, 4), "ocr_text": ocr_text[:80]})
        else:
            kept.append(enriched)
            info["validated"].append({"class": cls, "verdict": verdict, "score": round(best_score, 4), "conf_before": round(original_conf, 4), "conf_after": round(adjusted, 4)})

    kept.sort(key=lambda x: x.get("conf", 0.0), reverse=True)
    return kept, suppressed, info


def filter_anomalous_detections(detections: list[dict], *, width: int, height: int) -> tuple[list[dict], list[dict]]:
    """
    Filtra detection palesemente anomale per alcune classi UI.
    Utile per evitare falsi positivi come header/topbar classificati come login_button.
    """
    kept = []
    removed = []
    for d in detections:
        xyxy = d.get("xyxy") or []
        name = str(d.get("name", ""))
        if len(xyxy) != 4 or width <= 0 or height <= 0:
            kept.append(d)
            continue
        x1, y1, x2, y2 = map(float, xyxy)
        bw = max(0.0, x2 - x1)
        bh = max(0.0, y2 - y1)
        area_ratio = (bw * bh) / float(width * height)
        width_ratio = bw / float(width)
        height_ratio = bh / float(height)
        top_ratio = y1 / float(height)

        suspicious = False
        # Header/banner scambiati per login_button/link
        if name in {"login_button", "forgot_password_link", "remember_me_checkbox"}:
            if area_ratio > 0.12 or width_ratio > 0.65 or (top_ratio < 0.12 and width_ratio > 0.45):
                suspicious = True
        # Campi input improbabili enormi
        if name in {"username_field", "password_field", "2fa_field"}:
            if area_ratio > 0.20 or height_ratio > 0.18 or width_ratio > 0.85:
                suspicious = True
        # Banner/alert enormi o quasi full-width in alto: spesso falso positivo su hero/header
        if name in {"security_alert", "suspicious_banner"}:
            if area_ratio > 0.30 or (width_ratio > 0.90 and top_ratio < 0.15) or height_ratio > 0.30:
                suspicious = True
        # Captcha e loghi molto grandi sono spesso artefatti grafici, non veri widget UI
        if name in {"captcha", "logo_microsoft", "logo_google", "logo_facebook", "logo_paypal", "logo_amazon", "logo_apple", "logo_netflix", "logo_instagram", "logo_twitter", "logo_linkedin"}:
            if area_ratio > 0.10 or height_ratio > 0.22 or width_ratio > 0.40:
                suspicious = True

        if suspicious:
            removed.append({
                **d,
                "filtered_reason": {
                    "area_ratio": round(area_ratio, 4),
                    "width_ratio": round(width_ratio, 4),
                    "height_ratio": round(height_ratio, 4),
                    "top_ratio": round(top_ratio, 4),
                }
            })
        else:
            kept.append(d)
    return kept, removed


def advance_to_step2(page, email_value: str, selectors_csv: str) -> dict:
    """
    Best-effort: inserisce una email e prova ad avanzare al secondo step.
    Utile per Microsoft/Google login a step multipli.
    """
    out = {"attempted": False, "email_filled": False, "clicked": False, "final_url": None, "title": None}
    try:
        email_selectors = [
            "input[type=email]",
            "input[name=loginfmt]",
            "input[name=email]",
            "input[type=text]",
        ]
        field = None
        for sel in email_selectors:
            try:
                field = page.locator(sel).first
                if field.count() > 0:
                    break
            except Exception:
                field = None
        if field is not None:
            out["attempted"] = True
            try:
                field.fill(email_value)
                out["email_filled"] = True
            except Exception:
                try:
                    field.click()
                    field.type(email_value, delay=20)
                    out["email_filled"] = True
                except Exception:
                    pass

        selectors = [s.strip() for s in (selectors_csv or "").split(",") if s.strip()]
        for sel in selectors:
            if out["clicked"]:
                break
            try:
                if sel.startswith("text="):
                    page.get_by_text(sel.split("=", 1)[1], exact=False).first.click(timeout=2500)
                else:
                    page.locator(sel).first.click(timeout=2500)
                out["clicked"] = True
            except Exception:
                continue

        try:
            page.wait_for_load_state("networkidle", timeout=7000)
        except Exception:
            pass
        out["final_url"] = page.url
        try:
            out["title"] = page.title()
        except Exception:
            pass
    except Exception:
        pass
    return out



def _clip_box(x1: float, y1: float, x2: float, y2: float, width: int, height: int) -> list[int]:
    x1 = int(max(0, min(width - 1, round(x1))))
    y1 = int(max(0, min(height - 1, round(y1))))
    x2 = int(max(x1 + 1, min(width, round(x2))))
    y2 = int(max(y1 + 1, min(height, round(y2))))
    return [x1, y1, x2, y2]


def _iou_xyxy(a: list[float], b: list[float]) -> float:
    try:
        ax1, ay1, ax2, ay2 = map(float, a)
        bx1, by1, bx2, by2 = map(float, b)
        ix1 = max(ax1, bx1)
        iy1 = max(ay1, by1)
        ix2 = min(ax2, bx2)
        iy2 = min(ay2, by2)
        iw = max(0.0, ix2 - ix1)
        ih = max(0.0, iy2 - iy1)
        inter = iw * ih
        if inter <= 0:
            return 0.0
        aa = max(1.0, (ax2 - ax1) * (ay2 - ay1))
        bb = max(1.0, (bx2 - bx1) * (by2 - by1))
        return float(inter / max(1.0, aa + bb - inter))
    except Exception:
        return 0.0


def _extract_detections_from_results(results, *, offset_x: int = 0, offset_y: int = 0) -> list[dict]:
    detections = []
    for r in results:
        names = r.names if hasattr(r, "names") else {}
        boxes = getattr(r, "boxes", None)
        if boxes is None:
            continue
        for b in boxes:
            try:
                cls_id = int(b.cls.item()) if hasattr(b.cls, "item") else int(b.cls)
                conf = float(b.conf.item()) if hasattr(b.conf, "item") else float(b.conf)
                xyxy = b.xyxy[0].tolist() if hasattr(b.xyxy[0], "tolist") else list(map(float, b.xyxy[0]))
                xyxy = [round(float(xyxy[0]) + offset_x, 2), round(float(xyxy[1]) + offset_y, 2), round(float(xyxy[2]) + offset_x, 2), round(float(xyxy[3]) + offset_y, 2)]
                name = names.get(cls_id, str(cls_id))
                detections.append({"name": name, "conf": conf, "xyxy": xyxy})
            except Exception:
                continue
    return detections


def _merge_detection_sets(detection_sets: list[list[dict]], *, iou_threshold: float = 0.55) -> list[dict]:
    merged = []
    for dets in detection_sets:
        for d in dets or []:
            name = str(d.get("name", ""))
            xyxy = d.get("xyxy") or []
            conf = float(d.get("conf", 0.0))
            if len(xyxy) != 4:
                continue
            replaced = False
            for i, cur in enumerate(merged):
                if str(cur.get("name", "")) != name:
                    continue
                if _iou_xyxy(cur.get("xyxy") or [], xyxy) >= iou_threshold:
                    if conf > float(cur.get("conf", 0.0)):
                        merged[i] = d
                    replaced = True
                    break
            if not replaced:
                merged.append(d)
    merged.sort(key=lambda x: float(x.get("conf", 0.0)), reverse=True)
    return merged


def build_ocr_light_proposals(image_path: Path, *, width: int, height: int, max_proposals: int = 8, min_conf: int = 35) -> dict:
    info = {
        "enabled": True,
        "available": bool(PYTESSERACT_AVAILABLE and PIL_AVAILABLE),
        "tokens_total": 0,
        "tokens_used": 0,
        "matched_terms": [],
        "proposals": [],
    }
    if not (PYTESSERACT_AVAILABLE and PIL_AVAILABLE):
        return info
    try:
        img = Image.open(image_path).convert("RGB")
        img_w, img_h = img.size
        width = int(width or img_w or 1)
        height = int(height or img_h or 1)
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, config='--psm 11')
    except Exception:
        return info

    lexicon = {
        "username_field": ["email", "e-mail", "username", "user", "login", "account", "phone", "mobile", "identifier", "mail"],
        "password_field": ["password", "passcode", "pwd", "пароль", "contraseña", "senha", "mot", "pass"],
        "login_button": ["sign", "login", "log", "continue", "next", "accedi", "entra", "submit", "verify", "access"],
        "forgot_password_link": ["forgot", "reset", "recover"],
        "2fa_field": ["otp", "code", "2fa", "authenticator", "verification"],
        "captcha": ["captcha", "robot", "human", "recaptcha"],
    }
    tokens = []
    n = len(data.get("text", []))
    for i in range(n):
        txt = str(data.get("text", [""])[i] or "").strip()
        if not txt:
            continue
        try:
            conf = int(float(data.get("conf", ["-1"])[i]))
        except Exception:
            conf = -1
        if conf < min_conf:
            continue
        x = int(float(data.get("left", [0])[i]))
        y = int(float(data.get("top", [0])[i]))
        w = int(float(data.get("width", [0])[i]))
        h = int(float(data.get("height", [0])[i]))
        norm = re.sub(r'[^a-z0-9@._+-]+', '', txt.lower())
        if not norm:
            continue
        tokens.append({"text": txt, "norm": norm, "conf": conf, "x": x, "y": y, "w": w, "h": h})
    info["tokens_total"] = len(tokens)

    raw_props = []
    matched_terms = []
    for tok in tokens:
        matched_class = None
        for cls, keywords in lexicon.items():
            if any(k in tok["norm"] for k in keywords):
                matched_class = cls
                break
        if not matched_class:
            continue
        matched_terms.append(tok["text"])
        x1, y1, x2, y2 = tok["x"], tok["y"], tok["x"] + tok["w"], tok["y"] + tok["h"]
        # espansioni euristiche: OCR individua il testo, YOLO lavora meglio se vede il widget attorno
        if matched_class in {"username_field", "password_field", "2fa_field"}:
            pad_x = max(120, int(tok["w"] * 4.0))
            pad_top = max(20, int(tok["h"] * 1.8))
            pad_bottom = max(70, int(tok["h"] * 3.5))
            box = _clip_box(x1 - pad_x, y1 - pad_top, x2 + pad_x, y2 + pad_bottom, img_w, img_h)
        elif matched_class == "login_button":
            pad_x = max(80, int(tok["w"] * 2.5))
            pad_y = max(35, int(tok["h"] * 2.5))
            box = _clip_box(x1 - pad_x, y1 - pad_y, x2 + pad_x, y2 + pad_y, img_w, img_h)
        elif matched_class == "forgot_password_link":
            pad_x = max(70, int(tok["w"] * 2.8))
            pad_y = max(24, int(tok["h"] * 2.2))
            box = _clip_box(x1 - pad_x, y1 - pad_y, x2 + pad_x, y2 + pad_y, img_w, img_h)
        else:
            pad_x = max(90, int(tok["w"] * 3.0))
            pad_y = max(40, int(tok["h"] * 2.5))
            box = _clip_box(x1 - pad_x, y1 - pad_y, x2 + pad_x, y2 + pad_y, img_w, img_h)
        raw_props.append({
            "class_hint": matched_class,
            "keyword": tok["text"],
            "ocr_conf": tok["conf"],
            "xyxy": box,
            "area": max(1, (box[2] - box[0]) * (box[3] - box[1])),
        })

    merged = []
    for prop in raw_props:
        merged_into_existing = False
        for cur in merged:
            if cur["class_hint"] != prop["class_hint"]:
                continue
            if _iou_xyxy(cur["xyxy"], prop["xyxy"]) >= 0.20:
                ax1, ay1, ax2, ay2 = cur["xyxy"]
                bx1, by1, bx2, by2 = prop["xyxy"]
                cur["xyxy"] = _clip_box(min(ax1, bx1), min(ay1, by1), max(ax2, bx2), max(ay2, by2), img_w, img_h)
                cur["keywords"].append(prop["keyword"])
                cur["ocr_conf"] = max(cur["ocr_conf"], prop["ocr_conf"])
                merged_into_existing = True
                break
        if not merged_into_existing:
            merged.append({
                "class_hint": prop["class_hint"],
                "xyxy": prop["xyxy"],
                "keywords": [prop["keyword"]],
                "ocr_conf": prop["ocr_conf"],
            })

    merged.sort(key=lambda x: (len(x.get("keywords", [])), x.get("ocr_conf", 0)), reverse=True)
    info["matched_terms"] = matched_terms[:30]
    info["proposals"] = merged[:max_proposals]
    info["tokens_used"] = sum(len(x.get("keywords", [])) for x in info["proposals"])
    return info


def run_yolo_with_ocr_light(model_path: str, image_path: str, *, imgsz: int, conf: float, iou: float,
                            ocr_light: bool = True, ocr_max_proposals: int = 8,
                            ocr_crop_margin: float = 0.08, ocr_conf_scale: float = 0.85) -> tuple[list[dict], dict]:
    image_path = Path(image_path)
    base_results = run_yolo(model_path, str(image_path), imgsz=imgsz, conf=conf, iou=iou)
    base_dets = _extract_detections_from_results(base_results)
    ocr_info = {
        "enabled": bool(ocr_light),
        "available": False,
        "tokens_total": 0,
        "tokens_used": 0,
        "matched_terms": [],
        "proposals": [],
        "crop_runs": 0,
        "crop_detections": 0,
        "base_detections": len(base_dets),
        "merged_detections": len(base_dets),
    }
    if not ocr_light:
        return base_dets, ocr_info

    ocr_info = build_ocr_light_proposals(image_path, width=0, height=0, max_proposals=ocr_max_proposals)
    ocr_info["enabled"] = True
    ocr_info["base_detections"] = len(base_dets)
    if not ocr_info.get("available") or not (ocr_info.get("proposals") or []):
        ocr_info["merged_detections"] = len(base_dets)
        return base_dets, ocr_info

    if not PIL_AVAILABLE:
        ocr_info["merged_detections"] = len(base_dets)
        return base_dets, ocr_info

    crop_sets = []
    try:
        img = Image.open(image_path).convert("RGB")
        img_w, img_h = img.size
        for idx, prop in enumerate(ocr_info.get("proposals") or []):
            x1, y1, x2, y2 = prop.get("xyxy") or [0, 0, 1, 1]
            bw, bh = max(1, x2 - x1), max(1, y2 - y1)
            mx = int(max(8, bw * float(ocr_crop_margin)))
            my = int(max(8, bh * float(ocr_crop_margin)))
            crop_box = _clip_box(x1 - mx, y1 - my, x2 + mx, y2 + my, img_w, img_h)
            cx1, cy1, cx2, cy2 = crop_box
            crop = img.crop((cx1, cy1, cx2, cy2))
            crop_path = Path(tempfile.gettempdir()) / f"argus_ocr_light_crop_{idx}_{now_stamp()}.png"
            crop.save(crop_path, format="PNG")
            crop_results = run_yolo(model_path, str(crop_path), imgsz=imgsz, conf=max(0.10, conf * float(ocr_conf_scale)), iou=iou)
            crop_dets = _extract_detections_from_results(crop_results, offset_x=cx1, offset_y=cy1)
            if crop_dets:
                crop_sets.append(crop_dets)
            try:
                crop_path.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        ocr_info["merged_detections"] = len(base_dets)
        return base_dets, ocr_info

    merged = _merge_detection_sets([base_dets] + crop_sets, iou_threshold=max(0.45, min(0.75, iou)))
    ocr_info["crop_runs"] = len(crop_sets)
    ocr_info["crop_detections"] = sum(len(x) for x in crop_sets)
    ocr_info["merged_detections"] = len(merged)
    return merged, ocr_info


def run_yolo(model_path: str, image_path: str, *, imgsz: int, conf: float, iou: float):
    try:
        from ultralytics import YOLO
    except Exception as e:
        raise RuntimeError("Ultralytics non disponibile. Installa: pip install ultralytics") from e

    m = YOLO(model_path)
    # verbose=False per ridurre rumore, ma Ultralytics comunque stampa una riga: ok
    results = m.predict(source=image_path, imgsz=imgsz, conf=conf, iou=iou, verbose=False)
    return results



def extract_hostname(value: str | None) -> str:
    if not value:
        return ""
    try:
        host = (urlparse(value).hostname or "").lower()
        return host
    except Exception:
        return ""

def domain_matches_brand(brand: str | None, url_or_domain: str | None, custom_allowlist: str | None = None) -> bool:
    brand = (brand or "").strip().lower()
    host = extract_hostname(url_or_domain) if "://" in str(url_or_domain or "") else (str(url_or_domain or "").lower())
    if not brand or not host:
        return False

    builtin = {
        "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "office365.com"],
        "google": ["google.com", "googleusercontent.com", "gstatic.com", "withgoogle.com", "youtube.com", "gmail.com"],
        "apple": ["apple.com", "icloud.com", "me.com"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com", "amazon.it", "amazonaws.com"],
        "facebook": ["facebook.com", "fb.com", "meta.com", "messenger.com"],
        "instagram": ["instagram.com", "cdninstagram.com"],
        "linkedin": ["linkedin.com", "licdn.com"],
        "netflix": ["netflix.com"],
        "x": ["x.com", "twitter.com", "t.co"],
        "twitter": ["twitter.com", "x.com", "t.co"],
    }
    allowed = list(builtin.get(brand, []))
    if custom_allowlist:
        for item in str(custom_allowlist).split(","):
            item = item.strip().lower()
            if item:
                allowed.append(item)
    for dom in allowed:
        if host == dom or host.endswith("." + dom):
            return True
    return False

def filter_suspicious_large_boxes(detections: list[dict], width: int, height: int) -> tuple[list[dict], list[dict]]:
    """
    Rimuove alcuni falsi positivi grossolani: box enormi per classi che di solito sono piccole/medie.
    """
    if width <= 0 or height <= 0:
        return detections, []
    kept, removed = [], []
    for d in detections:
        xyxy = d.get("xyxy") or []
        name = d.get("name") or ""
        if len(xyxy) != 4:
            kept.append(d)
            continue
        x1, y1, x2, y2 = map(float, xyxy)
        bw = max(0.0, x2 - x1)
        bh = max(0.0, y2 - y1)
        area_ratio = (bw * bh) / float(max(1, width * height))
        h_ratio = bh / float(max(1, height))
        suspicious = name in {"login_button", "forgot_password_link", "remember_me_checkbox"} and (area_ratio > 0.25 or h_ratio > 0.18)
        if suspicious:
            removed.append({**d, "filtered_reason": "oversized_bbox"})
        else:
            kept.append(d)
    return kept, removed

def best_detection_by_class(detections: list[dict], class_name: str) -> dict | None:
    cands = [d for d in detections if d.get("name") == class_name and (d.get("xyxy") and len(d.get("xyxy")) == 4)]
    if not cands:
        return None
    cands.sort(key=lambda x: float(x.get("conf", 0.0)), reverse=True)
    return cands[0]

def _bbox_center_norm_from_xyxy(xyxy: list[float], width: int, height: int) -> tuple[float, float]:
    x1, y1, x2, y2 = map(float, xyxy)
    return (((x1 + x2) / 2.0) / float(max(1, width)), ((y1 + y2) / 2.0) / float(max(1, height)))

def dom_visual_mapping(meta: dict, detections: list[dict], width: int, height: int, tol: float = 0.12) -> dict:
    """
    Confronta alcune detection YOLO con gli elementi reali del DOM.
    """
    dom = (meta or {}).get("dom_signals") or {}
    result = {
        "available": bool(dom),
        "pairs": [],
        "missing_in_dom": [],
        "score": None,
    }
    if not dom:
        return result

    selector_map = {
        "username_field": (dom.get("email_inputs") or []) + (dom.get("text_inputs") or []),
        "password_field": dom.get("password_inputs") or [],
        "login_button": dom.get("buttons") or [],
    }

    matched = 0
    total = 0
    for cls, dom_boxes in selector_map.items():
        det = best_detection_by_class(detections, cls)
        if not det:
            continue
        total += 1
        if not dom_boxes:
            result["missing_in_dom"].append(cls)
            result["pairs"].append({"class": cls, "matched": False, "reason": "dom_missing"})
            continue
        dcx, dcy = _bbox_center_norm_from_xyxy(det["xyxy"], width, height)
        best_dist = None
        for bb in dom_boxes:
            cx = (float(bb["x"]) + float(bb["w"]) / 2.0) / float(max(1, width))
            cy = (float(bb["y"]) + float(bb["h"]) / 2.0) / float(max(1, height))
            dist = ((dcx - cx) ** 2 + (dcy - cy) ** 2) ** 0.5
            if best_dist is None or dist < best_dist:
                best_dist = dist
        is_match = best_dist is not None and best_dist <= tol
        matched += 1 if is_match else 0
        result["pairs"].append({"class": cls, "matched": bool(is_match), "best_dist": round(float(best_dist or 0.0), 4), "tol": tol})
    if total > 0:
        result["score"] = round(matched / total, 3)
    return result

def get_avg_color_for_detection(image_path: Path, detection: dict | None) -> dict | None:
    if not PIL_AVAILABLE or not detection:
        return None
    try:
        xyxy = detection.get("xyxy") or []
        if len(xyxy) != 4:
            return None
        img = Image.open(image_path).convert("RGB")
        x1, y1, x2, y2 = [int(max(0, round(v))) for v in xyxy]
        x2 = min(img.width, max(x1 + 1, x2))
        y2 = min(img.height, max(y1 + 1, y2))
        crop = img.crop((x1, y1, x2, y2))
        small = crop.resize((1, 1))
        r, g, b = small.getpixel((0, 0))
        return {"rgb": [int(r), int(g), int(b)], "hex": f"#{int(r):02x}{int(g):02x}{int(b):02x}"}
    except Exception:
        return None

def color_distance_rgb(a: dict | None, b: dict | None) -> float | None:
    try:
        if not a or not b:
            return None
        ar, ag, ab = a["rgb"]
        br, bg, bb = b["rgb"]
        return round((((ar-br)**2 + (ag-bg)**2 + (ab-bb)**2) ** 0.5), 2)
    except Exception:
        return None



def detect_cookie_banner_context(dom_intel: dict | None = None, meta: dict | None = None) -> dict:
    dom_intel = dom_intel or {}
    meta = meta or {}
    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    links = [str(s).lower() for s in (dom_intel.get("links") or [])]
    forms = [str(s).lower() for s in (dom_intel.get("form_actions") or [])]
    title = str(meta.get("title") or "").lower()

    strong_needles = [
        "cookie", "consent", "gdpr", "cmp", "gatekeeper",
        "onetrust", "didomi", "iubenda", "quantcast", "trustarc",
        "cookiebot", "consentmanager", "cookieyes"
    ]
    weak_needles = [
        "privacy", "privacystatement"
    ]

    strong_hits = []
    weak_hits = []
    sources = scripts + links + forms + [title]
    for needle in strong_needles:
        if any(needle in s for s in sources):
            strong_hits.append(needle)
    for needle in weak_needles:
        if any(needle in s for s in sources):
            weak_hits.append(needle)

    is_cookie_context = bool(strong_hits)
    hits = sorted(set(strong_hits + (weak_hits if is_cookie_context else [])))

    return {
        "is_cookie_context": is_cookie_context,
        "hits": hits,
        "strong_hits": sorted(set(strong_hits)),
        "weak_hits": sorted(set(weak_hits)),
    }


def suppress_cookie_banner_false_positives(detections: list[dict], dom_intel: dict | None = None, meta: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    cookie_ctx = detect_cookie_banner_context(dom_intel=dom_intel, meta=meta)
    names = [str(d.get("name", "")) for d in detections]
    credential_like = {"username_field", "password_field", "login_button"}
    has_credential_combo = ("login_button" in names) and (("username_field" in names) or ("password_field" in names))
    has_password = "password_field" in names

    if not cookie_ctx.get("is_cookie_context"):
        return detections, [], cookie_ctx

    kept = []
    suppressed = []
    suppressible = {"2fa_field", "security_alert", "captcha", "forgot_password_link"}

    for d in detections:
        name = str(d.get("name", ""))
        if (name in suppressible) and (not has_password) and (not has_credential_combo):
            suppressed.append({**d, "filtered_reason": "cookie_banner_context"})
        else:
            kept.append(d)

    return kept, suppressed, cookie_ctx


def benign_site_adjustment(detections: list[dict], meta: dict, visual_metrics: dict, dom_intel: dict | None = None) -> tuple[int, list[str]]:
    dom_intel = dom_intel or {}
    reasons = []
    adjust = 0
    names = [str(d.get("name", "")) for d in detections]
    host = extract_hostname((meta or {}).get("final_url") or (meta or {}).get("url") or "")

    cookie_ctx = (visual_metrics or {}).get("cookie_banner_context") or detect_cookie_banner_context(dom_intel=dom_intel, meta=meta)
    if cookie_ctx.get("is_cookie_context"):
        adjust -= 12
        reasons.append("cookie/privacy banner context")

    hard_dom_gate = (visual_metrics or {}).get("hard_dom_gate") or {}
    if hard_dom_gate.get("active"):
        adjust -= 10
        reasons.append("DOM has no password field; login-like YOLO detections suppressed")

    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    suspicious_script_needles = ["emailjs", "smtpjs", "telegram", "discord", "webhook", "formsubmit", "getform", "sheetdb"]
    if scripts and not any(any(n in s for n in suspicious_script_needles) for s in scripts):
        adjust -= 4
        reasons.append("scripts look benign/common")

    form_actions = [str(f).lower() for f in (dom_intel.get("form_actions") or [])]
    if host and form_actions:
        if all((extract_hostname(f) == host) or f.startswith("javascript:") or f in {"", "#"} for f in form_actions):
            adjust -= 4
            reasons.append("form actions stay on same host")

    clip = (visual_metrics or {}).get("clip_brand") or {}
    top_score = float(clip.get("top_score") or 0.0)
    mismatch = (visual_metrics or {}).get("brand_domain_mismatch")
    if (mismatch is False) or (not mismatch and top_score < 0.85):
        adjust -= 3
        reasons.append("no strong brand-domain mismatch")

    high_risk_combo = ("password_field" in names) or (("login_button" in names) and (("username_field" in names) or ("password_field" in names)))
    if not high_risk_combo and any(n in names for n in ["2fa_field", "security_alert", "captcha"]):
        adjust -= 6
        reasons.append("isolated UI signals without credential flow")

    return adjust, reasons


def contextual_risk(detections: list[dict], meta: dict, visual_metrics: dict, dom_intel: dict | None = None, custom_allowlist: str | None = None) -> tuple[int, list[str]]:
    names = [d.get("name") for d in detections]
    final_url = (meta or {}).get("final_url") or (meta or {}).get("url") or ""
    clip = (visual_metrics or {}).get("clip_brand") or {}
    top_brand = clip.get("top_brand")
    top_score = float(clip.get("top_score") or 0.0)
    dom_intel = dom_intel or {}
    reasons = []
    bonus = 0

    builtin_brand_domains = {
        "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "office365.com"],
        "google": ["google.com", "googleusercontent.com", "gstatic.com", "withgoogle.com", "youtube.com", "gmail.com"],
        "apple": ["apple.com", "icloud.com", "me.com"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com", "amazon.it", "amazonaws.com"],
        "facebook": ["facebook.com", "fb.com", "meta.com", "messenger.com"],
        "instagram": ["instagram.com", "cdninstagram.com"],
        "linkedin": ["linkedin.com", "licdn.com"],
        "netflix": ["netflix.com"],
        "autoscout24": ["autoscout24.com", "autoscout24.de", "autoscout24.it", "autoscout24.es", "autoscout24.fr", "autoscout24.nl", "autoscout24.be", "autoscout24.lu"],
        "x": ["x.com", "twitter.com", "t.co"],
        "twitter": ["twitter.com", "x.com", "t.co"],
    }

    def _host_matches_allowed_domains(host: str, domains: list[str]) -> bool:
        for dom in domains:
            if host == dom or host.endswith('.' + dom):
                return True
        return False

    final_host = extract_hostname(final_url)
    suspicious_hosts = ["github.io", "pages.dev", "netlify.app", "vercel.app"]
    is_free_hosting = any(final_host == h or final_host.endswith('.' + h) for h in suspicious_hosts)

    mismatch = False
    if top_brand and top_score >= 0.85:
        mismatch = not domain_matches_brand(top_brand, final_url, custom_allowlist=custom_allowlist)
        visual_metrics["brand_domain_mismatch"] = mismatch
        if mismatch:
            if top_score >= 0.95:
                bonus += 50
                reasons.append(f"brand-domain mismatch ({top_brand}, CLIP {top_score:.2f})")
            else:
                bonus += 35
                reasons.append(f"strong brand-domain mismatch ({top_brand}, CLIP {top_score:.2f})")

    # Keyword brand impersonation even when CLIP is weak/absent.
    host_brand_hits = []
    for brand_name, allowed_domains in builtin_brand_domains.items():
        if brand_name in {"x", "twitter"}:
            continue
        if brand_name in final_host and not _host_matches_allowed_domains(final_host, allowed_domains):
            host_brand_hits.append(brand_name)
    if host_brand_hits:
        strong_host_brand = sorted(set(host_brand_hits))[0]
        visual_metrics["hostname_brand_hit"] = strong_host_brand
        if is_free_hosting:
            bonus += 35
            reasons.append(f"brand keyword on free-hosting domain ({strong_host_brand})")
        else:
            bonus += 22
            reasons.append(f"brand keyword in non-official domain ({strong_host_brand})")

    if ("password_field" in names) and ("login_button" in names) and mismatch:
        reasons.append("password field + login button + brand mismatch")
        return 100, reasons

    if (("username_field" in names) or ("password_field" in names)) and ("login_button" in names) and mismatch and top_score >= 0.90:
        bonus += 25
        reasons.append("credential UI + high-confidence brand mismatch")

    mapping = (visual_metrics or {}).get("dom_visual_mapping") or {}
    if mapping.get("available") and mapping.get("missing_in_dom"):
        miss = mapping.get("missing_in_dom") or []
        if "password_field" in miss:
            bonus += 20
            reasons.append("YOLO sees password field but DOM does not")
        elif miss:
            bonus += 10
            reasons.append("YOLO/DOM mismatch on key fields")

    if (visual_metrics or {}).get("button_color_compare"):
        cdist = (visual_metrics["button_color_compare"] or {}).get("distance")
        if cdist is not None and cdist >= 40:
            bonus += 8
            reasons.append(f"login button color drift ({cdist})")

    if (visual_metrics or {}).get("layout_compare"):
        same_sig = (visual_metrics["layout_compare"] or {}).get("same_signature")
        if same_sig:
            reasons.append("same layout signature as reference")
        elif (visual_metrics["layout_compare"] or {}).get("common_classes", 0) >= 2:
            bonus += 6
            reasons.append("layout partially aligned with reference")

    if (visual_metrics or {}).get("filtered_out"):
        removed_n = len((visual_metrics or {}).get("filtered_out") or [])
        if removed_n:
            reasons.append(f"filtered {removed_n} oversized detections")

    scripts = [str(s).lower() for s in (dom_intel.get("scripts") or [])]
    exfil_hits = []
    exfil_map = {
        "emailjs": 35,
        "smtpjs": 35,
        "telegram": 40,
        "discord": 35,
        "webhook": 35,
        "formsubmit": 30,
        "getform": 30,
        "sheetdb": 30,
    }
    exfil_bonus = 0
    for needle, pts in exfil_map.items():
        if any(needle in s for s in scripts):
            exfil_hits.append(needle)
            exfil_bonus = max(exfil_bonus, pts)
    if exfil_hits:
        bonus += exfil_bonus
        reasons.append(f"possible exfiltration script: {', '.join(sorted(set(exfil_hits)))}")

    if top_brand and is_free_hosting:
        bonus += 25
        reasons.append("free-hosting brand impersonation")

    if str(final_url).lower().startswith("http://") and (("login_button" in names) or ("password_field" in names) or ("username_field" in names)):
        bonus += 20
        reasons.append("insecure HTTP credential page")

    # Suspicious redirect target paths and multi-hop chains matter even without visible login UI.
    suspicious_path_needles = [
        "coffee", "verify", "verification", "check", "auth", "secure", "update",
        "payment", "confirm", "wallet", "gift", "bonus", "claim", "signin", "login"
    ]
    all_urls = [str(final_url)] + [str(x) for x in ((meta or {}).get("redirect_chain") or [])]
    lowered_urls = [u.lower() for u in all_urls if u]
    if any(any(needle in u for needle in suspicious_path_needles) for u in lowered_urls):
        bonus += 20
        reasons.append("suspicious redirect target path")
    if len([u for u in lowered_urls if u]) >= 2:
        bonus += 10
        reasons.append("redirect chain observed")

    # External favicon hosting is suspicious for brand-abuse pages and lightweight kits.
    fav = (visual_metrics or {}).get("favicon_intelligence") or {}
    fav_url = str(fav.get("favicon_url") or "")
    fav_host = extract_hostname(fav_url)
    if fav_host and final_host and fav_host != final_host and not fav_host.endswith('.' + final_host) and not final_host.endswith('.' + fav_host):
        bonus += 12
        if any(x in fav_host for x in ["postimg", "imgur", "ibb.co", "pinimg", "discordapp", "discordcdn"]):
            reasons.append(f"external favicon hosting ({fav_host})")
        else:
            reasons.append("favicon hosted on third-party domain")

    cookie_ctx = (visual_metrics or {}).get("cookie_banner_context") or {}
    if cookie_ctx.get("is_cookie_context"):
        reasons.append(f"cookie context detected ({', '.join((cookie_ctx.get('hits') or [])[:4])})")

    tg = (dom_intel.get("telegram_indicators") or {}) if dom_intel else {}
    tg_text = tg.get("telegram_text_hits") or []
    tg_targets = collect_telegram_targets(dom_intel=dom_intel, meta=meta)
    visual_metrics["telegram_target_urls"] = tg_targets.get("all") or []
    visual_metrics["telegram_targets_by_source"] = tg_targets
    blank_landing = looks_like_blank_redirect_landing(meta=meta, dom_intel=dom_intel, detections=detections, visual_metrics=visual_metrics)

    if tg_targets.get("from_redirect_chain") or tg_targets.get("from_popups"):
        bonus += 70
        reasons.append("resolved Telegram redirect/popup target")
    elif tg_targets.get("from_meta_refresh"):
        bonus += 75 if blank_landing else 65
        reasons.append("meta refresh toward Telegram")
        if blank_landing:
            reasons.append("blank intermediary landing before Telegram")
    elif tg_targets.get("from_links"):
        bonus += 45
        reasons.append("Telegram link present in DOM")
    elif tg_targets.get("from_inline_js") or tg_targets.get("from_onclick"):
        bonus += 55
        reasons.append("inline JS / onclick suggests Telegram redirection")
    elif tg_text or tg_targets.get("from_text"):
        bonus += 20
        reasons.append("Telegram reference found in page text")

    return min(100, max(0, bonus)), reasons

def compute_risk(detections: list[dict], interstitial: bool) -> int:
    # Heuristic semplice: più elementi "cred" + logo => rischio alto
    score = 0
    names = [d["name"] for d in detections]
    # pesi
    weights = {
        "password_field": 25,
        "username_field": 20,
        "login_button": 15,
        "2fa_field": 15,
        "captcha": 10,
        "forgot_password_link": 10,
        "security_alert": 10,
        "fake_certificate": 10,
        "suspicious_banner": 12,
        "remember_me_checkbox": 5,
        "logo_microsoft": 10,
        "logo_google": 10,
        "logo_facebook": 10,
        "logo_paypal": 12,
        "logo_amazon": 10,
        "logo_apple": 10,
        "logo_netflix": 10,
        "logo_instagram": 10,
        "logo_twitter": 10,
        "logo_linkedin": 10,
    }
    for n in set(names):
        score += weights.get(n, 0)

    # bonus se combo classica cred-harvest
    if ("password_field" in names) and ("login_button" in names):
        score += 10
    if ("username_field" in names) and ("password_field" in names):
        score += 10

    # se interstitial Cloudflare suspected phishing => non è "login", ma è un segnale forte di abuso
    if interstitial:
        score += 20

    return max(0, min(100, score))


def fetch_url_bytes(url: str, timeout: float = 8.0) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None

def resolve_favicon_url(final_url: str, dom_intel: dict | None = None) -> str | None:
    dom_intel = dom_intel or {}
    candidates = [str(x) for x in (dom_intel.get("favicon_links") or []) if str(x).strip()]
    if candidates:
        return candidates[0]
    host = extract_hostname(final_url)
    scheme = urlparse(final_url).scheme or "https"
    if not host:
        return None
    return f"{scheme}://{host}/favicon.ico"

def compute_favicon_intelligence(final_url: str, dom_intel: dict | None = None) -> dict:
    out = {
        "favicon_url": None,
        "fetched": False,
        "sha256": None,
        "md5": None,
        "mmh3": None,
        "bytes": 0,
        "search_query": None,
    }
    fav_url = resolve_favicon_url(final_url, dom_intel=dom_intel)
    out["favicon_url"] = fav_url
    if not fav_url:
        return out
    raw = fetch_url_bytes(fav_url)
    if not raw:
        return out
    out["fetched"] = True
    out["bytes"] = len(raw)
    out["sha256"] = hashlib.sha256(raw).hexdigest()
    out["md5"] = hashlib.md5(raw).hexdigest()
    if MMH3_AVAILABLE:
        try:
            b64 = base64.b64encode(raw)
            out["mmh3"] = int(mmh3.hash(b64))
            out["search_query"] = f"http.favicon.hash:{out['mmh3']}"
        except Exception:
            out["mmh3"] = None
    return out

def _load_report_jsons(out_dir: Path) -> list[dict]:
    rows = []
    for fp in sorted(out_dir.glob("phishradar_*.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            data["_report_file"] = str(fp)
            rows.append(data)
        except Exception:
            continue
    return rows

def find_local_correlations(out_dir: Path, current_url: str, visual_metrics: dict, dom_intel: dict | None = None, limit: int = 10) -> dict:
    dom_intel = dom_intel or {}
    current_layout = ((visual_metrics or {}).get("layout_fingerprint") or {}).get("signature")
    current_favicon = ((visual_metrics or {}).get("favicon_intelligence") or {}).get("mmh3")
    current_brand = (((visual_metrics or {}).get("clip_brand") or {}).get("top_brand") or "")
    current_scripts = {str(s).lower() for s in (dom_intel.get("scripts") or [])}
    current_host = extract_hostname(current_url)
    related = []

    for row in _load_report_jsons(out_dir):
        row_url = row.get("final_url") or row.get("url") or ""
        if row_url == current_url:
            continue
        row_vm = row.get("visual_metrics") or {}
        score = 0
        reasons = []

        row_layout = ((row_vm.get("layout_fingerprint") or {}).get("signature"))
        if current_layout and row_layout and current_layout == row_layout:
            score += 60
            reasons.append("same layout signature")

        row_favicon = ((row_vm.get("favicon_intelligence") or {}).get("mmh3"))
        if current_favicon is not None and row_favicon is not None and current_favicon == row_favicon:
            score += 35
            reasons.append("same favicon mmh3")

        row_brand = (((row_vm.get("clip_brand") or {}).get("top_brand")) or "")
        if current_brand and row_brand and current_brand.lower() == row_brand.lower():
            score += 10
            reasons.append("same CLIP brand")

        row_dom = row.get("dom_intelligence") or {}
        row_scripts = {str(s).lower() for s in (row_dom.get("scripts") or [])}
        shared_scripts = sorted(x for x in (current_scripts & row_scripts) if any(k in x for k in ["emailjs","smtpjs","telegram","discord","webhook","formsubmit","getform","sheetdb"]))
        if shared_scripts:
            score += 20
            reasons.append("shared suspicious scripts")

        if current_host and extract_hostname(row_url) == current_host:
            score += 5
            reasons.append("same host")

        if score > 0:
            related.append({
                "url": row_url,
                "report_file": row.get("_report_file"),
                "score": score,
                "reasons": reasons,
                "risk": row.get("risk"),
                "layout_signature": row_layout,
                "favicon_mmh3": row_favicon,
                "brand": row_brand,
                "shared_scripts": shared_scripts,
            })

    related.sort(key=lambda x: (-x["score"], x["url"]))
    return {"count": len(related), "top_matches": related[:limit]}

def build_hunting_queries(visual_metrics: dict, final_url: str) -> dict:
    fav = (visual_metrics or {}).get("favicon_intelligence") or {}
    fp = (visual_metrics or {}).get("layout_fingerprint") or {}
    clip = (visual_metrics or {}).get("clip_brand") or {}
    queries = {
        "favicon_shodan": None,
        "layout_signature": fp.get("signature"),
        "brand_host_note": None,
    }
    if fav.get("mmh3") is not None:
        queries["favicon_shodan"] = f"http.favicon.hash:{fav.get('mmh3')}"
    tb = clip.get("top_brand")
    if tb:
        queries["brand_host_note"] = f"Investigate {tb} impersonation on host {extract_hostname(final_url)}"
    return queries


def classify_correlation_strength(item: dict) -> dict:
    """
    Distinguish strong campaign correlation from weak asset similarity.
    Strong correlation requires structural or suspicious-signal overlap.
    """
    reasons = item.get("reasons") or []
    score = int(item.get("score") or 0)

    strong_signals = {"same layout signature", "same suspicious scripts", "same host"}
    moderate_signals = {"same favicon mmh3", "same CLIP brand", "same favicon sha256", "same layout family"}

    reason_set = set(reasons)
    has_strong = any(r in reason_set for r in strong_signals)
    moderate_count = sum(1 for r in reasons if r in moderate_signals)

    if has_strong:
        return {"classification": "strong_campaign_correlation", "label": "Strong campaign correlation"}

    if ("same favicon mmh3" in reason_set and "same CLIP brand" in reason_set) and score >= 40:
        return {"classification": "weak_asset_similarity", "label": "Weak asset similarity"}

    if moderate_count >= 2 and score >= 35:
        return {"classification": "weak_asset_similarity", "label": "Weak asset similarity"}

    return {"classification": "weak_asset_similarity", "label": "Weak asset similarity"}


def split_correlation_results(items: list[dict]) -> dict:
    strong = []
    weak = []
    for item in items or []:
        cls = classify_correlation_strength(item)
        merged = {**item, **cls}
        if cls["classification"] == "strong_campaign_correlation":
            strong.append(merged)
        else:
            weak.append(merged)
    return {"strong": strong, "weak": weak}

PHISHING_VARIANT_TLDS = ["com", "net", "org", "info", "site", "online", "click", "top", "support", "security", "help", "live"]
PHISHING_TOKENS = ["login", "signin", "sign-in", "secure", "security", "verify", "verification", "account", "auth", "support", "update", "alert", "portal", "check", "service", "help"]


def split_host_labels(host: str) -> list[str]:
    host = str(host or "").strip().lower().strip('.')
    return [x for x in host.split('.') if x]


def split_core_tld(host: str) -> tuple[str, str]:
    labels = split_host_labels(host)
    if not labels:
        return "", ""
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "gov", "ac", "edu", "net"} and len(labels[-1]) == 2:
        return ".".join(labels[:-2]), ".".join(labels[-2:])
    if len(labels) >= 2:
        return ".".join(labels[:-1]), labels[-1]
    return labels[0], ""


def tokenize_host_core(core: str) -> list[str]:
    s = str(core or "").lower()
    s = re.sub(r'[^a-z0-9]+', '-', s)
    toks = [t for t in s.split('-') if t]
    return toks


def levenshtein_distance_limited(a: str, b: str, max_distance: int = 3) -> int:
    a = str(a or "")
    b = str(b or "")
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        min_row = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
            if cur[-1] < min_row:
                min_row = cur[-1]
        if min_row > max_distance:
            return max_distance + 1
        prev = cur
    return prev[-1]


def looks_like_brand_typo(token: str, brand: str) -> bool:
    token = str(token or "").lower()
    brand = str(brand or "").lower()
    if not token or not brand or token == brand:
        return False
    if token.replace('0', 'o').replace('1', 'l') == brand:
        return True
    dist = levenshtein_distance_limited(token, brand, max_distance=2)
    if dist <= 2:
        return True
    return SequenceMatcher(None, token, brand).ratio() >= 0.78


def guess_brand_from_context(seed_url: str, visual_metrics: dict | None = None, dom_intel: dict | None = None) -> str | None:
    visual_metrics = visual_metrics or {}
    dom_intel = dom_intel or {}
    host = extract_hostname(seed_url)
    core, _ = split_core_tld(host)
    tokens = tokenize_host_core(core)
    known = ["microsoft", "google", "apple", "facebook", "instagram", "paypal", "amazon", "netflix", "linkedin", "twitter", "x"]
    for b in known:
        if b in tokens or any(looks_like_brand_typo(t, b) for t in tokens):
            return b
    clip_brand = (((visual_metrics or {}).get("clip_brand") or {}).get("top_brand") or "").strip().lower()
    if clip_brand:
        if clip_brand == 'twitter':
            return 'twitter'
        return clip_brand
    page_text = str((dom_intel or {}).get("page_text_sample") or "").lower()
    for b in known:
        if b in page_text:
            return b
    return None


def score_variant_host(candidate_host: str, seed_host: str, brand: str | None = None) -> dict:
    seed_core, _ = split_core_tld(seed_host)
    cand_core, cand_tld = split_core_tld(candidate_host)
    seed_tokens = tokenize_host_core(seed_core)
    cand_tokens = tokenize_host_core(cand_core)
    reasons = []
    score = 0
    brand = (brand or "").lower().strip()

    if brand and brand in cand_tokens:
        score += 26
        reasons.append("brand exact")
    elif brand and any(looks_like_brand_typo(t, brand) for t in cand_tokens):
        score += 18
        reasons.append("brand typo")

    shared = [t for t in cand_tokens if t in seed_tokens and t not in {brand}]
    if shared:
        score += min(18, 6 * len(shared))
        reasons.append("token overlap")

    phish_hits = [t for t in cand_tokens if t in PHISHING_TOKENS]
    if phish_hits:
        score += min(18, 4 * len(set(phish_hits)))
        reasons.append("phishing tokens")

    if cand_tld in {"site", "online", "click", "top", "live", "support", "security", "help"}:
        score += 8
        reasons.append("suspicious tld")

    if '-' in cand_core and '-' in seed_core:
        score += 4
        reasons.append("same separator style")

    if brand and candidate_host.startswith(f"login.{brand}"):
        score += 8
        reasons.append("brand subdomain style")

    return {"score": int(min(100, score)), "reasons": reasons, "tokens": cand_tokens, "tld": cand_tld}


def generate_variant_candidates(seed_url: str, brand: str | None = None, max_candidates: int = 20) -> dict:
    host = extract_hostname(seed_url)
    seed_core, seed_tld = split_core_tld(host)
    seed_tokens = tokenize_host_core(seed_core)
    brand = (brand or "").lower().strip()

    if not seed_tokens:
        return {"seed_host": host, "brand": brand, "generated": []}

    brand_forms = []
    if brand:
        brand_forms.extend([brand])
        replacements = {
            'microsoft': ['micr0soft', 'rnicrosoft'],
            'google': ['g00gle'],
            'paypal': ['paypa1'],
            'facebook': ['faceb00k'],
            'instagram': ['instagrarn'],
            'linkedin': ['linkedln'],
            'amazon': ['arnazon'],
            'netflix': ['netf1ix'],
            'apple': ['app1e'],
            'twitter': ['twltter'],
        }
        brand_forms.extend(replacements.get(brand, []))

    token_pool = []
    for t in seed_tokens:
        token_pool.append(t)
    for t in PHISHING_TOKENS:
        if t not in token_pool:
            token_pool.append(t)

    generated = []
    seen = set([host])

    def add_candidate(hostname: str, source: str):
        hn = str(hostname or "").lower().strip().strip('.')
        if not hn or hn in seen:
            return
        seen.add(hn)
        generated.append({"host": hn, "source": source, **score_variant_host(hn, host, brand=brand)})

    # same pattern, token substitutions
    if brand:
        base_non_brand = [t for t in seed_tokens if t != brand and not looks_like_brand_typo(t, brand)]
        if not base_non_brand:
            base_non_brand = [t for t in seed_tokens if t != brand] or ['secure']
        for bf in brand_forms[:3]:
            for extra in [x for x in ["login", "verify", "secure", "account", "support", "alert"] if x not in base_non_brand][:4]:
                toks = [bf] + base_non_brand[:2] + [extra]
                add_candidate("-".join(dict.fromkeys(toks)) + "." + (seed_tld or "com"), "brand_token_mix")
                add_candidate("-".join(dict.fromkeys([extra, bf] + base_non_brand[:2])) + "." + (seed_tld or "com"), "brand_token_reorder")
            add_candidate(f"login.{bf}-{'-'.join(base_non_brand[:2] or ['secure'])}.{seed_tld or 'com'}", "brand_subdomain_style")

    # TLD swaps
    base_join = "-".join(seed_tokens[:4])
    for tld in PHISHING_VARIANT_TLDS[:8]:
        if tld != seed_tld:
            add_candidate(base_join + "." + tld, "tld_swap")

    # suspicious token append/prepend
    for extra in ["login", "verify", "secure", "account", "support", "check"]:
        add_candidate("-".join(dict.fromkeys(seed_tokens[:4] + [extra])) + "." + (seed_tld or "com"), "append_token")
        add_candidate("-".join(dict.fromkeys([extra] + seed_tokens[:4])) + "." + (seed_tld or "com"), "prepend_token")

    generated.sort(key=lambda x: (int(x.get("score") or 0), x.get("host") or ""), reverse=True)
    return {"seed_host": host, "brand": brand, "generated": generated[:max_candidates]}


def probe_candidate_host(candidate_host: str, *, timeout: float = 3.0, user_agent: str | None = None) -> dict:
    out = {
        "host": candidate_host,
        "resolved": False,
        "ips": [],
        "https": None,
        "http": None,
        "best": None,
    }
    try:
        infos = socket.getaddrinfo(candidate_host, None)
        ips = []
        for item in infos:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
        out["resolved"] = bool(ips)
        out["ips"] = ips[:6]
    except Exception as e:
        out["dns_error"] = type(e).__name__
        return out

    headers = {"User-Agent": user_agent or "ARGUS-PhishRadar/1.0"}
    opener = urllib.request.build_opener()
    opener.addheaders = list(headers.items())
    ssl_ctx = ssl._create_unverified_context()

    def _probe_one(url: str) -> dict:
        res = {"url": url, "ok": False, "status": None, "final_url": None, "title": None, "content_type": None, "error": None}
        try:
            req = urllib.request.Request(url, method="HEAD")
            with opener.open(req, timeout=timeout, context=ssl_ctx) as r:
                res["status"] = getattr(r, 'status', None) or r.getcode()
                res["final_url"] = getattr(r, 'url', url)
                res["content_type"] = r.headers.get('Content-Type')
                res["ok"] = True
        except Exception:
            try:
                req = urllib.request.Request(url, method="GET")
                with opener.open(req, timeout=timeout, context=ssl_ctx) as r:
                    res["status"] = getattr(r, 'status', None) or r.getcode()
                    res["final_url"] = getattr(r, 'url', url)
                    res["content_type"] = r.headers.get('Content-Type')
                    body = r.read(4096)
                    try:
                        txt = body.decode('utf-8', errors='ignore')
                    except Exception:
                        txt = ''
                    m = re.search(r'<title[^>]*>(.*?)</title>', txt, flags=re.I | re.S)
                    if m:
                        res["title"] = re.sub(r'\s+', ' ', m.group(1)).strip()[:160]
                    res["ok"] = True
            except Exception as e2:
                res["error"] = type(e2).__name__
        return res

    out["https"] = _probe_one(f"https://{candidate_host}/")
    out["http"] = _probe_one(f"http://{candidate_host}/")
    choices = [x for x in [out.get("https"), out.get("http")] if x]
    choices.sort(key=lambda x: ((1 if x.get("ok") else 0), int(x.get("status") or 0)), reverse=True)
    out["best"] = choices[0] if choices else None
    return out


def expand_and_probe_campaign_variants(seed_url: str, visual_metrics: dict | None = None, dom_intel: dict | None = None, *, max_generate: int = 18, max_probe: int = 10, timeout: float = 3.0, user_agent: str | None = None) -> dict:
    visual_metrics = visual_metrics or {}
    dom_intel = dom_intel or {}
    brand = guess_brand_from_context(seed_url, visual_metrics=visual_metrics, dom_intel=dom_intel)
    generated = generate_variant_candidates(seed_url, brand=brand, max_candidates=max_generate)
    results = []
    for item in (generated.get("generated") or [])[:max_probe]:
        probe = probe_candidate_host(item.get("host") or "", timeout=timeout, user_agent=user_agent)
        best = probe.get("best") or {}
        status = int(best.get("status") or 0) if str(best.get("status") or '').isdigit() else best.get("status")
        live = bool(best.get("ok")) and (status in {200, 301, 302, 303, 307, 308})
        title = str(best.get("title") or "")
        result = {
            **item,
            "resolved": probe.get("resolved"),
            "ips": probe.get("ips") or [],
            "live": live,
            "status": status,
            "final_url": best.get("final_url"),
            "title": title,
            "probe": probe,
        }
        if live:
            if status == 200:
                result["classification"] = "live_200"
            elif status in {301, 302, 303, 307, 308}:
                result["classification"] = "redirector"
            else:
                result["classification"] = "live"
        elif probe.get("resolved"):
            result["classification"] = "resolved_not_live"
        else:
            result["classification"] = "dead"
        results.append(result)

    live_results = [r for r in results if r.get("live")]
    return {
        "enabled": True,
        "seed_url": seed_url,
        "seed_host": extract_hostname(seed_url),
        "brand": brand,
        "generated_count": len(generated.get("generated") or []),
        "probed_count": len(results),
        "live_count": len(live_results),
        "top_candidates": sorted(results, key=lambda x: (1 if x.get("live") else 0, int(x.get("score") or 0), int(x.get("status") or 0) if isinstance(x.get("status"), int) else 0), reverse=True),
    }


def save_outputs(out_dir: Path, url: str, meta: dict, detections: list[dict], risk: int, screenshot_path: Path, annotated_path: Path | None, visual_metrics: dict, dom_intel: dict, step2_info: dict, filtered_out_detections: list[dict], *, open_after: bool, save_layout_json: bool = False):
    safe_mkdir(out_dir)
    stamp = now_stamp()
    # JSON report
    import json
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_url": meta.get("final_url"),
        "title": meta.get("title"),
        "status_hint": meta.get("status_hint"),
        "interstitial_hint": meta.get("interstitial_hint"),
        "redirect_chain": meta.get("redirect_chain") or [],
        "popup_urls": meta.get("popup_urls") or [],
        "screenshot": str(screenshot_path),
        "annotated_screenshot": str(annotated_path) if annotated_path else None,
        "detections": detections,
        "visual_metrics": visual_metrics,
        "risk": risk,
        "dom_intelligence": dom_intel,
        "step2": step2_info,
        "filtered_detections": filtered_out_detections,
        "infrastructure_intelligence": (visual_metrics or {}).get("favicon_intelligence"),
        "campaign_correlation": (visual_metrics or {}).get("local_correlation"),
        "hunting_queries": (visual_metrics or {}).get("hunting_queries"),
        "telegram_target_urls": (visual_metrics or {}).get("telegram_target_urls"),
        "telegram_targets_by_source": (visual_metrics or {}).get("telegram_targets_by_source"),
        "campaign_expansion": (visual_metrics or {}).get("campaign_expansion"),
    }
    json_path = out_dir / f"phishradar_{stamp}.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Copia screenshot dentro out_dir con nome stabile (così l'HTML la trova sempre)
    out_png = out_dir / f"phishradar_{stamp}.png"
    try:
        out_png.write_bytes(Path(screenshot_path).read_bytes())
    except Exception:
        pass

    annotated_png = None
    if annotated_path is not None:
        annotated_png = out_dir / f"phishradar_{stamp}_annotated.png"
        try:
            annotated_png.write_bytes(Path(annotated_path).read_bytes())
        except Exception:
            pass

    # HTML mini-dashboard
    rows = "\n".join(
        f"<tr><td>{d['name']}</td><td>{d['conf']:.3f}</td><td>{d['xyxy']}</td></tr>"
        for d in detections
    ) or "<tr><td colspan='3'>(no detections)</td></tr>"


    # palette swatches HTML
    palette = (report.get("visual_metrics", {}) or {}).get("palette_hex", []) or []
    palette_swatches = "".join([f"<span style='width:22px;height:22px;border-radius:6px;border:1px solid #233044;background:{c};display:inline-block' title='{c}'></span>" for c in palette])

    ref_block = ""
    vm = report.get("visual_metrics", {}) or {}
    if vm.get("ref"):
        ref_palette = vm["ref"].get("palette_hex", []) or []
        ref_swatches = "".join([f"<span style='width:22px;height:22px;border-radius:6px;border:1px solid #233044;background:{c};display:inline-block' title='{c}'></span>" for c in ref_palette])
        hs = vm.get("hash_similarity")
        pc = vm.get("position_compare", {})
        lc = vm.get("layout_compare", {}) or {}
        ref_block = f"""
  <div class='small' style='margin-top:14px'><b>Reference compare</b></div>
  <div class='small'>Hash similarity: {hs if hs is not None else ''}</div>
  <div class='small'>YOLO position mismatch: {pc.get('mismatched',0)}/{pc.get('common',0)} (rate {pc.get('mismatch_rate',0)}) tol={pc.get('tol','')}</div>
  <div class='small'>Layout common classes: {lc.get('common_classes', 0)}</div>
  <div class='small'>Layout avg position shift: {lc.get('position_shift_avg', '')}</div>
  <div class='small'>Layout avg size shift: {lc.get('size_shift_avg', '')}</div>
  <div class='small'>Same layout signature: {lc.get('same_signature', False)}</div>
  <div class='small'>Button color distance: {((vm.get("button_color_compare") or {}).get("distance") if vm.get("button_color_compare") else "")}</div>
  <div class='small' style='margin-top:8px'>Palette (ref): {", ".join(ref_palette)}</div>
  <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">{ref_swatches}</div>
"""

    domi = report.get("dom_intelligence", {}) or {}
    _forms = domi.get("form_actions", []) or []
    _links = domi.get("links", []) or []
    _scripts = domi.get("scripts", []) or []
    _tg_targets = report.get("telegram_target_urls") or []
    _tg_by_source = report.get("telegram_targets_by_source") or {}
    dom_form_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_forms[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    dom_link_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_links[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    dom_script_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_scripts[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    tg_target_rows = "\n".join([f"<tr><td>{i+1}</td><td>{v}</td></tr>" for i, v in enumerate(_tg_targets[:25])]) or "<tr><td colspan='2'>(none)</td></tr>"
    tg_source_rows = "\n".join(
        f"<tr><td>{k}</td><td>{', '.join(v[:10]) if isinstance(v, list) else v}</td></tr>"
        for k, v in _tg_by_source.items() if k != 'all' and v
    ) or "<tr><td colspan='2'>(none)</td></tr>"

    annotated_block = ""
    if annotated_png is not None:
        try:
            annotated_block = f"""\n  <div class=\"small\" style=\"margin:14px 0 8px\">Annotato (bbox + cerchi + label)</div>\n  <img src=\"{annotated_png.name}\" alt=\"screenshot annotato\"/>\n"""
        except Exception:
            annotated_block = ""

    infra = report.get("infrastructure_intelligence") or {}
    corr = report.get("campaign_correlation") or {}
    hunting = report.get("hunting_queries") or {}
    expansion = report.get("campaign_expansion") or {}
    corr_rows = "\n".join(
        f"<tr><td><div>{html.escape(str(m.get('url','')))}</div><div class='small'>{html.escape(', '.join(m.get('reasons',[]) or []))}</div></td><td>{m.get('score','')}</td><td>{m.get('risk','')}</td></tr>"
        for m in (corr.get("top_matches") or [])[:10]
    ) or "<tr><td colspan='3'>(none)</td></tr>"
    expansion_rows = "\n".join(
        f"<tr><td><div>{html.escape(str(m.get('host','')))}</div><div class='small'>{html.escape(', '.join(m.get('reasons',[]) or []))}</div></td><td>{m.get('score','')}</td><td>{m.get('status','')}</td><td>{html.escape(str(m.get('classification','')))}</td></tr>"
        for m in (expansion.get("top_candidates") or [])[:12]
    ) or "<tr><td colspan='4'>(none)</td></tr>"
    infra_block = f"""
<div class="card">
  <h1>Infrastructure Signals</h1>
  <div class="small">Favicon URL: {infra.get("favicon_url") or ""}</div>
  <div class="small" style="margin-top:8px">Favicon SHA256: {infra.get("sha256") or ""}</div>
  <div class="small" style="margin-top:8px">Favicon mmh3: {infra.get("mmh3") if infra.get("mmh3") is not None else ""}</div>
  <div class="small" style="margin-top:8px">Hunting query: {hunting.get("favicon_shodan") or ""}</div>
</div>
<div class="card">
  <h1>Correlation Analysis</h1>
  <div class="small">Strong campaign correlation: {corr.get("count", 0)}</div>
  <table>
    <thead><tr><th>Related URL</th><th>Score</th><th>Risk</th></tr></thead>
    <tbody>{corr_rows}</tbody>
  </table>
</div>
<div class="card">
  <h1>Campaign Expansion</h1>
  <div class="small">Brand guessed: {expansion.get("brand") or ""}</div>
  <div class="small" style="margin-top:8px">Generated: {expansion.get("generated_count", 0)} · Probed: {expansion.get("probed_count", 0)} · Live: {expansion.get("live_count", 0)}</div>
  <table>
    <thead><tr><th>Candidate</th><th>Score</th><th>Status</th><th>Class</th></tr></thead>
    <tbody>{expansion_rows}</tbody>
  </table>
</div>
"""
    html_doc = f"""<!doctype html>
<html lang="it"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ARGUS PhishRadar</title>
<style>
body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;margin:24px;background:#0b0f14;color:#e6eef7}}
.card{{background:#121826;border:1px solid #233044;border-radius:14px;padding:16px;box-shadow:0 8px 30px rgba(0,0,0,.35);margin-bottom:16px}}
h1{{margin:0 0 8px 0;font-size:22px}}
.small{{opacity:.85;font-size:13px}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;background:#1a2636;border:1px solid #2a3b52;margin-right:8px}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #233044;font-size:13px}}
.risk{{font-size:28px;font-weight:700}}
img{{max-width:100%;border-radius:12px;border:1px solid #233044}}
</style></head>
<body>
<div class="card">
  <h1>ARGUS PhishRadar — Visual Phishing Detection Engine</h1>
  <div class="small">By Neurone4444 · Generated: {report['generated']}</div>
</div>

<div class="card">
  <div class="badge">URL</div> <span class="small">{url}</span><br/>
  <div class="badge">Final</div> <span class="small">{report.get('final_url') or ''}</span><br/>
  <div class="badge">Title</div> <span class="small">{report.get('title') or ''}</span><br/>
  <div class="badge">Status hint</div> <span class="small">{report.get('status_hint')}</span><br/>
  <div class="badge">Interstitial</div> <span class="small">{'YES' if report.get('interstitial_hint') else 'NO'}</span><br/>
  <div class="badge">Redirect chain</div> <span class="small">{' → '.join(report.get('redirect_chain') or [])}</span><br/>
  <div class="badge">Popups</div> <span class="small">{', '.join(report.get('popup_urls') or [])}</span><br/>
  <div class="badge">Telegram targets</div> <span class="small">{', '.join(report.get('telegram_target_urls') or [])}</span><br/>
  <div style="margin-top:10px" class="risk">Risk: {risk}/100</div>
</div>


<div class="card">
  <h1>Visual Metrics</h1>
  <div class="small">Palette (screenshot): {", ".join(report.get("visual_metrics", {}).get("palette_hex", []) or [])}</div>
  <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">
    {palette_swatches}
  </div>
  <div class="small" style="margin-top:10px">aHash: {report.get("visual_metrics", {}).get("ahash") or ""}</div>
  <div class="small" style="margin-top:10px">CLIP brand: {((report.get("visual_metrics", {}).get("clip_brand") or {}).get("top_brand") or "")} (score {((report.get("visual_metrics", {}).get("clip_brand") or {}).get("top_score") or "")})</div>
  <div class="small" style="margin-top:10px">Brand-domain mismatch: {((report.get("visual_metrics", {}).get("brand_domain_mismatch")) if "brand_domain_mismatch" in (report.get("visual_metrics", {}) or {}) else "")}</div>
  <div class="small" style="margin-top:10px">DOM/Visual mapping: score {((report.get("visual_metrics", {}).get("dom_visual_mapping") or {}).get("score") or "")}, missing {((report.get("visual_metrics", {}).get("dom_visual_mapping") or {}).get("missing_in_dom") or [])}</div>
  <div class="small" style="margin-top:10px">Layout fingerprint: {((report.get("visual_metrics", {}).get("layout_fingerprint") or {}).get("signature") or "")}</div>
  <div class="small" style="margin-top:6px; word-break:break-all">Layout summary: {((report.get("visual_metrics", {}).get("layout_fingerprint") or {}).get("summary") or "")}</div>
  <div class="small" style="margin-top:10px">Risk drivers: {", ".join(report.get("visual_metrics", {}).get("risk_drivers", []) or [])}</div>
  {ref_block}
</div>

{infra_block}

<div class="card">
  <h1>Redirect Artifacts</h1>
  <div class="small" style="margin-top:4px"><b>Resolved Telegram targets:</b></div>
  <table>
    <thead><tr><th>#</th><th>Target</th></tr></thead>
    <tbody>{tg_target_rows}</tbody>
  </table>
  <div class="small" style="margin-top:10px"><b>Telegram evidence by source:</b></div>
  <table>
    <thead><tr><th>Source</th><th>Values</th></tr></thead>
    <tbody>{tg_source_rows}</tbody>
  </table>
</div>

<div class="card">
  <h1>Screenshot</h1>
  <div class="small" style="margin-bottom:8px">Originale</div>
  <img src="{out_png.name}" alt="screenshot originale"/>
  {annotated_block}
</div>

<div class="card">
  <h1>Detections</h1>
  <table>
    <thead><tr><th>Class</th><th>Conf</th><th>Box (xyxy)</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<div class="card">
  <h1>DOM Intelligence</h1>
  <div class="small"><b>Input types:</b> {", ".join((report.get("dom_intelligence", {}) or {}).get("input_types", []) or [])}</div>
  <div class="small" style="margin-top:8px"><b>Form actions:</b></div>
  <table>
    <thead><tr><th>#</th><th>Action</th></tr></thead>
    <tbody>{dom_form_rows}</tbody>
  </table>
  <div class="small" style="margin-top:10px"><b>Links:</b></div>
  <table>
    <thead><tr><th>#</th><th>Href</th></tr></thead>
    <tbody>{dom_link_rows}</tbody>
  </table>
  <div class="small" style="margin-top:10px"><b>Scripts:</b></div>
  <table>
    <thead><tr><th>#</th><th>Src</th></tr></thead>
    <tbody>{dom_script_rows}</tbody>
  </table>
</div>

<div class="small">Tip: se vedi (no detections) prova --width 1366 --height 768 --fullpage --wait 3 --no-headless</div>
</body></html>
"""
    html_path = out_dir / f"phishradar_{stamp}.html"
    html_path.write_text(html_doc, encoding="utf-8")



    layout_json_path = None
    if save_layout_json:
        try:
            layout_report = {
                "generated": report["generated"],
                "url": url,
                "final_url": meta.get("final_url"),
                "title": meta.get("title"),
                "status_hint": meta.get("status_hint"),
                "risk": risk,
        "dom_intelligence": dom_intel,
        "step2": step2_info,
        "filtered_detections": filtered_out_detections,
                "layout_fingerprint": (visual_metrics or {}).get("layout_fingerprint"),
                "clip_brand": (visual_metrics or {}).get("clip_brand"),
                "palette_hex": (visual_metrics or {}).get("palette_hex"),
                "ahash": (visual_metrics or {}).get("ahash"),
                "reference_compare": {
                    "position_compare": (visual_metrics or {}).get("position_compare"),
                    "layout_compare": (visual_metrics or {}).get("layout_compare"),
                    "button_color_compare": (visual_metrics or {}).get("button_color_compare"),
                    "ref": ((visual_metrics or {}).get("ref") or {}),
                },
                "dom_visual_mapping": (visual_metrics or {}).get("dom_visual_mapping"),
                "brand_domain_mismatch": (visual_metrics or {}).get("brand_domain_mismatch"),
                "risk_drivers": (visual_metrics or {}).get("risk_drivers"),
                "favicon_intelligence": (visual_metrics or {}).get("favicon_intelligence"),
                "local_correlation": (visual_metrics or {}).get("local_correlation"),
                "hunting_queries": (visual_metrics or {}).get("hunting_queries"),
            }
            layout_json_path = out_dir / f"layout_fingerprint_{stamp}.json"
            layout_json_path.write_text(json.dumps(layout_report, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            layout_json_path = None

    print(f"\nSaved:\n  JSON: {json_path}\n  HTML: {html_path}\n  PNG:  {out_png}" + (f"\n  ANNOTATED: {annotated_png}" if annotated_png else "") + (f"\n  LAYOUT_JSON: {layout_json_path}" if layout_json_path else ""))
    if open_after:
        try:
            webbrowser.open(str(html_path.resolve()))
        except Exception:
            pass

def parse_args():
    ap = argparse.ArgumentParser(description="ARGUS PhishRadar Phishing Scanner (NO-API)")
    ap.add_argument("--url", required=True, help="URL da analizzare (live)")
    ap.add_argument("--yolo-model", default=None, help=f"Path al modello YOLO (.pt) addestrato. Se omesso, ARGUS usa {DEFAULT_MODEL} e lo scarica automaticamente se manca.")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUTPUT), help=f"Cartella output (default: {DEFAULT_OUTPUT})")
    ap.add_argument("--headless", action="store_true", help="Esegue browser in headless (default: false)")
    ap.add_argument("--no-headless", action="store_true", help="Forza headless=false (utile per siti anti-bot)")
    ap.add_argument("--wait", type=float, default=2.5, help="Secondi di attesa dopo DOMContentLoaded (default 2.5)")
    ap.add_argument("--fullpage", action="store_true", help="Screenshot full page (scroll) (default false)")
    ap.add_argument("--width", type=int, default=1366, help="Viewport width (default 1366)")
    ap.add_argument("--height", type=int, default=768, help="Viewport height (default 768)")
    ap.add_argument("--ua", default=None, help="User-Agent custom (string)")
    ap.add_argument("--imgsz", type=int, default=640, help="YOLO imgsz (default 640)")
    ap.add_argument("--ref-url", default=None, help="URL di riferimento (originale) per confronto visivo")
    ap.add_argument("--ref-image", default=None, help="PNG/JPG di riferimento locale per confronto visivo")
    ap.add_argument("--palette-k", type=int, default=6, help="Numero colori palette (default 6)")
    ap.add_argument("--pos-tol", type=float, default=0.06, help="Tolleranza mismatch posizioni (0-1, default 0.06)")
    ap.add_argument("--clip", action="store_true", help="Abilita CLIP brand recognition (richiede transformers/torch)")
    ap.add_argument("--clip-brands", default="Microsoft,Google,Apple,Facebook,Instagram,PayPal,Amazon,Netflix,LinkedIn,X,Twitter", help="Lista brand separati da virgola")
    ap.add_argument("--clip-threshold", type=float, default=0.30, help="Soglia score CLIP per considerare un brand (default 0.30)")
    ap.add_argument("--clip-device", default="cpu", choices=["cpu","cuda"], help="Device CLIP (cpu/cuda)")
    ap.add_argument("--print-layout", action="store_true", help="Stampa fingerprint layout in console")
    ap.add_argument("--save-layout-json", action="store_true", help="Salva anche un file layout_fingerprint_*.json separato")
    ap.add_argument("--filter-anomalous-boxes", action="store_true", help="Filtra bbox anomale (es. falsi positivi enormi su header/banner)")
    ap.add_argument("--step2-email", default=None, help="Email fake da inserire per forzare il secondo step di login, se presente")
    ap.add_argument("--step2-click-selectors", default="button[type=submit],input[type=submit],#idSIButton9,text=Next,text=Avanti,text=Sign in", help="Selettori o testi da provare per avanzare allo step 2")
    ap.add_argument("--brand-allowlist", default=None, help="Domini ufficiali extra separati da virgola per il controllo brand-domain mismatch")
    ap.add_argument("--ocr-light", action="store_true", default=True, help="Abilita OCR light prima di YOLO per proporre ROI semantiche (default: attivo)")
    ap.add_argument("--no-ocr-light", action="store_true", help="Disabilita il pre-step OCR light")
    ap.add_argument("--ocr-max-proposals", type=int, default=8, help="Numero massimo di ROI OCR da passare a YOLO (default 8)")
    ap.add_argument("--ocr-crop-margin", type=float, default=0.08, help="Margine extra attorno alle ROI OCR (default 0.08)")
    ap.add_argument("--ocr-conf-scale", type=float, default=0.85, help="Scala la conf YOLO sui crop OCR (default 0.85)")
    ap.add_argument("--campaign-expand", action="store_true", help="Genera varianti del dominio seed e ne testa un sottoinsieme per hunting campagna")
    ap.add_argument("--campaign-max-generate", type=int, default=18, help="Numero massimo di varianti da generare (default 18)")
    ap.add_argument("--campaign-max-probe", type=int, default=10, help="Numero massimo di varianti da sondare via DNS/HTTP (default 10)")
    ap.add_argument("--campaign-timeout", type=float, default=3.0, help="Timeout per probe variante in secondi (default 3.0)")
    ap.add_argument("--conf", type=float, default=0.25, help="YOLO conf threshold (default 0.25)")
    ap.add_argument("--iou", type=float, default=0.45, help="YOLO IoU threshold (default 0.45)")
    ap.add_argument("--open", action="store_true", help="Apre la dashboard HTML al termine")
    return ap.parse_args()


def hard_dom_gate_false_positives(detections: list[dict], dom_intel: dict | None = None) -> tuple[list[dict], list[dict], dict]:
    """
    Sopprime detection login-like quando il DOM non contiene un vero password field.
    Utile per ridurre falsi positivi su siti corporate/industriali dove YOLO vede
    pannelli, widget o elementi grafici come campi login.
    """
    dom_intel = dom_intel or {}
    dom_inputs = [str(x).lower() for x in (dom_intel.get("input_types") or [])]

    info = {
        "active": False,
        "reason": None,
        "dom_inputs": dom_inputs,
    }

    # Se esiste una password reale nel DOM, non sopprimere nulla
    if "password" in dom_inputs:
        return detections, [], info

    suppressible = {
        "username_field",
        "password_field",
        "login_button",
        "remember_me_checkbox",
        "forgot_password_link",
    }

    kept = []
    suppressed = []
    for d in detections:
        name = str(d.get("name", ""))
        if name in suppressible:
            suppressed.append({**d, "filtered_reason": "hard_dom_gate_no_password"})
        else:
            kept.append(d)

    if suppressed:
        info["active"] = True
        info["reason"] = "no password field in DOM"

    return kept, suppressed, info


def main():
    banner()
    args = parse_args()

    try:
        resolved_model = args.yolo_model if args.yolo_model else ensure_default_model()
    except Exception as e:
        print(f"❌ {e}")
        return 2

    model_path = Path(resolved_model)
    if not model_path.exists():
        print(f"❌ YOLO model not found: {model_path}")
        print("Place your model at models/best.pt or pass --yolo-model <path>")
        return 2

    headless = True if args.headless else False
    if args.no_headless:
        headless = False

    out_dir = Path(args.out_dir)
    safe_mkdir(out_dir)

    # screenshot temp
    tmp_png = Path(tempfile.gettempdir()) / f"argus_phishradar_{now_stamp()}.png"
    annotated_tmp = None  # always defined (anche se annotazione non disponibile)
    visual_metrics = {}
    step2_info = {}
    filtered_out_detections = []
    print(f"Opening: {args.url}")

    meta, dom_intel, step2_info = capture_live_session(
        args.url, tmp_png,
        headless=headless,
        width=args.width,
        height=args.height,
        wait=args.wait,
        fullpage=args.fullpage,
        user_agent=args.ua,
        step2_email=args.step2_email,
        step2_click_selectors=args.step2_click_selectors,
    )
    print(f"Screenshot: {tmp_png}")
    if meta.get("title"):
        print(f"Title: {meta['title']}")
    if meta.get("status_hint") is not None:
        print(f"Status hint: {meta['status_hint']}")
    if meta.get("interstitial_hint"):
        print("⚠️  Interstitial/WAF hint: sembra una pagina di blocco (es. Cloudflare 'Suspected Phishing').")
    if meta.get("redirect_chain") and len(meta.get("redirect_chain") or []) > 1:
        print(f"Redirect chain: {' -> '.join(meta.get('redirect_chain') or [])}")
    if meta.get("popup_urls"):
        print(f"Popup URLs: {', '.join(meta.get('popup_urls') or [])}")

    # OCR light -> YOLO
    ocr_light_enabled = bool(getattr(args, "ocr_light", True)) and not bool(getattr(args, "no_ocr_light", False))
    detections, ocr_light_info = run_yolo_with_ocr_light(
        str(model_path), str(tmp_png),
        imgsz=args.imgsz,
        conf=args.conf,
        iou=args.iou,
        ocr_light=ocr_light_enabled,
        ocr_max_proposals=int(getattr(args, "ocr_max_proposals", 8)),
        ocr_crop_margin=float(getattr(args, "ocr_crop_margin", 0.08)),
        ocr_conf_scale=float(getattr(args, "ocr_conf_scale", 0.85)),
    )
    visual_metrics["ocr_light"] = ocr_light_info
    detections.sort(key=lambda x: x["conf"], reverse=True)
    if ocr_light_enabled:
        print(f"OCR light: available={ocr_light_info.get('available')} proposals={len(ocr_light_info.get('proposals') or [])} base={ocr_light_info.get('base_detections')} merged={ocr_light_info.get('merged_detections')}")

    if getattr(args, "filter_anomalous_boxes", False):
        detections, filtered_out_detections = filter_anomalous_detections(detections, width=args.width, height=args.height)
        if filtered_out_detections:
            print(f"Filtered anomalous detections: {len(filtered_out_detections)}")
    detections, filtered_out = filter_suspicious_large_boxes(detections, args.width, args.height)
    if filtered_out:
        visual_metrics["filtered_out"] = filtered_out

    detections, cookie_suppressed, cookie_ctx = suppress_cookie_banner_false_positives(detections, dom_intel=dom_intel, meta=meta)
    if cookie_suppressed:
        filtered_out_detections.extend(cookie_suppressed)
        visual_metrics["cookie_suppressed"] = cookie_suppressed
        print(f"Suppressed cookie-banner false positives: {len(cookie_suppressed)}")
    visual_metrics["cookie_banner_context"] = cookie_ctx

    detections, dom_gate_suppressed, dom_gate_info = hard_dom_gate_false_positives(detections, dom_intel=dom_intel)
    if dom_gate_suppressed:
        filtered_out_detections.extend(dom_gate_suppressed)
        visual_metrics["dom_gate_suppressed"] = dom_gate_suppressed
        print(f"Suppressed DOM-gated login false positives: {len(dom_gate_suppressed)}")
    visual_metrics["hard_dom_gate"] = dom_gate_info

    detections, semantic_suppressed, semantic_info = semantic_rescore_detections(
        detections, dom_intel, tmp_png, width=args.width, height=args.height
    )
    if semantic_suppressed:
        filtered_out_detections.extend(semantic_suppressed)
        print(f"Suppressed semantic false positives: {len(semantic_suppressed)}")
    visual_metrics["semantic_validator"] = semantic_info

    print("\nDetections")
    print("-" * 40)
    if not detections:
        print("(no detections)")
        print("\nTip rapidi se ti aspetti detection ma non arrivano:")
        print("  • prova DESKTOP: --width 1366 --height 768")
        print("  • prova fullpage: --fullpage")
        print("  • aumenta attesa: --wait 3.5")
        print("  • prova non-headless: --no-headless")
        print("  • se il sito è 'mobile-only' prova 390x844: --width 390 --height 844")
        print("  • se vedi pagina di blocco Cloudflare, è normale che YOLO non veda la UI del phishing.")
    else:
        for d in detections:
            print(f"{d['name']:<22} {d['conf']:.3f}  {d['xyxy']}")

    if detections:
        annotated_tmp = Path(tempfile.gettempdir()) / f"argus_phishradar_annotated_{now_stamp()}.png"
        ok = annotate_screenshot(tmp_png, detections, annotated_tmp)
        if not ok:
            annotated_tmp = None
    else:
        annotated_tmp = None

    # ----------------------------
    # Metriche visive (palette/hash + confronto opzionale)
    # ----------------------------
    try:
        visual_metrics["palette_hex"] = compute_palette(tmp_png, k=int(getattr(args, "palette_k", 6)))
        visual_metrics["ahash"] = compute_ahash(tmp_png)
        visual_metrics["layout_fingerprint"] = build_layout_fingerprint(detections, width=args.width, height=args.height)
        visual_metrics["dom_visual_mapping"] = dom_visual_mapping(meta, detections, args.width, args.height)

        # CLIP brand recognition (opzionale)
        if getattr(args, "clip", False):
            brands = [b.strip() for b in str(getattr(args, "clip_brands", "")).split(",") if b.strip()]
            clip_res = clip_brand_recognition(tmp_png, brands, device=str(getattr(args, "clip_device", "cpu")))
            visual_metrics["clip_brand"] = clip_res
            if clip_res.get("available"):
                tb = clip_res.get("top_brand")
                ts = clip_res.get("top_score") or 0.0
                th = float(getattr(args, "clip_threshold", 0.30))
                if tb and ts >= th:
                    # bonus rischio se ci sono indicatori cred-harvest e brand forte
                    names = [d.get("name") for d in detections]
                    if ("login_button" in names) and (("username_field" in names) or ("password_field" in names)):
                        visual_metrics["clip_risk_bonus"] = 15
                    else:
                        visual_metrics["clip_risk_bonus"] = 7
                else:
                    visual_metrics["clip_risk_bonus"] = 0
            else:
                visual_metrics["clip_risk_bonus"] = 0

    except Exception:
        pass

    # Se fornito un riferimento (URL o immagine), facciamo un confronto
    ref_path = None
    if getattr(args, "ref_image", None):
        rp = Path(args.ref_image)
        if rp.exists():
            ref_path = rp
        else:
            print(f"⚠️  ref-image non trovato: {rp}")
    elif getattr(args, "ref_url", None):
        try:
            ref_tmp = Path(tempfile.gettempdir()) / f"argus_yolo_ref_{now_stamp()}.png"
            print(f"Opening REF: {args.ref_url}")
            _ = take_screenshot_playwright(
                args.ref_url, ref_tmp,
                headless=headless,
                width=args.width,
                height=args.height,
                wait=args.wait,
                fullpage=args.fullpage,
                user_agent=args.ua,
            )
            ref_path = ref_tmp
            print(f"REF Screenshot: {ref_tmp}")
        except Exception as e:
            print(f"⚠️  Impossibile acquisire ref-url: {e}")
            ref_path = None

    if ref_path is not None:
        try:
            # YOLO sul riferimento
            ref_results = run_yolo(str(model_path), str(ref_path), imgsz=args.imgsz, conf=args.conf, iou=args.iou)
            ref_dets = _extract_detections_from_results(ref_results)
            ref_dets.sort(key=lambda x: x["conf"], reverse=True)

            visual_metrics["ref"] = {
                "path": str(ref_path),
                "palette_hex": compute_palette(ref_path, k=int(getattr(args, "palette_k", 6))),
                "ahash": compute_ahash(ref_path),
                "layout_fingerprint": build_layout_fingerprint(ref_dets, width=args.width, height=args.height),
            }
            hd = hamming_hex(visual_metrics.get("ahash"), visual_metrics["ref"].get("ahash"))
            if hd is not None:
                # 8x8 aHash = 64 bit => dist 0..64
                visual_metrics["hash_hamming"] = hd
                visual_metrics["hash_similarity"] = round(1.0 - (hd / 64.0), 3)

            visual_metrics["layout_compare"] = compare_layout_fingerprints(
                visual_metrics.get("layout_fingerprint"),
                (visual_metrics.get("ref") or {}).get("layout_fingerprint"),
            )
            visual_metrics["position_compare"] = compare_yolo_positions(
                detections, ref_dets, w=args.width, h=args.height, tol=float(getattr(args, "pos_tol", 0.06))
            )

            btn_det = best_detection_by_class(detections, "login_button")
            ref_btn_det = best_detection_by_class(ref_dets, "login_button")
            suspect_btn_color = get_avg_color_for_detection(tmp_png, btn_det)
            ref_btn_color = get_avg_color_for_detection(ref_path, ref_btn_det)
            visual_metrics["button_color_compare"] = {
                "suspect": suspect_btn_color,
                "reference": ref_btn_color,
                "distance": color_distance_rgb(suspect_btn_color, ref_btn_color),
            }

            # Piccolo bonus rischio se layout "mismatch" alto (tipico kit phishing che copia male)
            try:
                mr = visual_metrics["position_compare"].get("mismatch_rate", 0.0)
                visual_metrics["layout_mismatch_bonus"] = int(round(min(25, mr * 40)))
            except Exception:
                visual_metrics["layout_mismatch_bonus"] = 0

        except Exception as e:
            print(f"⚠️  Confronto con riferimento fallito: {e}")

    try:
        visual_metrics["favicon_intelligence"] = compute_favicon_intelligence(meta.get("final_url") or args.url, dom_intel=dom_intel)
        visual_metrics["hunting_queries"] = build_hunting_queries(visual_metrics, meta.get("final_url") or args.url)
        visual_metrics["local_correlation"] = find_local_correlations(out_dir, meta.get("final_url") or args.url, visual_metrics, dom_intel=dom_intel)
    except Exception as e:
        visual_metrics["favicon_intelligence_error"] = str(e)

    try:
        if getattr(args, "campaign_expand", False):
            visual_metrics["campaign_expansion"] = expand_and_probe_campaign_variants(
                meta.get("final_url") or args.url,
                visual_metrics=visual_metrics,
                dom_intel=dom_intel,
                max_generate=int(getattr(args, "campaign_max_generate", 18)),
                max_probe=int(getattr(args, "campaign_max_probe", 10)),
                timeout=float(getattr(args, "campaign_timeout", 3.0)),
                user_agent=args.ua,
            )
    except Exception as e:
        visual_metrics["campaign_expansion_error"] = str(e)

    try:
        tg = (dom_intel.get("telegram_indicators") or {})
        visual_metrics["telegram_detected"] = bool(
            (tg.get("telegram_links") or []) or
            (tg.get("telegram_meta_refresh") or []) or
            (tg.get("telegram_inline_hits") or []) or
            (tg.get("telegram_onclick_hits") or []) or
            (tg.get("telegram_text_hits") or []) or
            any(any(n in str(x).lower() for n in TELEGRAM_URL_NEEDLES) for x in ((meta.get("redirect_chain") or []) + (meta.get("popup_urls") or [])))
        )
    except Exception:
        visual_metrics["telegram_detected"] = False

    try:
        if getattr(args, "print_layout", False):
            fp = (visual_metrics.get("layout_fingerprint") or {})
            print("\nLayout fingerprint")
            print("-" * 40)
            print(f"Signature: {fp.get('signature')}")
            print(f"Summary  : {fp.get('summary')}")
            dvm = (visual_metrics.get("dom_visual_mapping") or {})
            if dvm.get("available"):
                print(f"DOM map  : score={dvm.get('score')} missing={dvm.get('missing_in_dom')}")
    except Exception:
        pass


    try:
        if step2_info:
            print("\nStep-2 interaction")
            print("-" * 40)
            print(f"Attempted : {step2_info.get('attempted')}")
            print(f"Filled    : {step2_info.get('email_filled')}")
            print(f"Clicked   : {step2_info.get('clicked')}")
            print(f"Title     : {step2_info.get('title')}")
            print(f"Final URL : {step2_info.get('final_url')}")
    except Exception:
        pass

    risk = compute_risk(detections, bool(meta.get("interstitial_hint")))
    try:
        risk = max(0, min(100, int(risk + visual_metrics.get("layout_mismatch_bonus", 0) + visual_metrics.get("clip_risk_bonus", 0))))
    except Exception:
        pass
    ctx_bonus, ctx_reasons = contextual_risk(detections, meta, visual_metrics, dom_intel=dom_intel, custom_allowlist=args.brand_allowlist)
    visual_metrics["contextual_risk_bonus"] = ctx_bonus
    visual_metrics["risk_drivers"] = ctx_reasons
    risk = max(0, min(100, int(risk + ctx_bonus)))

    benign_adjust, benign_reasons = benign_site_adjustment(detections, meta, visual_metrics, dom_intel=dom_intel)
    visual_metrics["benign_adjustment"] = benign_adjust
    visual_metrics["benign_reasons"] = benign_reasons
    risk = max(0, min(100, int(risk + benign_adjust)))

    campaign_expansion = (visual_metrics.get("campaign_expansion") or {})
    campaign_live_bonus = 0
    if campaign_expansion:
        live_count = int(campaign_expansion.get("live_count") or 0)
        top_live = [x for x in (campaign_expansion.get("top_candidates") or []) if x.get("live")]
        if live_count >= 1:
            campaign_live_bonus = min(12, 4 * live_count)
            if top_live and any(int(x.get("score") or 0) >= 35 for x in top_live[:3]):
                campaign_live_bonus += 4
        visual_metrics["campaign_live_bonus"] = int(min(16, campaign_live_bonus))
        risk = max(0, min(100, int(risk + visual_metrics["campaign_live_bonus"])))
    print(f"\nRisk: {risk}")
    if ctx_reasons:
        print("Risk drivers:")
        for r in ctx_reasons:
            print(f"  - {r}")
    if benign_reasons:
        print("Benign/context adjustments:")
        for r in benign_reasons:
            print(f"  - {r}")
    fav = (visual_metrics.get("favicon_intelligence") or {})
    if fav.get("sha256") or fav.get("mmh3") is not None:
        print("Infrastructure signals:")
        if fav.get("favicon_url"):
            print(f"  - favicon_url: {fav.get('favicon_url')}")
        if fav.get("sha256"):
            print(f"  - favicon_sha256: {fav.get('sha256')}")
        if fav.get("mmh3") is not None:
            print(f"  - favicon_mmh3: {fav.get('mmh3')}")
    corr = (visual_metrics.get("local_correlation") or {})
    if corr.get("count"):
        print(f"Local correlations found: {corr.get('count')}")
        for m in (corr.get("top_matches") or [])[:3]:
            print(f"  - {m.get('url')} (score {m.get('score')}, reasons: {', '.join(m.get('reasons') or [])})")
    camp = (visual_metrics.get("campaign_expansion") or {})
    if camp.get("probed_count"):
        print(f"Campaign expansion: brand={camp.get('brand') or ''} generated={camp.get('generated_count')} probed={camp.get('probed_count')} live={camp.get('live_count')}")
        for m in (camp.get("top_candidates") or [])[:5]:
            print(f"  - {m.get('host')} [{m.get('classification')}] status={m.get('status')} score={m.get('score')} reasons={', '.join(m.get('reasons') or [])}")
    tg = (dom_intel.get("telegram_indicators") or {})
    if visual_metrics.get("telegram_detected"):
        print("Telegram indicators detected:")
        tg_targets = visual_metrics.get("telegram_targets_by_source") or collect_telegram_targets(dom_intel=dom_intel, meta=meta)
        if tg_targets.get("all"):
            print(f"  - resolved_targets: {', '.join(tg_targets.get('all')[:10])}")
        if meta.get("redirect_chain") and any(any(n in str(x).lower() for n in TELEGRAM_URL_NEEDLES) for x in (meta.get("redirect_chain") or [])):
            print(f"  - redirect_chain: {' -> '.join(meta.get('redirect_chain') or [])}")
        if meta.get("popup_urls") and any(any(n in str(x).lower() for n in TELEGRAM_URL_NEEDLES) for x in (meta.get("popup_urls") or [])):
            print(f"  - popup_urls: {', '.join(meta.get('popup_urls') or [])}")
        if tg.get("telegram_links"):
            print(f"  - links: {', '.join(tg.get('telegram_links')[:5])}")
        if tg.get("telegram_meta_refresh"):
            print(f"  - meta_refresh: {tg.get('telegram_meta_refresh')[:3]}")
        if tg.get("telegram_inline_hits"):
            print(f"  - inline_hits: {len(tg.get('telegram_inline_hits') or [])}")
        if tg.get("telegram_onclick_hits"):
            print(f"  - onclick_hits: {len(tg.get('telegram_onclick_hits') or [])}")
    print()

    save_outputs(out_dir, args.url, meta, detections, risk, tmp_png, annotated_tmp, visual_metrics, dom_intel, step2_info, filtered_out_detections, open_after=args.open, save_layout_json=args.save_layout_json)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
