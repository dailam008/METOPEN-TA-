"""
VT Analyzer — Pure Python, no API key, no cost.
Parses VirusTotal JSON response into a clean summary.
"""

from datetime import datetime
from typing import Optional


def _safe_get(d: dict, *keys, default=None):
    """Safely traverse nested dict."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


def _parse_last_analysis_stats(attrs: dict) -> tuple[int, int, int]:
    stats = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0) or 0
    suspicious  = stats.get("suspicious", 0) or 0
    undetected  = stats.get("undetected", 0) or 0
    return malicious, suspicious, undetected


def _get_top_detections(attrs: dict, limit: int = 5) -> list[dict]:
    results = attrs.get("last_analysis_results", {})
    hits = []
    for engine, info in results.items():
        if isinstance(info, dict) and info.get("category") in ("malicious", "suspicious"):
            hits.append({
                "engine": engine,
                "result": info.get("result") or info.get("category", "—"),
                "category": info.get("category", "")
            })
    # Sort: malicious first, then alphabetical by engine
    hits.sort(key=lambda x: (0 if x["category"] == "malicious" else 1, x["engine"]))
    return hits[:limit]


def _get_threat_level(malicious: int, suspicious: int) -> str:
    if malicious >= 10:
        return "HIGH"
    elif malicious >= 3 or suspicious >= 5:
        return "MEDIUM"
    elif malicious >= 1 or suspicious >= 1:
        return "LOW"
    else:
        return "CLEAN"


def _get_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 1:
        return "MALICIOUS"
    elif suspicious >= 1:
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def _format_date(ts) -> Optional[str]:
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        return str(ts)[:10]
    except Exception:
        return None


def analyze(vt_response: dict) -> dict:
    """
    Main analysis function.
    Input : raw VT API JSON response (the full dict returned from VT)
    Output: clean analysis summary dict
    """
    attrs = _safe_get(vt_response, "data", "attributes", default={})
    if not attrs:
        return {
            "threat_level": "UNKNOWN",
            "verdict": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "top_detections": [],
            "first_seen": None,
            "country": None,
            "asn": None,
            "network": None,
            "tags": [],
            "reputation": None,
            "note": "Could not parse VT response attributes."
        }

    malicious, suspicious, undetected = _parse_last_analysis_stats(attrs)
    threat_level = _get_threat_level(malicious, suspicious)
    verdict      = _get_verdict(malicious, suspicious)
    top_detections = _get_top_detections(attrs)

    # Timestamps
    first_seen = _format_date(
        attrs.get("first_seen_itw_date")
        or attrs.get("first_submission_date")
        or attrs.get("creation_date")
        or attrs.get("last_dns_records_date")
    )

    # IP-specific fields
    country = attrs.get("country")
    asn     = attrs.get("asn")
    network = attrs.get("network")
    as_owner = attrs.get("as_owner")

    # Common optional fields
    tags       = attrs.get("tags", []) or []
    reputation = attrs.get("reputation")

    # Domain / URL extras
    registrar  = attrs.get("registrar")
    tld        = attrs.get("tld")
    # Hash extras
    file_type  = attrs.get("type_description") or attrs.get("type_tag")
    file_size  = attrs.get("size")
    file_name  = attrs.get("meaningful_name") or attrs.get("name")

def _get_sandbox_verdicts(attrs: dict, limit: int = 5) -> list[dict]:
    """Parse sandbox_verdicts dict from VT into a clean list."""
    raw = attrs.get("sandbox_verdicts", {})
    if not isinstance(raw, dict):
        return []
    verdicts = []
    for sandbox_name, info in raw.items():
        if not isinstance(info, dict):
            continue
        verdicts.append({
            "sandbox": sandbox_name,
            "category": info.get("category", "unknown"),
            "malware_names": (info.get("malware_names") or info.get("malware_classification") or [])[:3],
        })
    verdicts.sort(key=lambda x: 0 if x["category"] == "malicious" else 1)
    return verdicts[:limit]


def _get_malicious_relations(attrs: dict) -> dict:
    """
    Extract 'relasi file malicious' signals from available attributes.
    Covers: crowdsourced IDS, sigma rules, crowdsourced context tags.
    """
    result = {}

    # Sigma analysis (static rule matches)
    sigma = attrs.get("sigma_analysis_stats", {})
    if sigma:
        result["sigma"] = {
            "critical": sigma.get("critical", 0),
            "high":     sigma.get("high", 0),
            "medium":   sigma.get("medium", 0),
            "low":      sigma.get("low", 0),
        }

    # Crowdsourced IDS (network-based detection rules, e.g. Suricata/Snort)
    ids = attrs.get("crowdsourced_ids_stats", {})
    if ids:
        result["ids"] = {
            "high":   ids.get("high", 0),
            "medium": ids.get("medium", 0),
            "low":    ids.get("low", 0),
            "info":   ids.get("info", 0),
        }

    # Crowdsourced context (community-submitted labels)
    ctx = attrs.get("crowdsourced_context", [])
    if ctx and isinstance(ctx, list):
        result["context_count"] = len(ctx)
        result["context_sources"] = list({
            c.get("source", "") for c in ctx[:5] if isinstance(c, dict) and c.get("source")
        })

    return result


def analyze(vt_response: dict) -> dict:
    """
    Main analysis function.
    Input : raw VT API JSON response (the full dict returned from VT)
    Output: clean analysis summary dict
    """
    attrs = _safe_get(vt_response, "data", "attributes", default={})
    if not attrs:
        return {
            "threat_level": "UNKNOWN",
            "verdict": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "top_detections": [],
            "first_seen": None,
            "country": None,
            "asn": None,
            "network": None,
            "tags": [],
            "reputation": None,
            "community_votes": None,
            "sandbox_verdicts": [],
            "malicious_relations": {},
            "note": "Could not parse VT response attributes."
        }

    malicious, suspicious, undetected = _parse_last_analysis_stats(attrs)
    threat_level = _get_threat_level(malicious, suspicious)
    verdict      = _get_verdict(malicious, suspicious)
    top_detections = _get_top_detections(attrs)

    # Timestamps
    first_seen = _format_date(
        attrs.get("first_seen_itw_date")
        or attrs.get("first_submission_date")
        or attrs.get("creation_date")
        or attrs.get("last_dns_records_date")
    )

    # IP-specific fields
    country = attrs.get("country")
    asn     = attrs.get("asn")
    network = attrs.get("network")
    as_owner = attrs.get("as_owner")

    # Common optional fields
    tags       = attrs.get("tags", []) or []
    reputation = attrs.get("reputation")

    # Domain / URL extras
    registrar  = attrs.get("registrar")
    tld        = attrs.get("tld")
    # Hash extras
    file_type  = attrs.get("type_description") or attrs.get("type_tag")
    file_size  = attrs.get("size")
    file_name  = attrs.get("meaningful_name") or attrs.get("name")

    # === NEW: Community Votes (Public Reputation Report) ===
    raw_votes = attrs.get("total_votes", {})
    community_votes = None
    if raw_votes and isinstance(raw_votes, dict):
        harmless  = raw_votes.get("harmless", 0) or 0
        mal_votes = raw_votes.get("malicious", 0) or 0
        total_v   = harmless + mal_votes
        community_votes = {
            "harmless":   harmless,
            "malicious":  mal_votes,
            "total":      total_v,
            "malicious_pct": round(mal_votes / total_v * 100) if total_v > 0 else 0,
        }

    # === NEW: Sandbox Verdicts (Relasi File Malicious) ===
    sandbox_verdicts = _get_sandbox_verdicts(attrs)

    # === NEW: Malicious Relations (Sigma + IDS + Context) ===
    malicious_relations = _get_malicious_relations(attrs)

    return {
        "threat_level":        threat_level,
        "verdict":             verdict,
        "malicious":           malicious,
        "suspicious":          suspicious,
        "undetected":          undetected,
        "top_detections":      top_detections,
        "first_seen":          first_seen,
        # IP
        "country":             country,
        "asn":                 asn,
        "network":             network,
        "as_owner":            as_owner,
        # File/hash
        "file_type":           file_type,
        "file_size":           file_size,
        "file_name":           file_name,
        # Domain
        "registrar":           registrar,
        "tld":                 tld,
        # Common
        "tags":                tags[:10],
        "reputation":          reputation,
        # === NEW ===
        "community_votes":     community_votes,
        "sandbox_verdicts":    sandbox_verdicts,
        "malicious_relations": malicious_relations,
    }
