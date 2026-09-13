"""
AbuseIPDB client — reputasi IP dari laporan komunitas.

Endpoint: GET /check?ipAddress=<ip>&maxAgeInDays=<n>&verbose
Auth    : header  Key: <api_key>
Docs    : https://docs.abuseipdb.com/#check-endpoint
"""

from sqlalchemy.orm import Session

from app.config import settings
from app.services.base_client import (
    BaseThreatClient, field, STATUS_OK, PROBE_RATE_LIMITED,
)
from app.services.key_detector import ABUSEIPDB

# Kategori laporan resmi AbuseIPDB (angka -> nama)
CATEGORY_MAP = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

# Ambang vonis berdasarkan abuseConfidenceScore (0-100)
THRESHOLD_MALICIOUS = 75
THRESHOLD_SUSPICIOUS = 25


class AbuseIPDBClient(BaseThreatClient):
    api_type = ABUSEIPDB

    # Probe key: GET /check?ipAddress=8.8.8.8 — IP publik yang pasti ada,
    # maxAgeInDays=1 biar response-nya sekecil mungkin. Tetap makan 1 kuota
    # harian, jadi jangan dipanggil di loop.
    probe = {
        "endpoint": "check",
        "method": "GET",
        "params": {"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
    }

    def __init__(self, db: Session):
        super().__init__(db)
        self.base_url = settings.ABUSEIPDB_API_BASE_URL

    def _auth_headers(self, api_key) -> dict:
        return {"Key": api_key, "Accept": "application/json"}

    # ============================================================
    # SCAN
    # ============================================================
    def check_ip(self, ip: str) -> dict:
        return self.call_with_cache(
            "ip", ip, "check",
            params={
                "ipAddress": ip,
                "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS,
                "verbose": "",
            },
        )

    def scan(self, scan_type: str, identifier: str) -> dict:
        if scan_type != "ip":
            return {"error": f"AbuseIPDB hanya mendukung IP address, bukan '{scan_type}'"}
        return self.check_ip(identifier)

    # ============================================================
    # REPORT
    # ============================================================
    def report(self, scan_type: str, identifier: str) -> dict:
        if not self.has_key():
            return self.no_key()

        raw = self.scan(scan_type, identifier)
        cached = bool(isinstance(raw, dict) and raw.pop("_from_cache", False))

        if not isinstance(raw, dict) or "error" in raw:
            msg = raw.get("error") if isinstance(raw, dict) else "Response tidak valid"
            return self.error(msg, raw=raw if isinstance(raw, dict) else None)

        d = raw.get("data") or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        total_reports = int(d.get("totalReports") or 0)
        distinct_users = int(d.get("numDistinctUsers") or 0)
        last_reported = (d.get("lastReportedAt") or "")[:10] or None
        isp = d.get("isp")
        usage_type = d.get("usageType")
        country = d.get("countryCode")
        domain = d.get("domain")
        is_tor = bool(d.get("isTor"))
        is_whitelisted = bool(d.get("isWhitelisted"))

        categories = self._top_categories(d.get("reports") or [])

        if score >= THRESHOLD_MALICIOUS:
            verdict = "MALICIOUS"
        elif score >= THRESHOLD_SUSPICIOUS:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        score_tone = "crit" if score >= THRESHOLD_MALICIOUS else "warn" if score >= THRESHOLD_SUSPICIOUS else "ok"

        fields = [
            field("Confidence", f"{score}%", score_tone),
            field("Abuse Score", f"{score}%", score_tone),
            field("Total Reports", total_reports, "crit" if total_reports > 100 else "warn" if total_reports else "ok"),
            field("Distinct Reporters", distinct_users, "none"),
        ]
        if last_reported:
            fields.append(field("Last Report", last_reported))
        if categories:
            fields.append(field("Categories", ", ".join(categories), "crit" if score else None))
        if isp:
            fields.append(field("ISP", isp))
        if usage_type:
            fields.append(field("Usage Type", usage_type))
        if country:
            fields.append(field("Country", country))
        if domain:
            fields.append(field("Domain", domain, mono=True))
        if is_tor:
            fields.append(field("Tor Exit Node", "Ya", "warn"))
        if is_whitelisted:
            fields.append(field("Whitelisted", "Ya", "ok"))

        return self.envelope(
            STATUS_OK,
            verdict=verdict,
            fields=fields,
            summary={
                "abuse_score": score,
                "total_reports": total_reports,
                "distinct_users": distinct_users,
                "last_reported": last_reported,
                "categories": categories,
                "isp": isp,
                "usage_type": usage_type,
                "country": country,
                "is_tor": is_tor,
                "is_whitelisted": is_whitelisted,
            },
            raw=raw,
            cached=cached,
        )

    @staticmethod
    def _top_categories(reports: list, limit: int = 6) -> list:
        """Ambil kategori paling sering muncul dari laporan verbose."""
        counter = {}
        for r in reports:
            if not isinstance(r, dict):
                continue
            for cid in (r.get("categories") or []):
                name = CATEGORY_MAP.get(cid)
                if name:
                    counter[name] = counter.get(name, 0) + 1
        ranked = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
        return [name for name, _ in ranked[:limit]]

    # ============================================================
    # TEST PING / HEALTH CHECK
    # ============================================================
    # test_key() dan health_check_key() diwarisi dari BaseThreatClient dan
    # jalan di atas `probe` di atas. Yang dibedakan cuma pesan rate limit:
    # kuota AbuseIPDB itu harian, bukan per menit.
    def _interpret_probe(self, response) -> tuple:
        if response.status_code == 429:
            return PROBE_RATE_LIMITED, "🟡 Key valid — kuota harian AbuseIPDB habis, bisa dipakai lagi besok"
        return super()._interpret_probe(response)
