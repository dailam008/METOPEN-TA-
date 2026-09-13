"""
URLhaus (abuse.ch) client — database URL & host penyebar malware.

Endpoint:
  POST /url/   body: url=<full url>
  POST /host/  body: host=<domain / ip>
Auth: header  Auth-Key: <api_key>  (abuse.ch mewajibkan Auth-Key sejak 2024;
      key_optional=True dipertahankan supaya instalasi lama tanpa key tetap
      jalan dan dapat pesan error yang jelas kalau ditolak).
Docs: https://urlhaus-api.abuse.ch/
"""

import time
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.config import settings
from app.services.base_client import (
    BaseThreatClient, field, STATUS_OK,
    PROBE_VALID, PROBE_INVALID, PROBE_INCONCLUSIVE,
)
from app.services.key_detector import URLHAUS

# query_status dari abuse.ch yang artinya "Auth-Key ditolak".
# Perlu dicek dari BODY juga, bukan cuma HTTP status: abuse.ch pernah
# membalas HTTP 200 sambil menaruh penolakan auth di dalam JSON.
_BAD_AUTH_STATUSES = {
    "unauthorized", "invalid_auth_key", "auth_key_required",
    "no_auth_key", "forbidden", "invalid_api_key",
}

# Key sampah buat "control probe" — lihat _auth_is_enforced().
_CONTROL_KEY = "vtproxy-control-key-yang-pasti-tidak-valid-000"

# Hasil control probe di-cache: 1 panggilan per 10 menit, bukan tiap validasi.
_AUTH_ENFORCED = {"value": None, "at": 0.0}
_AUTH_ENFORCED_TTL = 600.0


class URLhausClient(BaseThreatClient):
    api_type = URLHAUS
    key_optional = True

    # Probe key: POST /host/ dengan host yang pasti ada di database abuse.ch.
    # Catatan: /downloads/ (dump CSV) TIDAK dipakai — itu ada di host lain
    # (urlhaus.abuse.ch, bukan urlhaus-api) dan payload-nya puluhan MB,
    # kemahalan buat sekadar mengecek satu key.
    probe = {
        "endpoint": "host/",
        "method": "POST",
        "data": {"host": "urlhaus.abuse.ch"},
    }

    def __init__(self, db: Session):
        super().__init__(db)
        self.base_url = settings.URLHAUS_API_BASE_URL

    def _auth_headers(self, api_key) -> dict:
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Auth-Key"] = api_key
        return headers

    # ============================================================
    # SCAN
    # ============================================================
    def check_url(self, url: str) -> dict:
        return self.call_with_cache("url", url, "url/", method="POST", data={"url": url})

    def check_host(self, host: str) -> dict:
        return self.call_with_cache("domain", host, "host/", method="POST", data={"host": host})

    def scan(self, scan_type: str, identifier: str) -> dict:
        if scan_type == "url":
            return self.check_url(identifier)
        if scan_type in ("domain", "ip"):
            return self.check_host(identifier)
        return {"error": f"URLhaus hanya mendukung URL/domain/host, bukan '{scan_type}'"}

    # ============================================================
    # REPORT
    # ============================================================
    def report(self, scan_type: str, identifier: str) -> dict:
        raw = self.scan(scan_type, identifier)
        cached = bool(isinstance(raw, dict) and raw.pop("_from_cache", False))

        if not isinstance(raw, dict) or "error" in raw:
            msg = raw.get("error") if isinstance(raw, dict) else "Response tidak valid"
            # Kalau ditolak karena Auth-Key, tampilkan sebagai "belum ada key"
            if isinstance(raw, dict) and raw.get("error_kind") == "no_key":
                return self.no_key()
            return self.error(msg, raw=raw if isinstance(raw, dict) else None)

        status = str(raw.get("query_status") or "").lower()

        # Tidak terdaftar di URLhaus = sinyal bersih (bukan error)
        if status in ("no_results", "not_found"):
            return self.envelope(
                STATUS_OK,
                verdict="CLEAN",
                fields=[
                    field("Listed", "Tidak", "ok"),
                    field("Status", "Tidak terdaftar di database URLhaus", "ok"),
                    field("Query", identifier, mono=True),
                ],
                summary={"listed": False, "url_count": 0},
                raw=raw,
                cached=cached,
            )

        if status not in ("ok",):
            return self.error(f"URLhaus query_status: {status or 'unknown'}", raw=raw)

        # --- Terdaftar ---
        if scan_type == "url":
            return self._report_url(raw, identifier, cached)
        return self._report_host(raw, identifier, cached)

    def _report_url(self, raw: dict, identifier: str, cached: bool) -> dict:
        url_status = str(raw.get("url_status") or "unknown").lower()
        threat = raw.get("threat") or "—"
        tags = raw.get("tags") or []
        date_added = (raw.get("date_added") or "")[:10] or None
        reporter = raw.get("reporter")
        payloads = raw.get("payloads") or []
        blacklists = raw.get("blacklists") or {}

        verdict = "MALICIOUS" if url_status == "online" else "SUSPICIOUS"

        fields = [
            field("Listed", "Ya", "crit"),
            field("URL Status", url_status, "crit" if url_status == "online" else "warn"),
            field("Threat", str(threat).replace("_", " "), "crit"),
        ]
        if tags:
            fields.append(field("Tags", ", ".join(map(str, tags[:8])), "warn"))
        if date_added:
            fields.append(field("Date Added", date_added))
        if reporter:
            fields.append(field("Reporter", reporter))
        if payloads:
            fields.append(field("Payloads", len(payloads), "crit"))
            names = [p.get("filename") for p in payloads[:3] if isinstance(p, dict) and p.get("filename")]
            if names:
                fields.append(field("Payload Files", ", ".join(names), "crit", mono=True))
        bl = [k for k, v in blacklists.items() if v and str(v).lower() not in ("not listed", "no")]
        if bl:
            fields.append(field("Blacklists", ", ".join(bl), "crit"))
        if raw.get("urlhaus_reference"):
            fields.append(field("Reference", raw["urlhaus_reference"], mono=True))

        return self.envelope(
            STATUS_OK,
            verdict=verdict,
            fields=fields,
            summary={
                "listed": True,
                "url_status": url_status,
                "threat": threat,
                "tags": tags,
                "date_added": date_added,
                "payload_count": len(payloads),
                "blacklists": bl,
                "reference": raw.get("urlhaus_reference"),
            },
            raw=raw,
            cached=cached,
        )

    def _report_host(self, raw: dict, identifier: str, cached: bool) -> dict:
        urls = raw.get("urls") or []
        url_count = int(raw.get("url_count") or len(urls) or 0)
        online = sum(1 for u in urls if isinstance(u, dict) and str(u.get("url_status")).lower() == "online")
        first_seen = (raw.get("firstseen") or "")[:10] or None
        blacklists = raw.get("blacklists") or {}

        threats = []
        for u in urls[:20]:
            if isinstance(u, dict) and u.get("threat"):
                t = str(u["threat"]).replace("_", " ")
                if t not in threats:
                    threats.append(t)

        verdict = "MALICIOUS" if online > 0 else "SUSPICIOUS" if url_count > 0 else "CLEAN"

        fields = [
            field("Listed", "Ya" if url_count else "Tidak", "crit" if url_count else "ok"),
            field("Malware URLs", url_count, "crit" if url_count else "ok"),
            field("Masih Online", online, "crit" if online else "warn"),
        ]
        if threats:
            fields.append(field("Threat Types", ", ".join(threats[:5]), "crit"))
        if first_seen:
            fields.append(field("First Seen", first_seen))
        bl = [k for k, v in blacklists.items() if v and str(v).lower() not in ("not listed", "no")]
        if bl:
            fields.append(field("Blacklists", ", ".join(bl), "crit"))
        if raw.get("urlhaus_reference"):
            fields.append(field("Reference", raw["urlhaus_reference"], mono=True))

        return self.envelope(
            STATUS_OK,
            verdict=verdict,
            fields=fields,
            summary={
                "listed": bool(url_count),
                "url_count": url_count,
                "online_count": online,
                "threats": threats,
                "first_seen": first_seen,
                "blacklists": bl,
                "reference": raw.get("urlhaus_reference"),
            },
            raw=raw,
            cached=cached,
        )

    @staticmethod
    def host_of(value: str) -> str:
        """Ambil host dari URL — dipakai router kalau mau lookup host dari URL."""
        try:
            parsed = urlparse(value if "://" in value else f"http://{value}")
            return parsed.hostname or value
        except Exception:
            return value

    # ============================================================
    # TEST PING / HEALTH CHECK
    # ============================================================
    @staticmethod
    def _rejects_auth(response) -> bool:
        """
        True kalau response ini artinya "Auth-Key ditolak".
        Dicek dua lapis karena abuse.ch tidak konsisten: kadang lewat HTTP
        status, kadang lewat query_status di body walau HTTP-nya 200.
        """
        if response.status_code in (401, 403):
            return True
        try:
            body = response.json()
        except Exception:
            return False
        return str((body or {}).get("query_status", "")).lower() in _BAD_AUTH_STATUSES

    def _auth_is_enforced(self):
        """
        Apakah endpoint URLhaus ini benar-benar MEWAJIBKAN Auth-Key?

        Kenapa perlu: URLhaus punya mode publik (key_optional=True). Kalau
        endpoint-nya lagi tidak memaksa auth, key apa pun — termasuk key
        AbuseIPDB yang nyasar — bakal dibalas HTTP 200. Tanpa cek ini,
        validasi URLhaus bakal "menyerap" semua key dan mengulang bug yang
        sama persis, cuma kebalik arah.

        Caranya: tembak endpoint yang sama pakai key yang dijamin ngawur.
          - key ngawur ditolak  → auth aktif  → 200 = bukti key valid
          - key ngawur diterima → auth mati   → 200 tidak membuktikan apa-apa

        Return True / False / None (None = gagal dicek, jangan disimpulkan).
        """
        now = time.monotonic()
        if _AUTH_ENFORCED["value"] is not None and (now - _AUTH_ENFORCED["at"]) < _AUTH_ENFORCED_TTL:
            return _AUTH_ENFORCED["value"]

        response = self._raw_probe(_CONTROL_KEY)
        if response is None:
            return None

        enforced = self._rejects_auth(response)
        _AUTH_ENFORCED["value"] = enforced
        _AUTH_ENFORCED["at"] = now
        return enforced

    def _interpret_probe(self, response) -> tuple:
        if self._rejects_auth(response):
            return PROBE_INVALID, f"🔴 Auth-Key ditolak URLhaus (HTTP {response.status_code})"

        if response.status_code == 200:
            enforced = self._auth_is_enforced()
            if enforced is False:
                return PROBE_INCONCLUSIVE, (
                    "❓ URLhaus sedang melayani request tanpa Auth-Key, jadi HTTP 200 "
                    "bukan bukti key ini valid. Tentukan jenis key secara manual."
                )
            if enforced is None:
                return PROBE_VALID, (
                    "✅ Auth-Key diterima URLhaus (catatan: pengecekan pembanding gagal, "
                    "hasil ini belum 100% pasti)"
                )
            return PROBE_VALID, "✅ Auth-Key URLhaus valid & aktif"

        return super()._interpret_probe(response)
