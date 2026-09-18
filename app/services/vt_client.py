"""
VirusTotal client.

Sekarang berdiri di atas BaseThreatClient (cache multi-source + load balancer
per api_type), tapi SEMUA method lama tetap ada dengan signature yang sama:
scan_url / scan_hash / scan_ip / scan_domain / call_vt_with_cache /
health_check_key / health_check_all_keys — jadi endpoint & scheduler lama
gak perlu diubah.
"""

from sqlalchemy.orm import Session

from app.config import settings
from app.models import VTAPIKey
from app.services.analyzer import analyze
from app.services.base_client import (
    BaseThreatClient, field, STATUS_OK, STATUS_ERROR,
)
from app.services.key_detector import VIRUSTOTAL


class VTClient(BaseThreatClient):
    api_type = VIRUSTOTAL

    # Probe key: endpoint paling ringan di VT v3 — lookup IP publik.
    probe = {"endpoint": "ip_addresses/8.8.8.8", "method": "GET"}

    def __init__(self, db: Session):
        super().__init__(db)
        self.base_url = settings.VT_API_BASE_URL

    def _auth_headers(self, api_key) -> dict:
        return {"x-apikey": api_key}

    # ================================================================
    # KOMPATIBILITAS: nama method lama dipertahankan
    # ================================================================
    def _call_vt_api(self, endpoint: str, params: dict = None) -> dict:
        """Panggil VT API dengan auto-fallback (alias ke _request)."""
        return self._request(endpoint, params=params)

    def call_vt_with_cache(self, scan_type: str, identifier: str, endpoint: str, params: dict = None) -> dict:
        """Call VT API dengan cache check terlebih dahulu."""
        return self.call_with_cache(scan_type, identifier, endpoint, params=params)

    def scan_url(self, url: str) -> dict:
        """
        VT API v3 — URL scan:
        1. POST /urls  (form-encoded: url=<url>) → dapat url_id
        2. GET  /urls/{url_id} → ambil report analisis

        VT tidak menerima GET /urls?url=... (→ 405 Method Not Allowed)
        """
        import base64
        # Derive url_id: base64url tanpa padding dari URL asli
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

        # Cek cache dulu (pakai url_id sebagai cache_key agar konsisten)
        cached = self._check_cache(url_id, "url")
        if cached is not None:
            if isinstance(cached, dict):
                return {**cached, "_from_cache": True}
            return cached

        # Step 1: Submit URL ke VT untuk dianalisis
        submit = self._request("urls", method="POST", data={"url": url})
        if not submit or "error" in submit:
            # Kalau submit gagal, coba langsung GET report (mungkin URL sudah pernah disubmit)
            result = self._request(f"urls/{url_id}", method="GET")
        else:
            # Step 2: Ambil report berdasarkan url_id
            result = self._request(f"urls/{url_id}", method="GET")

        if result and "error" not in result:
            self._save_cache(url_id, "url", result)

        return result

    def scan_hash(self, hash_value: str) -> dict:
        return self.call_with_cache("hash", hash_value, f"files/{hash_value}")

    def scan_ip(self, ip: str) -> dict:
        return self.call_with_cache("ip", ip, f"ip_addresses/{ip}")

    def scan_domain(self, domain: str) -> dict:
        return self.call_with_cache("domain", domain, f"domains/{domain}")

    def scan(self, scan_type: str, identifier: str) -> dict:
        """Dispatch berdasarkan scan_type hasil auto-detect."""
        mapping = {
            "url": self.scan_url,
            "hash": self.scan_hash,
            "ip": self.scan_ip,
            "domain": self.scan_domain,
        }
        fn = mapping.get(scan_type)
        if not fn:
            return {"error": f"VirusTotal tidak mendukung tipe input '{scan_type}'"}
        return fn(identifier)

    # ================================================================
    # REPORT — box VirusTotal buat aggregated report
    # ================================================================
    def report(self, scan_type: str, identifier: str) -> dict:
        if not self.has_key():
            return self.no_key()

        raw = self.scan(scan_type, identifier)
        cached = bool(isinstance(raw, dict) and raw.pop("_from_cache", False))

        if not isinstance(raw, dict) or "error" in raw:
            msg = raw.get("error") if isinstance(raw, dict) else "Response tidak valid"
            return self.error(msg, raw=raw if isinstance(raw, dict) else None)

        a = analyze(raw)
        malicious = a.get("malicious", 0) or 0
        suspicious = a.get("suspicious", 0) or 0
        undetected = a.get("undetected", 0) or 0
        verdict = a.get("verdict", "UNKNOWN")

        fields = [
            field("Malicious", malicious, "crit" if malicious else "ok"),
            field("Suspicious", suspicious, "warn" if suspicious else "ok"),
            field("Undetected", undetected, "none"),
        ]
        if a.get("country"):
            fields.append(field("Country", a["country"]))
        if a.get("as_owner"):
            fields.append(field("AS Owner", a["as_owner"]))
        if a.get("network"):
            fields.append(field("Network", a["network"], mono=True))
        if a.get("asn"):
            fields.append(field("ASN", a["asn"]))
        if a.get("registrar"):
            fields.append(field("Registrar", a["registrar"]))
        if a.get("file_type"):
            fields.append(field("File Type", a["file_type"]))
        if a.get("file_name"):
            fields.append(field("File Name", a["file_name"], mono=True))
        if a.get("reputation") is not None:
            rep = a["reputation"]
            fields.append(field("Reputation", rep, "crit" if rep < 0 else "ok" if rep > 0 else "none"))
        if a.get("first_seen"):
            fields.append(field("First Seen", a["first_seen"]))

        top = a.get("top_detections") or []
        if top:
            fields.append(field(
                "Top Detections",
                ", ".join(f"{d['engine']}: {d['result']}" for d in top[:3]),
                "crit",
            ))

        env = self.envelope(
            STATUS_OK,
            verdict=verdict,
            fields=fields,
            summary={
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "threat_level": a.get("threat_level"),
                "country": a.get("country"),
                "network": a.get("network"),
                "reputation": a.get("reputation"),
                "top_detections": top,
            },
            raw=raw,
            cached=cached,
        )
        # analysis lengkap tetap ikut supaya panel analisa VT yang lama
        # (SOC panel, TTP, sandbox, community votes) bisa dipakai apa adanya
        env["analysis"] = a
        return env

    # ================================================================
    # HEALTH CHECK METHODS
    # ================================================================
    # health_check_key() & test_key() sekarang diwarisi dari BaseThreatClient
    # (jalan di atas `probe` di atas), jadi semua provider memakai logika
    # penilaian key yang sama persis.

    def health_check_all_keys(self) -> dict:
        """
        Cek semua API Key yang aktif.
        Sekarang tiap key dicek pakai client sesuai api_type-nya, jadi key
        AbuseIPDB/URLhaus/MxToolbox gak salah divonis 'dead' gara-gara
        ditembakin ke endpoint VirusTotal.
        """
        from app.services.registry import health_check_key as route_health_check

        keys = self.db.query(VTAPIKey).filter(VTAPIKey.is_active == True).all()
        results = []
        for key in keys:
            result = route_health_check(self.db, key.id)
            results.append({
                "id": key.id,
                "api_key": key.api_key[:10] + "...",
                "api_type": key.api_type or VIRUSTOTAL,
                "status": result.get("status"),
                "message": result.get("message")
            })
        return {"total": len(results), "results": results}
