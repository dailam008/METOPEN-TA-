"""
MxToolbox client — blacklist / kesehatan domain email.

Endpoint: GET /Lookup/{command}/{argument}
          GET /Usage                (kuota, dipakai health check — gak makan lookup)
Auth    : header  Authorization: <api_key>
Docs    : https://mxtoolbox.com/restapi.aspx

Catatan: input email diambil bagian domain-nya, karena MxToolbox melakukan
lookup terhadap domain/host, bukan alamat email penuh.
"""

from sqlalchemy.orm import Session

from app.config import settings
from app.services.base_client import BaseThreatClient, field, STATUS_OK
from app.services.key_detector import MXTOOLBOX


class MxToolboxClient(BaseThreatClient):
    api_type = MXTOOLBOX

    # Probe key: /Usage — kuota akun, tidak memotong jatah lookup.
    probe = {"endpoint": "Usage", "method": "GET"}

    def __init__(self, db: Session):
        super().__init__(db)
        self.base_url = settings.MXTOOLBOX_API_BASE_URL

    def _auth_headers(self, api_key) -> dict:
        return {"Authorization": api_key, "Accept": "application/json"}

    # ============================================================
    # SCAN
    # ============================================================
    @staticmethod
    def domain_of(value: str) -> str:
        """user@domain.com -> domain.com ; selain itu dikembalikan apa adanya."""
        v = (value or "").strip()
        return v.split("@", 1)[1] if "@" in v else v

    def lookup(self, argument: str, command: str = None) -> dict:
        command = (command or settings.MXTOOLBOX_COMMAND).lower()
        target = self.domain_of(argument)
        return self.call_with_cache(
            "email", target, f"Lookup/{command}/{target}",
            # cache dipisah per command supaya blacklist & mx gak saling timpa
            cache_key=f"{command}:{target}",
        )

    def scan(self, scan_type: str, identifier: str) -> dict:
        if scan_type not in ("email", "domain"):
            return {"error": f"MxToolbox mendukung email/domain, bukan '{scan_type}'"}
        return self.lookup(identifier)

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

        failed = raw.get("Failed") or []
        warnings = raw.get("Warnings") or []
        passed = raw.get("Passed") or []
        errors = raw.get("Errors") or []
        timeouts = raw.get("Timeouts") or []
        command = raw.get("Command") or settings.MXTOOLBOX_COMMAND

        n_failed, n_warn, n_pass = len(failed), len(warnings), len(passed)

        if n_failed > 0:
            verdict = "MALICIOUS"
        elif n_warn > 0:
            verdict = "SUSPICIOUS"
        elif n_pass > 0:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        fields = [
            field("Lookup", str(command).upper()),
            field("Target", self.domain_of(identifier), mono=True),
            field("Blacklisted", n_failed, "crit" if n_failed else "ok"),
            field("Warnings", n_warn, "warn" if n_warn else "ok"),
            field("Passed", n_pass, "ok"),
        ]

        if failed:
            names = [f.get("Name") for f in failed[:5] if isinstance(f, dict) and f.get("Name")]
            if names:
                fields.append(field("Listed On", ", ".join(names), "crit"))
        if warnings:
            names = [w.get("Name") for w in warnings[:5] if isinstance(w, dict) and w.get("Name")]
            if names:
                fields.append(field("Warning On", ", ".join(names), "warn"))
        if timeouts:
            fields.append(field("Timeouts", len(timeouts), "none"))
        if errors:
            names = [e.get("Name") or e.get("Info") for e in errors[:3] if isinstance(e, dict)]
            fields.append(field("Errors", ", ".join(n for n in names if n) or len(errors), "warn"))
        if raw.get("ReportingNameServer"):
            fields.append(field("Name Server", raw["ReportingNameServer"], mono=True))

        return self.envelope(
            STATUS_OK,
            verdict=verdict,
            fields=fields,
            summary={
                "command": command,
                "target": self.domain_of(identifier),
                "failed_count": n_failed,
                "warning_count": n_warn,
                "passed_count": n_pass,
                "listed_on": [f.get("Name") for f in failed if isinstance(f, dict) and f.get("Name")],
            },
            raw=raw,
            cached=cached,
        )

    # ============================================================
    # TEST PING / HEALTH CHECK
    # ============================================================
    # Diwarisi dari BaseThreatClient lewat `probe` (/Usage) di atas.
