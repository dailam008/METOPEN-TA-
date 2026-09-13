"""
Registry client multi-source.

Satu tempat buat mapping api_type -> class client, biar endpoint/scheduler
gak perlu import satu-satu dan gak ada import melingkar antar client.
"""

from sqlalchemy.orm import Session

from app.models import VTAPIKey
from app.services.abuseipdb_client import AbuseIPDBClient
from app.services.key_detector import (
    ABUSEIPDB, MXTOOLBOX, URLHAUS, VIRUSTOTAL, SOURCE_META, get_meta,
)
from app.services.mxtoolbox_client import MxToolboxClient
from app.services.urlhaus_client import URLhausClient
from app.services.vt_client import VTClient

CLIENTS = {
    VIRUSTOTAL: VTClient,
    ABUSEIPDB: AbuseIPDBClient,
    URLHAUS: URLhausClient,
    MXTOOLBOX: MxToolboxClient,
}

# Urutan tampil box di dashboard
SOURCE_ORDER = [VIRUSTOTAL, ABUSEIPDB, URLHAUS, MXTOOLBOX]


def get_client(api_type: str, db: Session):
    """Bikin instance client sesuai api_type (fallback VirusTotal)."""
    cls = CLIENTS.get((api_type or "").strip().lower(), VTClient)
    return cls(db)


def health_check_key(db: Session, key_id: int) -> dict:
    """
    Health check yang otomatis milih client sesuai api_type key-nya.
    Ini penting: key AbuseIPDB kalau ditembakin ke endpoint VirusTotal pasti
    kena 401 dan bakal salah divonis 'dead'.
    """
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        return {"error": "Key not found"}
    client = get_client(key.api_type or VIRUSTOTAL, db)
    return client.health_check_key(key_id)


def key_stats(db: Session) -> list:
    """Ringkasan jumlah key per provider — dipakai kartu stats dashboard."""
    out = []
    for api_type in SOURCE_ORDER:
        meta = SOURCE_META[api_type]
        client = get_client(api_type, db)
        lb = client.load_balancer
        total = db.query(VTAPIKey).filter(lb._type_filter(api_type)).count()
        active = lb.count_active(api_type)
        out.append({
            "source": api_type,
            "label": meta["label"],
            "emoji": meta["emoji"],
            "color": meta["color"],
            "icon": meta["icon"],
            "total_keys": total,
            "active_keys": active,
            "configured": total > 0,
        })
    return out
