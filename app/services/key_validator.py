"""
Validasi API key lewat test ping — PENENTU AKHIR jenis key.

Kenapa ada modul ini
--------------------
Auth-Key URLhaus dan API key AbuseIPDB sama-sama `[A-Za-z0-9_]{30,50}`.
Himpunannya identik, jadi key_detector (yang cuma baca format) tidak akan
pernah bisa memisahkan keduanya — sekeras apa pun regex-nya diatur ulang.
Yang bisa memisahkan cuma satu: TANYA LANGSUNG KE PROVIDER-NYA.

Cara kerja
----------
1. key_detector menebak dari format → menghasilkan `candidates`, yaitu urutan
   provider yang bakal dicoba (VirusTotal → URLhaus → MxToolbox → AbuseIPDB;
   AbuseIPDB terakhir karena polanya paling longgar).
2. Tiap provider ditembak endpoint ringannya pakai key tersebut.
3. Provider pertama yang menjawab 200 (atau 429 — auth lolos, cuma kuota
   habis) itulah pemilik key-nya. Pencarian langsung berhenti di situ.
4. Kalau semua menolak → key invalid. Kalau ada yang tidak bisa dihubungi →
   hasilnya "unknown", BUKAN invalid: internet mati bukan bukti key rusak.

Biaya: sekali validasi = maksimal 4 request ringan (biasanya 1-2, karena
tebakan format dipakai buat menentukan siapa yang dites duluan). Kalau user
sudah memilih jenis API manual, cuma provider itu yang dites.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.models import VTAPIKey
from app.services.base_client import (
    PROBE_INVALID, PROBE_UNREACHABLE, PROBE_INCONCLUSIVE,
)
from app.services.key_detector import (
    VIRUSTOTAL, get_meta, normalize_api_type, resolve_api_type,
)

# Hasil akhir identifikasi
RESULT_VALID = "valid"        # ada provider yang mengakui key ini
RESULT_INVALID = "invalid"    # semua provider menolak — key salah/kadaluarsa
RESULT_UNKNOWN = "unknown"    # belum bisa disimpulkan (jaringan/endpoint aneh)
RESULT_SKIPPED = "skipped"    # validasi memang tidak dijalankan


def test_key(db: Session, api_type: str, api_key: str, timeout: float = 10.0) -> dict:
    """Test ping satu key ke SATU provider. Tidak menyentuh database."""
    from app.services.registry import get_client  # lokal: hindari import melingkar

    return get_client(api_type, db).test_key(api_key, timeout=timeout)


def test_all(db: Session, api_key: str, timeout: float = 10.0) -> list:
    """
    Test ping ke SEMUA provider tanpa berhenti di yang pertama cocok.
    Dipakai tombol diagnosa di dashboard waktu user pengin lihat gambaran utuh.
    """
    from app.services.registry import SOURCE_ORDER

    return [test_key(db, t, api_key, timeout=timeout) for t in SOURCE_ORDER]


def identify_key(
    db: Session,
    api_key: str,
    manual: Optional[str] = None,
    timeout: float = 10.0,
) -> dict:
    """
    Tentukan jenis key sebenarnya: tebak dari format, lalu BUKTIKAN via ping.

    manual: kalau user memaksa jenis API lewat dropdown, cuma provider itu
            yang dites — hasilnya cuma memberi tahu key-nya valid atau tidak,
            bukan memindahkannya ke provider lain.
    """
    key = (api_key or "").strip()
    detection = resolve_api_type(key, manual)
    forced = bool(manual and normalize_api_type(manual))

    if not key:
        return _wrap(detection, RESULT_INVALID, "Key kosong.", [], forced)

    attempts = []
    for api_type in detection.get("candidates") or [detection["api_type"]]:
        result = test_key(db, api_type, key, timeout=timeout)
        attempts.append(result)

        if result["valid"] is True:
            meta = get_meta(api_type)
            note = ""
            if not forced and api_type != detection["api_type"]:
                # Inilah kasus yang bikin bug awal: tebakan format meleset,
                # dan ping-lah yang membetulkannya.
                note = (
                    f" (tebakan format sempat mengarah ke "
                    f"{get_meta(detection['api_type'])['label']}, dikoreksi lewat test ping)"
                )
            return {
                **detection,
                "api_type": api_type,
                "label": meta["label"],
                "emoji": meta["emoji"],
                "color": meta["color"],
                "icon": meta["icon"],
                "verified": True,
                "forced": forced,
                "validation_status": RESULT_VALID,
                "probe_status": result["status"],
                "confidence": "verified",
                "message": result["message"] + note,
                "reason": (
                    f"Diverifikasi lewat test ping: {meta['label']} menerima key ini "
                    f"(HTTP {result.get('http_status')})."
                ),
                "attempts": attempts,
            }

    # Tidak ada yang menerima key ini.
    unreachable = [a for a in attempts if a["status"] in (PROBE_UNREACHABLE, PROBE_INCONCLUSIVE)]
    rejected = [a["label"] for a in attempts if a["status"] == PROBE_INVALID]

    if unreachable:
        names = ", ".join(a["label"] for a in unreachable)
        return _wrap(
            detection, RESULT_UNKNOWN,
            f"❓ Belum bisa dipastikan — {names} tidak menjawab dengan jelas. "
            f"Jenis key dipakai dari tebakan format ({detection['label']}).",
            attempts, forced,
        )

    names = ", ".join(rejected) or "semua provider"
    return _wrap(
        detection, RESULT_INVALID,
        f"❌ Key ditolak {names}. Pastikan key-nya belum kadaluarsa dan tersalin utuh.",
        attempts, forced,
    )


def _wrap(detection: dict, status: str, message: str, attempts: list, forced: bool) -> dict:
    """Hasil identifikasi yang GAGAL — jenis key jatuh balik ke tebakan format."""
    return {
        **detection,
        "verified": False,
        "validation_status": status,
        "probe_status": attempts[-1]["status"] if attempts else None,
        "message": message,
        "attempts": attempts,
        "forced": forced,
    }


def unvalidated(api_key: str, manual: Optional[str] = None) -> dict:
    """Bentuk hasil kalau validasi sengaja dilewati (validate=false)."""
    detection = resolve_api_type(api_key, manual)
    return {
        **detection,
        "verified": False,
        "validation_status": RESULT_SKIPPED,
        "probe_status": None,
        "message": "Validasi test ping dilewati — jenis key masih berupa tebakan dari format.",
        "attempts": [],
        "forced": bool(manual and normalize_api_type(manual)),
    }


def apply_to_key(db: Session, key: VTAPIKey, result: dict) -> str:
    """
    Simpan hasil validasi ke row key: jenis API + status kesehatan.
    Return health_status finalnya ('fresh' | 'rate_limited' | 'dead' | 'unknown').
    """
    from app.services.registry import get_client

    key.api_type = result["api_type"]

    attempts = result.get("attempts") or []
    if not attempts:
        return key.health_status or "unknown"

    # Ambil hasil ping provider yang akhirnya dipakai; kalau tidak ada yang
    # cocok, pakai percobaan terakhir supaya statusnya tetap tercatat.
    probe = next((a for a in attempts if a["api_type"] == key.api_type), attempts[-1])
    client = get_client(key.api_type, db)
    return client.apply_probe_to_key(key, probe)


def revalidate_stored_key(db: Session, key_id: int, reassign: bool = True) -> dict:
    """
    Validasi ulang key yang sudah tersimpan. Kalau `reassign` True dan test
    ping menunjuk provider lain, api_type-nya ikut dibetulkan — ini jalan
    keluar buat key lama yang terlanjur salah label di database.
    """
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        return {"error": "Key not found"}

    previous = key.api_type or VIRUSTOTAL
    # reassign=False -> kunci ke tipe yang sekarang tersimpan
    result = identify_key(db, key.api_key, manual=None if reassign else previous)

    if not result["verified"]:
        # Jangan pindahkan tipe berdasarkan tebakan format — biarkan apa adanya.
        result["api_type"] = previous
        meta = get_meta(previous)
        result.update(label=meta["label"], emoji=meta["emoji"], color=meta["color"], icon=meta["icon"])

    health = apply_to_key(db, key, result)
    db.commit()

    result["id"] = key.id
    result["health_status"] = health
    result["status"] = health          # kompatibel dengan endpoint health-check lama
    result["previous_api_type"] = previous
    result["reassigned"] = previous != key.api_type
    if result["reassigned"]:
        result["message"] += f" Jenis key dipindah dari {get_meta(previous)['label']} ke {result['label']}."
    return result
