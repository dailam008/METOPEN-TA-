from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import VTAPIKey, CacheScan
from app.services.key_detector import (
    SOURCE_META, VALID_TYPES, VIRUSTOTAL,
    detect_api_type, get_meta, normalize_api_type,
)
from app.services import key_validator
from app.services.registry import health_check_key as route_health_check, key_stats
from app.services.vt_client import VTClient
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

class KeyAddRequest(BaseModel):
    # Body boleh pakai "verify" atau "validate" — nama field-nya sendiri
    # tidak boleh `validate` (bentrok sama atribut pydantic BaseModel).
    model_config = ConfigDict(populate_by_name=True)

    api_key: str
    notes: Optional[str] = None
    # Kosong = auto-detect
    api_type: Optional[str] = None
    # Verifikasi ke provider aslinya sebelum disimpan
    verify: bool = Field(True, alias="validate")
    reject_invalid: bool = False

class KeyDetectRequest(BaseModel):
    api_key: str

class KeyValidateRequest(BaseModel):
    api_key: str
    api_type: Optional[str] = None
    full: bool = False

# ================================================================
# API KEY CRUD
# ================================================================

@router.get("/keys")
def get_keys(db: Session = Depends(get_db)):
    """List semua API Key dengan status + health + jenis API"""
    keys = db.query(VTAPIKey).all()
    out = []
    for k in keys:
        api_type = k.api_type or VIRUSTOTAL
        meta = get_meta(api_type)
        out.append({
            "id": k.id,
            "api_key": k.api_key[:10] + "..." if len(k.api_key) > 10 else k.api_key,
            "full_key": k.api_key,
            "api_type": api_type,
            "api_label": meta["label"],
            "api_emoji": meta["emoji"],
            "api_color": meta["color"],
            "api_icon": meta["icon"],
            "usage_count": k.usage_count,
            "is_active": k.is_active,
            "is_error": k.is_error,
            "error_count": k.error_count,
            "health_status": k.health_status or "unknown",
            "last_checked": k.last_checked,
            "status": "🟢 Active" if k.is_active and not k.is_error else "🔴 Error" if not k.is_active else "🟡 Rate Limited",
            # === STATUS VALIDASI (dipakai label di tabel dashboard) ===
            # verified True  -> provider mengakui key ini (🟢)
            #          False -> ditolak provider (❌ Invalid)
            #          None  -> belum pernah dites (❓ Unknown)
            "verified": _verified_flag(k.health_status),
            "verification_label": _verification_label(k.health_status),
            "notes": k.notes
        })
    return out


def _verified_flag(health_status):
    if health_status in ("fresh", "rate_limited"):
        return True
    if health_status == "dead":
        return False
    return None


def _verification_label(health_status):
    return {
        "fresh": "🟢 Verified",
        "rate_limited": "🟡 Verified (rate limited)",
        "dead": "❌ Invalid",
    }.get(health_status, "❓ Unknown")

@router.post("/keys/detect")
def detect_key(data: KeyDetectRequest):
    """Preview auto-detect jenis API key (tanpa menyimpan)"""
    return detect_api_type(data.api_key)

@router.get("/keys/types")
def key_types():
    """Metadata semua provider yang didukung"""
    return list(SOURCE_META.values())

@router.post("/keys/validate")
def validate_key(data: KeyValidateRequest, db: Session = Depends(get_db)):
    """
    Test ping key ke provider aslinya tanpa menyimpan — dipakai tombol
    "Test Key" di dashboard. Deteksi format cuma menentukan urutan tes;
    yang memutuskan jenis key adalah jawaban server.
    """
    if data.api_type and not normalize_api_type(data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )

    result = key_validator.identify_key(db, data.api_key, data.api_type)
    if data.full:
        result["all_probes"] = key_validator.test_all(db, data.api_key)
    return result


@router.post("/keys/validate/{key_id}")
def revalidate_key(key_id: int, reassign: bool = True, db: Session = Depends(get_db)):
    """Validasi ulang key tersimpan; betulkan api_type-nya kalau salah label."""
    result = key_validator.revalidate_stored_key(db, key_id, reassign=reassign)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/keys/add")
def add_key(data: KeyAddRequest, db: Session = Depends(get_db)):
    """Tambah API Key manual — jenisnya diverifikasi lewat test ping"""
    existing = db.query(VTAPIKey).filter(VTAPIKey.api_key == data.api_key).first()
    if existing:
        raise HTTPException(status_code=400, detail="API key already exists")

    if data.api_type and not normalize_api_type(data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )

    if data.verify:
        result = key_validator.identify_key(db, data.api_key, data.api_type)
    else:
        result = key_validator.unvalidated(data.api_key, data.api_type)

    if data.reject_invalid and result["validation_status"] == key_validator.RESULT_INVALID:
        raise HTTPException(status_code=400, detail=result["message"])

    new_key = VTAPIKey(
        api_key=data.api_key,
        api_type=result["api_type"],
        notes=data.notes,
    )
    db.add(new_key)
    db.commit()

    # Key yang ditolak provider langsung nonaktif + health 'dead', jadi
    # load balancer gak pernah menyentuhnya.
    health = key_validator.apply_to_key(db, new_key, result)
    db.commit()
    db.refresh(new_key)

    return {
        "message": _add_message(result),
        "id": new_key.id,
        "api_type": new_key.api_type,
        "label": result["label"],
        "emoji": result["emoji"],
        "color": result["color"],
        "confidence": result["confidence"],
        "reason": result["reason"],
        "auto_detected": result.get("auto_detected", True),
        # === HASIL VALIDASI ===
        "verified": result["verified"],
        "validation_status": result["validation_status"],
        "validation_message": result["message"],
        "health_status": health,
        "is_active": new_key.is_active,
        "attempts": result.get("attempts", []),
    }


def _add_message(result: dict) -> str:
    label = result["label"]
    status = result["validation_status"]
    if status == key_validator.RESULT_VALID:
        return f"{result['emoji']} Key terverifikasi sebagai {label} 🟢 dan berhasil ditambahkan"
    if status == key_validator.RESULT_INVALID:
        return "❌ Key ditolak semua provider — disimpan sebagai Invalid dan dinonaktifkan"
    if status == key_validator.RESULT_UNKNOWN:
        return f"❓ Key disimpan sebagai {label} (belum terverifikasi — provider tidak menjawab)"
    return f"{result['emoji']} Key disimpan sebagai {label} (tanpa validasi)"

@router.delete("/keys/delete/{key_id}")
def delete_key(key_id: int, db: Session = Depends(get_db)):
    """Hapus API Key"""
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    db.delete(key)
    db.commit()
    return {"message": "Key deleted"}

# ================================================================
# HEALTH CHECK
# ================================================================

@router.post("/keys/health-check")
def health_check_keys(db: Session = Depends(get_db)):
    """Check status semua API Key (tiap key dicek ke provider-nya masing-masing)"""
    client = VTClient(db)
    result = client.health_check_all_keys()
    return result

@router.post("/keys/health-check/{key_id}")
def health_check_single_key(key_id: int, db: Session = Depends(get_db)):
    """Check status satu API Key aja (hemat kuota!) — otomatis pilih provider"""
    return route_health_check(db, key_id)

# ================================================================
# CACHE
# ================================================================

@router.get("/cache")
def get_cache(source: Optional[str] = None, db: Session = Depends(get_db)):
    """Lihat semua cache scan (opsional difilter per sumber API)"""
    query = db.query(CacheScan)
    if source:
        query = query.filter(CacheScan.source == source.lower())
    caches = query.order_by(CacheScan.scan_date.desc()).limit(200).all()

    out = []
    for c in caches:
        src = c.source or VIRUSTOTAL
        meta = get_meta(src)
        out.append({
            "id": c.id,
            "scan_type": c.scan_type,
            "identifier": c.identifier,
            "source": src,
            "source_label": meta["label"],
            "source_emoji": meta["emoji"],
            "source_color": meta["color"],
            "hits": c.hits,
            "scan_date": c.scan_date
        })
    return out

@router.post("/cache/refresh")
def refresh_cache(source: Optional[str] = None, db: Session = Depends(get_db)):
    """Kosongin cache scan (semua, atau cuma satu sumber kalau ?source= diisi)"""
    query = db.query(CacheScan)
    if source:
        query = query.filter(CacheScan.source == source.lower())
    count = query.delete()
    db.commit()
    scope = f" untuk {get_meta(source)['label']}" if source else ""
    return {"message": f"Cache refreshed{scope}! {count} entries deleted"}

@router.delete("/cache/delete/{cache_id}")
def delete_cache(cache_id: int, db: Session = Depends(get_db)):
    """Hapus 1 cache berdasarkan ID"""
    cache = db.query(CacheScan).filter(CacheScan.id == cache_id).first()
    if not cache:
        raise HTTPException(status_code=404, detail="Cache not found")

    db.delete(cache)
    db.commit()
    return {"message": "Cache deleted"}

# ================================================================
# STATS
# ================================================================

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Statistik dashboard (+ breakdown multi-source)"""
    total_keys = db.query(VTAPIKey).count()
    active_keys = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).count()
    error_keys = db.query(VTAPIKey).filter(VTAPIKey.is_error == True).count()
    total_cache = db.query(CacheScan).count()
    total_hits = db.query(func.sum(CacheScan.hits)).scalar() or 0

    # Cache per sumber
    cache_rows = (
        db.query(CacheScan.source, func.count(CacheScan.id), func.sum(CacheScan.hits))
        .group_by(CacheScan.source)
        .all()
    )
    cache_by_source = {}
    for src, cnt, hits in cache_rows:
        key = src or VIRUSTOTAL
        cache_by_source[key] = {"entries": int(cnt or 0), "hits": int(hits or 0)}

    sources = key_stats(db)
    for s in sources:
        c = cache_by_source.get(s["source"], {"entries": 0, "hits": 0})
        s["cache_entries"] = c["entries"]
        s["cache_hits"] = c["hits"]

    return {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "error_keys": error_keys,
        "total_cache": total_cache,
        "total_hits": total_hits,
        # === MULTI-SOURCE ===
        "sources": sources,
        "cache_by_source": cache_by_source,
    }
