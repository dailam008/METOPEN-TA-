from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import VTAPIKey
from app.services.key_detector import (
    SOURCE_META, VALID_TYPES, VIRUSTOTAL,
    detect_api_type, get_meta, normalize_api_type, resolve_api_type,
)
from app.services import key_validator
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional

router = APIRouter(prefix="/keys", tags=["API Keys"])

class KeyCreate(BaseModel):
    # populate_by_name: body boleh pakai "verify" maupun "validate".
    # Nama fieldnya sendiri bukan `validate` karena itu bentrok sama
    # atribut bawaan pydantic BaseModel.
    model_config = ConfigDict(populate_by_name=True)

    api_key: str
    notes: Optional[str] = None
    # Kosongin buat auto-detect; isi kalau mau override manual
    api_type: Optional[str] = None
    # Verifikasi key ke provider aslinya sebelum disimpan. Ini yang bikin
    # key URLhaus gak nyasar jadi AbuseIPDB — formatnya identik, cuma
    # jawaban server yang bisa membedakan.
    verify: bool = Field(True, alias="validate")
    # True = key yang ditolak semua provider ditolak juga (HTTP 400).
    # Default False: key tetap disimpan tapi nonaktif, biar kelihatan di
    # dashboard dengan label ❌ Invalid.
    reject_invalid: bool = False

class KeyDetectRequest(BaseModel):
    api_key: str

class KeyValidateRequest(BaseModel):
    api_key: str
    # Isi kalau cuma mau ngetes ke satu provider tertentu
    api_type: Optional[str] = None
    # True = tes ke SEMUA provider (buat diagnosa), bukan berhenti di yang cocok
    full: bool = False

class KeyTypeUpdate(BaseModel):
    # Kosongin buat re-run auto-detect dari format key yang tersimpan
    api_type: Optional[str] = None

class KeyResponse(BaseModel):
    id: int
    api_key: str
    api_type: str
    usage_count: int
    is_active: bool
    is_error: bool
    notes: Optional[str] = None


@router.post("/detect")
def detect_key_type(data: KeyDetectRequest):
    """
    Preview auto-detect tanpa menyimpan.
    Dipakai dashboard buat nampilin label live pas user ngetik/paste key.
    """
    return detect_api_type(data.api_key)


@router.get("/types")
def list_key_types():
    """Daftar provider yang didukung + metadata label/warna."""
    return list(SOURCE_META.values())


@router.post("/validate")
def validate_key(data: KeyValidateRequest, db: Session = Depends(get_db)):
    """
    Test ping key ke provider aslinya — TANPA menyimpan.

    Ini penentu jenis key yang sebenarnya. Deteksi format cuma menentukan
    provider mana yang ditembak duluan; yang memutuskan tetap jawaban server:
    HTTP 200/429 = key diterima, 401/403 = ditolak.
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


@router.post("/validate/{key_id}")
def revalidate_key(key_id: int, reassign: bool = True, db: Session = Depends(get_db)):
    """
    Validasi ulang key yang SUDAH tersimpan.
    reassign=true (default) membetulkan api_type kalau ternyata salah label —
    ini jalan keluar buat key lama yang terlanjur masuk sebagai provider keliru.
    """
    result = key_validator.revalidate_stored_key(db, key_id, reassign=reassign)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/add")
def add_key(key_data: KeyCreate, db: Session = Depends(get_db)):
    """Tambah API key baru — jenisnya diverifikasi lewat test ping ke provider"""
    existing = db.query(VTAPIKey).filter(VTAPIKey.api_key == key_data.api_key).first()
    if existing:
        raise HTTPException(status_code=400, detail="API key already exists")

    if key_data.api_type and not normalize_api_type(key_data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )

    if key_data.verify:
        result = key_validator.identify_key(db, key_data.api_key, key_data.api_type)
    else:
        result = key_validator.unvalidated(key_data.api_key, key_data.api_type)

    if key_data.reject_invalid and result["validation_status"] == key_validator.RESULT_INVALID:
        raise HTTPException(status_code=400, detail=result["message"])

    new_key = VTAPIKey(
        api_key=key_data.api_key,
        api_type=result["api_type"],
        notes=key_data.notes,
    )
    db.add(new_key)
    db.commit()

    # Tulis hasil ping ke row-nya: key yang ditolak langsung nonaktif +
    # health_status 'dead', jadi load balancer gak pernah memakainya.
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
    """Satu kalimat status buat toast/banner dashboard."""
    label = result["label"]
    status = result["validation_status"]
    if status == key_validator.RESULT_VALID:
        return f"{result['emoji']} Key terverifikasi sebagai {label} 🟢 dan berhasil ditambahkan"
    if status == key_validator.RESULT_INVALID:
        return f"❌ Key ditolak semua provider — disimpan sebagai Invalid dan dinonaktifkan"
    if status == key_validator.RESULT_UNKNOWN:
        return f"❓ Key disimpan sebagai {label} (belum terverifikasi — provider tidak menjawab)"
    return f"{result['emoji']} Key disimpan sebagai {label} (tanpa validasi)"

@router.get("/list")
def list_keys(api_type: Optional[str] = None, db: Session = Depends(get_db)):
    """List semua API key (opsional difilter per api_type)"""
    query = db.query(VTAPIKey)
    if api_type:
        query = query.filter(VTAPIKey.api_type == api_type.lower())
    keys = query.all()

    out = []
    for k in keys:
        t = k.api_type or VIRUSTOTAL
        meta = get_meta(t)
        out.append({
            "id": k.id,
            "api_key": k.api_key[:10] + "..." if len(k.api_key) > 10 else k.api_key,
            "api_type": t,
            "api_label": meta["label"],
            "api_emoji": meta["emoji"],
            "api_color": meta["color"],
            "usage_count": k.usage_count,
            "is_active": k.is_active,
            "is_error": k.is_error,
            # Hasil validasi terakhir: 'fresh' = terverifikasi 🟢,
            # 'dead' = ❌ invalid, 'unknown' = belum pernah dites.
            "health_status": k.health_status or "unknown",
            "last_checked": k.last_checked,
            "notes": k.notes
        })
    return out

@router.delete("/remove/{key_id}")
def remove_key(key_id: int, db: Session = Depends(get_db)):
    """Hapus API key (soft delete)"""
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.is_active = False
    db.commit()
    return {"message": "Key deactivated"}

@router.post("/activate/{key_id}")
def activate_key(key_id: int, db: Session = Depends(get_db)):
    """Aktifkan kembali key yang dinonaktifkan"""
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.is_active = True
    key.is_error = False
    db.commit()
    return {"message": "Key activated"}


@router.patch("/type/{key_id}")
def set_key_type(key_id: int, data: KeyTypeUpdate, db: Session = Depends(get_db)):
    """
    Override jenis API key kalau auto-detect salah tebak.
    Kirim api_type kosong buat menjalankan ulang auto-detect.
    """
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Divalidasi duluan: resolve_api_type diam-diam jatuh ke auto-detect
    # kalau nilainya gak dikenal, jadi input ngawur harus ditolak di sini.
    if data.api_type and not normalize_api_type(data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )

    detection = resolve_api_type(key.api_key, data.api_type)
    key.api_type = detection["api_type"]
    db.commit()
    return {
        "message": f"Key type set to {detection['label']}",
        "api_type": key.api_type,
        "label": detection["label"],
        "emoji": detection["emoji"],
        "auto_detected": detection.get("auto_detected", False),
        "reason": detection["reason"],
    }
