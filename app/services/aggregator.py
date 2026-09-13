"""
Smart routing + aggregated multi-source report.

Alur:
  1. detect_input_type()  -> hash | url | ip | domain | email
  2. ROUTING              -> API mana aja yang relevan buat tipe itu
  3. run_multi_scan()     -> panggil API yang relevan, sisanya dibikin box
                             "tidak dipanggil" (tetap tampil di dashboard)
  4. build_final_verdict()-> gabung semua vonis jadi 1 keputusan + rekomendasi

Semua penilaian di sini dihitung lokal (gratis, tanpa API tambahan).
"""

import re
from sqlalchemy.orm import Session

from app.services.base_client import STATUS_OK
from app.services.key_detector import (
    ABUSEIPDB, MXTOOLBOX, URLHAUS, VIRUSTOTAL, SOURCE_META,
)
from app.services.registry import SOURCE_ORDER, get_client
from app.utils.timeutil import now_local

# ============================================================
# 1. AUTO-DETECT TIPE INPUT
# ============================================================
_RE_EMAIL = re.compile(r"^[^@\s]+@[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")
_RE_URL = re.compile(r"^https?://", re.I)
_RE_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_RE_DOMAIN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")

INPUT_TYPE_LABELS = {
    "hash": "File Hash",
    "url": "URL",
    "ip": "IP Address",
    "domain": "Domain",
    "email": "Email / Mail Domain",
}


def detect_input_type(raw: str) -> str:
    """
    Deteksi tipe input. Urutannya sengaja: email dan URL dicek duluan karena
    keduanya bisa nyerempet pola domain.
    """
    v = (raw or "").strip()
    if not v:
        return None

    if _RE_EMAIL.match(v):
        return "email"

    if _RE_URL.match(v):
        return "url"

    m = _RE_IPV4.match(v)
    if m and all(int(g) <= 255 for g in m.groups()):
        return "ip"

    if _RE_HASH.match(v):
        return "hash"

    if _RE_DOMAIN.match(v):
        return "domain"

    # URL tanpa skema (ada path/query) tetap diperlakukan sebagai URL
    if "/" in v or "?" in v:
        return "url"

    return "hash"


# ============================================================
# 2. SMART ROUTING — API mana yang dipanggil per tipe input
# ============================================================
ROUTING = {
    "ip":     [VIRUSTOTAL, ABUSEIPDB],
    "domain": [VIRUSTOTAL, URLHAUS],
    "url":    [VIRUSTOTAL, URLHAUS],
    "hash":   [VIRUSTOTAL],
    "email":  [MXTOOLBOX],
}

# Alasan yang ditampilkan di box "tidak dipanggil"
SKIP_REASONS = {
    VIRUSTOTAL: "API tidak dipanggil (input bukan hash/URL/IP/domain)",
    ABUSEIPDB: "API tidak dipanggil (input bukan IP Address)",
    URLHAUS: "API tidak dipanggil (input bukan URL/Domain)",
    MXTOOLBOX: "API tidak dipanggil (input bukan Email/Mail Domain)",
}


def sources_for(input_type: str) -> list:
    return ROUTING.get(input_type, [VIRUSTOTAL])


def routing_plan(input_type: str) -> list:
    """Rencana routing buat ditampilkan di UI sebelum/ sesudah scan."""
    active = sources_for(input_type)
    return [
        {
            "source": s,
            "label": SOURCE_META[s]["label"],
            "emoji": SOURCE_META[s]["emoji"],
            "color": SOURCE_META[s]["color"],
            "will_call": s in active,
        }
        for s in SOURCE_ORDER
    ]


# ============================================================
# 3. EKSEKUSI MULTI-SOURCE
# ============================================================
def run_multi_scan(db: Session, identifier: str, input_type: str = None) -> dict:
    """
    Jalankan scan ke semua API yang relevan, lalu susun laporan gabungan.
    API yang tidak relevan tetap masuk hasil dengan status 'skipped' supaya
    dashboard bisa menampilkan box-nya (biar keliatan kenapa gak dipanggil).
    """
    identifier = (identifier or "").strip()
    input_type = input_type or detect_input_type(identifier)
    targets = sources_for(input_type)

    boxes = []
    for api_type in SOURCE_ORDER:
        client = get_client(api_type, db)
        if api_type in targets:
            try:
                boxes.append(client.report(input_type, identifier))
            except Exception as e:
                boxes.append(client.error(f"Gagal memproses hasil: {e}"))
        else:
            boxes.append(client.skipped(SKIP_REASONS[api_type]))

    final = build_final_verdict(boxes)

    return {
        "input": identifier,
        "input_type": input_type,
        "input_type_label": INPUT_TYPE_LABELS.get(input_type, "Unknown"),
        "scan_date": now_local().strftime("%Y-%m-%d %H:%M:%S"),
        "routed_to": targets,
        "sources": boxes,
        "final": final,
    }


# ============================================================
# 4. FINAL VERDICT + RECOMMENDATION
# ============================================================
def _signal_strength(box: dict) -> int:
    """
    Seberapa kuat sinyal dari satu sumber (0-100).
    Untuk vonis MALICIOUS/SUSPICIOUS: makin tinggi makin yakin berbahaya.
    Untuk vonis CLEAN: makin tinggi makin yakin bersih.
    """
    s = box.get("summary") or {}
    src = box.get("source")
    verdict = box.get("verdict")

    if src == VIRUSTOTAL:
        mal = s.get("malicious") or 0
        sus = s.get("suspicious") or 0
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return min(100, mal * 12 + sus * 5)
        # bersih: makin banyak engine yang scan, makin meyakinkan
        undetected = s.get("undetected") or 0
        return min(95, 45 + undetected // 2)

    if src == ABUSEIPDB:
        score = s.get("abuse_score") or 0
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return int(score)
        reports = s.get("total_reports") or 0
        base = 85 if reports == 0 else 60
        return 95 if s.get("is_whitelisted") else base

    if src == URLHAUS:
        if verdict == "MALICIOUS":
            return 95
        if verdict == "SUSPICIOUS":
            return 70
        return 65  # tidak terdaftar — sinyal bersih tapi cakupannya terbatas

    if src == MXTOOLBOX:
        failed = s.get("failed_count") or 0
        warns = s.get("warning_count") or 0
        if verdict == "MALICIOUS":
            return min(95, 60 + failed * 10)
        if verdict == "SUSPICIOUS":
            return min(70, 35 + warns * 8)
        return 70

    return 50


def build_final_verdict(boxes: list) -> dict:
    """Gabungkan vonis semua sumber jadi satu keputusan akhir."""
    ok = [b for b in boxes if b.get("status") == STATUS_OK]

    malicious = [b for b in ok if b.get("verdict") == "MALICIOUS"]
    suspicious = [b for b in ok if b.get("verdict") == "SUSPICIOUS"]
    clean = [b for b in ok if b.get("verdict") == "CLEAN"]

    names = lambda arr: ", ".join(b["label"] for b in arr)

    # --- Tidak ada data sama sekali ---
    if not ok:
        errored = [b for b in boxes if b.get("status") == "error"]
        no_key = [b for b in boxes if b.get("status") == "no_key"]
        if no_key and not errored:
            reason = f"Belum ada API key untuk sumber yang relevan ({names(no_key)})."
        elif errored:
            reason = f"Semua sumber gagal dipanggil ({names(errored)})."
        else:
            reason = "Tidak ada sumber intel yang relevan untuk input ini."
        return {
            "verdict": "UNKNOWN",
            "tone": "none",
            "confidence": 0,
            "recommendation": "MANUAL REVIEW",
            "recommendation_detail": "Tidak ada data — perlu pemeriksaan manual",
            "reason": reason,
            "sources_ok": 0,
            "sources_malicious": 0,
            "sources_suspicious": 0,
            "sources_clean": 0,
            "agreement": None,
            "conflict": None,
        }

    # --- Ada minimal satu sumber bilang MALICIOUS ---
    if malicious:
        strengths = [_signal_strength(b) for b in malicious]
        confidence = min(99, max(strengths) + (len(malicious) - 1) * 8)
        verdict, tone = "MALICIOUS", "crit"
        if confidence >= 80:
            rec, detail = "BLOCK", "High confidence — blokir sekarang"
        elif confidence >= 50:
            rec, detail = "BLOCK & INVESTIGATE", "Medium confidence — blokir lalu telusuri"
        else:
            rec, detail = "QUARANTINE", "Low confidence — karantina dulu, verifikasi manual"
        reason = f"{len(malicious)} dari {len(ok)} sumber menandai berbahaya ({names(malicious)})."

    # --- Tidak ada MALICIOUS, tapi ada SUSPICIOUS ---
    elif suspicious:
        strengths = [_signal_strength(b) for b in suspicious]
        confidence = min(75, sum(strengths) // len(strengths))
        verdict, tone = "SUSPICIOUS", "warn"
        rec, detail = "MONITOR", "Perlu verifikasi manual sebelum diblokir"
        reason = f"{len(suspicious)} dari {len(ok)} sumber menandai mencurigakan ({names(suspicious)})."

    # --- Semua bersih ---
    else:
        strengths = [_signal_strength(b) for b in clean]
        confidence = min(95, sum(strengths) // len(strengths) + (len(clean) - 1) * 5)
        verdict, tone = "CLEAN", "ok"
        if confidence >= 75:
            rec, detail = "ALLOW", "Tidak ada indikasi ancaman dari sumber mana pun"
        else:
            rec, detail = "ALLOW WITH MONITORING", "Bersih, tapi cakupan data terbatas"
        reason = f"Semua sumber yang dipanggil ({names(clean)}) menyatakan bersih."

    # --- Catatan kalau sumber saling bertentangan ---
    conflict = None
    if (malicious or suspicious) and clean:
        flagged = names(malicious + suspicious)
        conflict = f"Sumber tidak sepakat: {flagged} menandai berisiko, sementara {names(clean)} menyatakan bersih."

    return {
        "verdict": verdict,
        "tone": tone,
        "confidence": int(confidence),
        "recommendation": rec,
        "recommendation_detail": detail,
        "reason": reason,
        "sources_ok": len(ok),
        "sources_malicious": len(malicious),
        "sources_suspicious": len(suspicious),
        "sources_clean": len(clean),
        "agreement": f"{len(malicious) + len(suspicious)}/{len(ok)} sumber menandai berisiko",
        "conflict": conflict,
    }
