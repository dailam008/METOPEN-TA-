"""
Auto-detect jenis API key dari formatnya — pure Python, no network, no cost.

Dipakai waktu user nempel key di dashboard: sistem nebak ini key VirusTotal,
AbuseIPDB, URLhaus, atau MxToolbox, lalu simpan ke kolom vt_api_keys.api_type.

Catatan penting soal keyakinan deteksi: format key antar vendor itu OVERLAP
(64 hex juga valid sebagai "alphanumeric", base64 tanpa padding juga
alphanumeric). Jadi urutan aturan di bawah sengaja dari yang paling spesifik
ke yang paling longgar, dan tiap hasil dikasih confidence + reason biar user
tahu kapan perlu override manual.

TERBATAS SECARA PRINSIP — baca ini sebelum nambah regex baru:
Auth-Key URLhaus dan API key AbuseIPDB sama-sama `[A-Za-z0-9_]{30,50}`. Dua
himpunan itu IDENTIK, jadi tidak ada regex yang bisa memisahkan keduanya —
mau diurutkan bagaimana pun. Karena itu modul ini cuma bikin TEBAKAN plus
daftar `candidates`; yang memutuskan jenis key sebenarnya adalah test ping
di app/services/key_validator.py. `candidates` itulah urutan provider yang
bakal dicoba ping-nya.
"""

import re
from typing import Optional

# ============================================================
# METADATA SUMBER — dipakai backend & dashboard (label + warna box)
# ============================================================
VIRUSTOTAL = "virustotal"
ABUSEIPDB = "abuseipdb"
URLHAUS = "urlhaus"
MXTOOLBOX = "mxtoolbox"

SOURCE_META = {
    VIRUSTOTAL: {
        "key": VIRUSTOTAL,
        "label": "VirusTotal",
        "emoji": "🟢",
        "color": "#3fce3f",
        "icon": "bi-shield-check",
        "docs": "https://www.virustotal.com/gui/my-apikey",
    },
    ABUSEIPDB: {
        "key": ABUSEIPDB,
        "label": "AbuseIPDB",
        "emoji": "🔵",
        "color": "#3987e5",
        "icon": "bi-hdd-network",
        "docs": "https://www.abuseipdb.com/account/api",
    },
    URLHAUS: {
        "key": URLHAUS,
        "label": "URLhaus",
        "emoji": "🟡",
        "color": "#c98500",
        "icon": "bi-link-45deg",
        "docs": "https://urlhaus-api.abuse.ch/",
    },
    MXTOOLBOX: {
        "key": MXTOOLBOX,
        "label": "MxToolbox",
        "emoji": "🟣",
        "color": "#a855f7",
        "icon": "bi-envelope-at",
        "docs": "https://mxtoolbox.com/user/api",
    },
}

VALID_TYPES = tuple(SOURCE_META.keys())

# Urutan default percobaan test-ping, dari format paling khas ke paling longgar:
#   VirusTotal (64 hex) → URLhaus → MxToolbox (GUID/mx_) → AbuseIPDB (fallback).
# AbuseIPDB ditaruh terakhir justru karena polanya paling longgar: hampir semua
# key provider lain "lolos" pola alphanumeric-nya, jadi dia cuma boleh menang
# kalau tiga provider di atasnya sudah menolak key-nya.
DEFAULT_PROBE_ORDER = (VIRUSTOTAL, URLHAUS, MXTOOLBOX, ABUSEIPDB)

# ============================================================
# REGEX
# ============================================================
_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_80 = re.compile(r"^[0-9a-fA-F]{80}$")
_HEX_ANY = re.compile(r"^[0-9a-fA-F]+$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ALNUM_UNDERSCORE = re.compile(r"^[A-Za-z0-9_]+$")
_ALNUM = re.compile(r"^[A-Za-z0-9]+$")
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/=]+$")

# Prefix eksplisit — user boleh nandain sendiri waktu paste
_PREFIXES = {
    "mx_": MXTOOLBOX,
    "mx-": MXTOOLBOX,
    "mxt_": MXTOOLBOX,
    "vt_": VIRUSTOTAL,
    "vt-": VIRUSTOTAL,
    "abuse_": ABUSEIPDB,
    "abuseipdb_": ABUSEIPDB,
    "aidb_": ABUSEIPDB,
    "uh_": URLHAUS,
    "urlhaus_": URLHAUS,
}


def get_meta(api_type: Optional[str]) -> dict:
    """Metadata tampilan untuk satu api_type (fallback aman ke VirusTotal)."""
    return SOURCE_META.get((api_type or "").strip().lower(), SOURCE_META[VIRUSTOTAL])


def normalize_api_type(value: Optional[str]) -> Optional[str]:
    """
    Rapikan input api_type manual dari user/dashboard.
    Return None kalau bukan tipe yang dikenal (biar caller jatuh ke auto-detect).
    """
    v = (value or "").strip().lower().replace("-", "").replace(" ", "")
    aliases = {
        "virustotal": VIRUSTOTAL, "vt": VIRUSTOTAL,
        "abuseipdb": ABUSEIPDB, "abuse": ABUSEIPDB, "aipdb": ABUSEIPDB,
        "urlhaus": URLHAUS, "abusech": URLHAUS, "haus": URLHAUS,
        "mxtoolbox": MXTOOLBOX, "mx": MXTOOLBOX, "mxbox": MXTOOLBOX,
    }
    return aliases.get(v)


def detect_api_type(api_key: str) -> dict:
    """
    Tebak jenis API key dari formatnya.

    Return:
        {
          "api_type": "virustotal",
          "confidence": "high" | "medium" | "low",
          "reason": "penjelasan singkat kenapa ditebak begitu",
          "label": "VirusTotal",
          "emoji": "🟢",
          "color": "#3fce3f",
        }
    """
    key = (api_key or "").strip()
    result = _detect(key)
    meta = get_meta(result["api_type"])
    return {
        **result,
        "label": meta["label"],
        "emoji": meta["emoji"],
        "color": meta["color"],
        "icon": meta["icon"],
    }


def _hit(
    api_type: str,
    confidence: str,
    reason: str,
    candidates: Optional[list] = None,
    ambiguous: bool = False,
) -> dict:
    """
    Satu hasil tebakan.

    candidates: urutan provider yang masuk akal buat key ini — dipakai
                key_validator sebagai urutan test ping. api_type selalu
                jadi elemen pertama, sisa provider ditambahkan di belakang
                supaya validator tetap punya jalan keluar kalau semua
                tebakan format meleset.
    ambiguous : True kalau formatnya memang tidak bisa dibedakan (mis.
                URLhaus vs AbuseIPDB) — UI wajib nyaranin verifikasi.
    """
    ordered = [api_type]
    for t in list(candidates or []) + list(DEFAULT_PROBE_ORDER):
        if t not in ordered:
            ordered.append(t)
    return {
        "api_type": api_type,
        "confidence": confidence,
        "reason": reason,
        "candidates": ordered,
        "ambiguous": ambiguous,
    }


def _detect(key: str) -> dict:
    n = len(key)

    if not key:
        return _hit(VIRUSTOTAL, "low", "Key kosong — dipakai default VirusTotal.")

    # --- 1. Prefix eksplisit dari user (paling dipercaya) ---
    low = key.lower()
    for prefix, api_type in _PREFIXES.items():
        if low.startswith(prefix):
            return _hit(api_type, "high", f"Diawali prefix '{prefix}' — penanda eksplisit {get_meta(api_type)['label']}.")

    # --- 2. GUID/UUID → MxToolbox (key MxToolbox berbentuk GUID) ---
    if _GUID.match(key):
        return _hit(MXTOOLBOX, "high", "Format GUID (8-4-4-4-12) — khas API key MxToolbox.")

    # --- 3. 64 karakter hex → VirusTotal ---
    # Auth-Key abuse.ch juga bisa kebetulan 64 karakter hex, jadi URLhaus
    # dipasang sebagai kandidat kedua buat test ping.
    if _HEX_64.match(key):
        return _hit(
            VIRUSTOTAL, "high",
            "64 karakter hex (0-9, a-f) — format standar API key VirusTotal.",
            candidates=[URLHAUS],
        )

    # --- 4. 80 karakter hex → AbuseIPDB (format asli key v2) ---
    if _HEX_80.match(key):
        return _hit(ABUSEIPDB, "high", "80 karakter hex — format standar API key AbuseIPDB v2.")

    # --- 5. Base64 (ada karakter +, /, atau =) → URLhaus ---
    # Ditaruh sebelum aturan alphanumeric karena '+', '/', '=' itu penanda
    # yang tidak dipakai AbuseIPDB — ini satu-satunya pembeda yang nyata.
    if _BASE64ISH.match(key) and re.search(r"[+/=]", key) and n >= 16:
        return _hit(URLHAUS, "medium", "Charset Base64 (mengandung '+', '/', atau '=') — pola Auth-Key URLhaus / abuse.ch.")

    # --- 6. Hex panjang lain (32/40) → VirusTotal ---
    if _HEX_ANY.match(key) and n in (32, 40):
        return _hit(VIRUSTOTAL, "medium", f"Hex {n} karakter — kemungkinan besar key VirusTotal legacy.")

    # --- 7. ZONA ABU-ABU: alphanumeric (+ underscore) 30-50 karakter ---
    # URLhaus dan AbuseIPDB pakai pola yang PERSIS SAMA di rentang ini.
    # Tebakan format apa pun di sini cuma lemparan koin, jadi:
    #   - primary = URLhaus (sesuai urutan prioritas: AbuseIPDB fallback terakhir)
    #   - ambiguous = True → wajib diverifikasi test ping sebelum dipercaya
    if _ALNUM_UNDERSCORE.match(key) and 30 <= n <= 50:
        charset = "alphanumeric + underscore" if "_" in key else "alphanumeric"
        return _hit(
            URLHAUS, "low",
            f"{charset.capitalize()}, {n} karakter — pola ini dipakai URLhaus DAN AbuseIPDB "
            "(identik, tidak bisa dibedakan dari format). Ditebak URLhaus; jalankan test ping untuk memastikan.",
            candidates=[ABUSEIPDB],
            ambiguous=True,
        )

    # --- 8. Base64 panjang tanpa padding → URLhaus ---
    if _BASE64ISH.match(key) and n > 50:
        return _hit(
            URLHAUS, "low",
            f"Charset Base64 sepanjang {n} karakter — kemungkinan Auth-Key URLhaus.",
            candidates=[ABUSEIPDB],
            ambiguous=True,
        )

    # --- 9. Fallback: VirusTotal (backward compatible) ---
    return _hit(
        VIRUSTOTAL,
        "low",
        f"Format tidak cocok pola mana pun ({n} karakter) — dipakai default VirusTotal. "
        "Jalankan test ping atau set api_type manual kalau ini key provider lain.",
        ambiguous=True,
    )


def resolve_api_type(api_key: str, manual: Optional[str] = None) -> dict:
    """
    Tentukan api_type final: override manual menang, kalau kosong baru auto-detect.
    Dipakai endpoint /keys/add dan /dashboard/keys/add.
    """
    forced = normalize_api_type(manual)
    if forced:
        meta = get_meta(forced)
        return {
            "api_type": forced,
            "confidence": "manual",
            "reason": f"Ditentukan manual sebagai {meta['label']}.",
            # Override manual = user yang tanggung jawab: cuma provider itu
            # yang boleh dites, jangan diam-diam dipindah ke provider lain.
            "candidates": [forced],
            "ambiguous": False,
            "label": meta["label"],
            "emoji": meta["emoji"],
            "color": meta["color"],
            "icon": meta["icon"],
            "auto_detected": False,
        }
    detected = detect_api_type(api_key)
    detected["auto_detected"] = True
    return detected
