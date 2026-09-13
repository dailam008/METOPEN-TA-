# BAGIAN A — AUDIT KODE INTI

> Dasar untuk **BAB 3 (Desain Sistem)**.
> Audit dilakukan atas 27 file Python di `app/` pada kondisi sebelum migrasi.

---

## A.1 TEMUAN UTAMA

**Lapisan logika bisnis sepenuhnya bebas framework.**

Hasil pemindaian `grep -rln "fastapi" app/`:

```
app/api/dashboard.py
app/api/keys.py
app/api/scan.py
app/main.py
```

Hanya **4 dari 27 file** yang mengimpor FastAPI, dan keempatnya adalah lapisan
HTTP (routing + validasi request). Seluruh isi `app/services/` (12 file),
`app/models/` (4 file), dan `app/utils/` (1 file) **tidak menyentuh FastAPI
sama sekali**.

Konsekuensi untuk migrasi ke Flask:

| Lapisan | Jumlah file | Nasib saat migrasi |
|---|---|---|
| Logika bisnis (`services/`) | 12 | **Pindah utuh** — nol perubahan |
| Model data (`models/`) | 4 | Pindah utuh + penyesuaian tipe PostgreSQL |
| Utilitas (`utils/`) | 1 | **Pindah utuh** — nol perubahan |
| Konfigurasi | 2 | Adaptasi sedang |
| Lapisan HTTP (`api/`, `main.py`) | 4 | **Ditulis ulang** (Blueprint Flask) |
| Scheduler | 2 | Diganti Celery Beat |

**±78% baris kode inti dapat dipindahkan tanpa disentuh.** Ini menjadi
argumen kuat di BAB 3: migrasi framework yang disarankan pembimbing tidak
membuang hasil kerja yang sudah ada, karena arsitekturnya sejak awal
memisahkan logika dari framework.

---

## A.2 TABEL AUDIT LENGKAP

Legenda kolom "Bisa Pindah Utuh?":
- ✅ **YA** — salin file, nol perubahan
- 🟡 **ADAPTASI** — sebagian besar dipertahankan, ada penyesuaian
- ❌ **TULIS ULANG** — terikat framework lama

### A.2.1 Lapisan Services (logika bisnis)

| File | Fungsi/Class Utama | Dependencies | Bisa Pindah Utuh? | Catatan |
|---|---|---|---|---|
| `services/key_detector.py` | `detect_api_type()`, `resolve_api_type()`, `normalize_api_type()`, `get_meta()`, konstanta `SOURCE_META` | `re`, `typing` | ✅ **YA** | **Pure Python murni.** Nol dependensi eksternal. Aset paling portabel di project. |
| `services/analyzer.py` | `analyze()`, `_get_sandbox_verdicts()`, `_get_malicious_relations()` | `datetime`, `typing` | ✅ **YA** | Pure Python. ⚠️ Ada **dead code** — lihat §A.4. |
| `services/load_balancer.py` | `LoadBalancer.get_best_key()`, `.count_active()`, `.mark_success()`, `.mark_error()`, `._type_filter()` | SQLAlchemy, `models.VTAPIKey`, `key_detector`, `timeutil` | ✅ **YA** | Menerima `Session` sebagai argumen konstruktor — tidak peduli siapa yang membuat session itu. |
| `services/base_client.py` | `BaseThreatClient` (cache, failover, `test_key()`, `health_check_key()`, `envelope()`) | `httpx`, SQLAlchemy, `config`, `models`, `key_detector`, `load_balancer`, `timeutil` | ✅ **YA** | Jantung sistem. `httpx` sinkron — justru **cocok** untuk Celery worker yang memang sinkron. |
| `services/vt_client.py` | `VTClient.scan()`, `.report()`, `.health_check_all_keys()` | SQLAlchemy, `config`, `models`, `analyzer`, `base_client`, `key_detector` | ✅ **YA** | ⚠️ Alias lama `_call_vt_api()` & `call_vt_with_cache()` sudah tidak dipakai siapa pun — kandidat hapus. |
| `services/urlhaus_client.py` | `URLhausClient.scan()`, `.report()`, `._auth_is_enforced()` | `time`, `urllib.parse`, SQLAlchemy, `config`, `base_client`, `key_detector` | ✅ **YA** | Berisi *control probe* anti-false-positive. Jangan disederhanakan saat migrasi. |
| `services/abuseipdb_client.py` | `AbuseIPDBClient.scan()`, `.report()`, `CATEGORY_MAP` | SQLAlchemy, `config`, `base_client`, `key_detector` | ✅ **YA** | — |
| `services/mxtoolbox_client.py` | `MxToolboxClient.lookup()`, `.report()`, `.domain_of()` | SQLAlchemy, `config`, `base_client`, `key_detector` | ✅ **YA** | — |
| `services/registry.py` | `get_client()`, `health_check_key()`, `key_stats()`, `CLIENTS`, `SOURCE_ORDER` | SQLAlchemy, `models`, 4 client, `key_detector` | ✅ **YA** | Satu-satunya tempat mapping `api_type → class`. Titik ekstensi kalau nanti tambah API kelima. |
| `services/key_validator.py` | `identify_key()`, `test_key()`, `revalidate_stored_key()`, `apply_to_key()` | `typing`, SQLAlchemy, `models`, `base_client`, `key_detector`, `registry` (lazy) | ✅ **YA** | Impor `registry` sengaja di dalam fungsi untuk menghindari circular import — pertahankan pola ini. |
| `services/aggregator.py` | `detect_input_type()`, `run_multi_scan()`, `build_final_verdict()`, `ROUTING` | `re`, SQLAlchemy, `base_client`, `key_detector`, `registry`, `timeutil` | 🟡 **ADAPTASI** | `detect_input_type()` & `build_final_verdict()` pindah utuh. **`run_multi_scan()` harus dirombak** jadi orkestrasi Celery (saat ini `for` loop sekuensial, baris 127). |
| `services/__init__.py` | — | — | ✅ **YA** | File kosong (0 byte). |

### A.2.2 Lapisan Models

| File | Fungsi/Class Utama | Dependencies | Bisa Pindah Utuh? | Catatan |
|---|---|---|---|---|
| `models/api_key.py` | `VTAPIKey` (15 kolom, 3 index) | SQLAlchemy, `database.Base`, `timeutil` | 🟡 **ADAPTASI** | `Enum('fresh','rate_limited','dead','unknown', name=...)` → jadi native ENUM di PostgreSQL. `name=` wajib dipertahankan. |
| `models/cache.py` | `CacheScan`, `ScanType` (enum) | SQLAlchemy, `database.Base`, `timeutil` | 🟡 **ADAPTASI** | `JSON` → **`JSONB`**. Unique constraint `(identifier, scan_type, source)` dipertahankan. |
| `models/usage_log.py` | `APIUsageLog` (9 kolom) | SQLAlchemy, `database.Base`, `timeutil` | 🟡 **ADAPTASI** | `JSON` → `JSONB`. ⚠️ Tabel ada tapi **tidak pernah ditulis** — lihat §A.4. |
| `models/__init__.py` | Re-export 4 model | — | ✅ **YA** | Tambah 3 model baru (`Indicator`, `Analysis`, `Report`). |

### A.2.3 Lapisan Konfigurasi & Infrastruktur

| File | Fungsi/Class Utama | Dependencies | Bisa Pindah Utuh? | Catatan |
|---|---|---|---|---|
| `utils/timeutil.py` | `now_local()` | `datetime` | ✅ **YA** | Pure Python. Menyelesaikan masalah beda timezone SQLite (UTC) vs MySQL (lokal). **Tetap relevan di PostgreSQL** — pertahankan. |
| `config.py` | `Settings` (pydantic-settings), `_resolve_database_url()` | `pydantic_settings`, `pydantic`, `dotenv`, `os` | 🟡 **ADAPTASI** | `pydantic-settings` **bukan** milik FastAPI — jalan normal di Flask. Perlu: tambah `POSTGRES_URL`, `REDIS_URL`, `CELERY_*`, `CACHE_TTL_DAYS`; hapus cabang SQLite. |
| `database.py` | `build_engine()`, `SessionLocal`, `get_db()`, `init_db()` | SQLAlchemy, `config`, `os` | 🟡 **ADAPTASI** | **Titik adaptasi utama.** `build_engine()` sudah dual-backend → tinggal tambah cabang PostgreSQL. `get_db()` bergaya FastAPI dependency (generator `yield`) → diganti `scoped_session` + `teardown_appcontext` Flask. Blok PRAGMA SQLite dihapus. |

### A.2.4 Lapisan yang DITULIS ULANG

| File | Fungsi/Class Utama | Dependencies | Bisa Pindah Utuh? | Catatan |
|---|---|---|---|---|
| `main.py` | `FastAPI()`, CORS, router, startup/shutdown event | `fastapi`, `uvicorn`, SQLAlchemy | ❌ **TULIS ULANG** | Jadi `create_app()` factory + `wsgi.py`. |
| `api/keys.py` | 9 endpoint (add, list, detect, validate, remove, activate, type) | `fastapi`, `pydantic`, SQLAlchemy, `key_detector`, `key_validator` | ❌ **TULIS ULANG** | **Logikanya dipertahankan**, hanya dekorator & error handling yang berubah: `APIRouter` → `Blueprint`, `HTTPException` → `abort()`/error handler, `Depends(get_db)` → session global. ⚠️ `KeyResponse` tidak terpakai — hapus. |
| `api/dashboard.py` | 11 endpoint (keys CRUD, validate, health-check, cache, stats) | idem | ❌ **TULIS ULANG** | Idem. Fungsi `_verified_flag()` & `_verification_label()` pindah utuh. |
| `api/scan.py` | 10 endpoint (multi, detect, 4 single, 4 bulk) | `fastapi`, `pydantic`, SQLAlchemy, `aggregator`, `vt_client`, `analyzer` | ❌ **TULIS ULANG** | ⚠️ 4 endpoint bulk hampir identik (duplikasi ±60 baris) — saat ditulis ulang, satukan jadi 1 endpoint generik. |
| `api/__init__.py` | — | — | ✅ **YA** | Kosong. |
| `scheduler/__init__.py` | `start_scheduler()`, `stop_scheduler()` | `apscheduler` | ❌ **TULIS ULANG** | Diganti **Celery Beat**. |
| `scheduler/refresh_job.py` | `refresh_api_keys()`, `add_keys_from_source()` | SQLAlchemy, `models`, `config` | 🟡 **ADAPTASI** | Isi `refresh_api_keys()` dipertahankan, dibungkus jadi Celery task. ⚠️ `fetch_keys_from_source()` selalu return `[]` — fitur mati, hapus. |
| `app/__init__.py` | — | — | ❌ | Jadi `create_app()` factory Flask. |

---

## A.3 REKAP DEPENDENSI

### Dependensi ke FastAPI (harus dilepas)
| File | Bentuk dependensi |
|---|---|
| `app/main.py` | `FastAPI`, `CORSMiddleware`, `@app.on_event`, `uvicorn` |
| `app/api/keys.py` | `APIRouter`, `Depends`, `HTTPException` |
| `app/api/dashboard.py` | `APIRouter`, `Depends`, `HTTPException` |
| `app/api/scan.py` | `APIRouter`, `Depends`, `HTTPException` |

**Total: 4 file.** Tidak ada file lain yang terkontaminasi.

### Dependensi ke SQLAlchemy (tetap dipakai di Flask)
19 file. SQLAlchemy adalah ORM yang framework-agnostic — **tidak ada yang perlu
diubah** selain `database.py`. Opsi `Flask-SQLAlchemy` sengaja **tidak
direkomendasikan**, karena akan memaksa seluruh model ditulis ulang dengan gaya
`db.Model`. Pakai SQLAlchemy murni + `Flask-Migrate` saja.

### Dependensi ke SQLite (harus dimigrasi)
| File | Baris | Bentuk dependensi |
|---|---|---|
| `config.py` | 13, 19, 23, 48–49, 60, 65–66 | `DEFAULT_SQLITE_URL`, `SQLITE_URL`, cabang `DB_BACKEND=sqlite`, properti `IS_SQLITE` |
| `database.py` | 10–17, 25–48 | `_prepare_sqlite_path()`, `check_same_thread=False`, 4 PRAGMA (`foreign_keys`, `journal_mode=WAL`, `synchronous`, `busy_timeout`) |

**Total: 2 file.** Model tidak memakai tipe khusus SQLite, sehingga migrasi
skema relatif aman.

### Dependensi ke pydantic
| File | Peran | Nasib |
|---|---|---|
| `config.py` | `BaseSettings` | **Tetap** — pydantic-settings jalan di Flask |
| `api/*.py` (3 file) | Request body schema | Tetap dipakai sebagai validator manual di dalam Blueprint |

---

## A.4 DAFTAR DEAD CODE & DUPLIKASI

Wajib dibereskan sebelum tahap dokumentasi kode, karena penguji cenderung
menanyakan kode yang tidak terpakai.

| # | Lokasi | Masalah | Dampak | Tindakan |
|---|---|---|---|---|
| 1 | `services/analyzer.py:75` dan `:186` | **Dua definisi `def analyze()`.** Yang pertama (baris 75–128) tertimpa total oleh yang kedua, dan bahkan **tidak punya `return`** | Tidak error (Python memakai definisi terakhir), tapi 54 baris kode mati | **Hapus baris 75–128** |
| 2 | `models/usage_log.py` | Tabel `APIUsageLog` terdaftar, tapi **tidak ada satu pun kode yang menulis ke sana** (0 baris di DB) | **KR1 (<15 detik) tidak bisa diukur** | Sambungkan saat Fase 5 |
| 3 | `config.py:30` | `AUTO_REFRESH_INTERVAL_DAYS` didefinisikan tapi tidak dipakai di mana pun | Cache tidak pernah kedaluwarsa → ancaman ke KR3 (akurasi) | Sambungkan jadi TTL cache (Fase 1) |
| 4 | `base_client.py:_check_cache()` | Query cache **tidak memfilter umur data** | Hasil scan lama disajikan sebagai hasil terbaru | Tambah filter `scan_date >= now - TTL` |
| 5 | `scheduler/refresh_job.py:63` | `fetch_keys_from_source()` selalu `return []` — fitur placeholder | Job terjadwal tiap 7 hari yang tidak melakukan apa pun | Hapus |
| 6 | `api/keys.py:48` | `class KeyResponse(BaseModel)` tidak pernah dipakai | Kode mati | Hapus |
| 7 | `services/vt_client.py` | `_call_vt_api()` & `call_vt_with_cache()` — alias kompatibilitas, sudah tidak dipanggil siapa pun | Kode mati | Hapus saat migrasi |
| 8 | `api/scan.py:137–203` | 4 endpoint bulk (`/bulk/hash`, `/bulk/url`, `/bulk/ip`, `/bulk/domain`) isinya hampir identik | Duplikasi ±60 baris | Satukan jadi 1 endpoint saat ditulis ulang |

---

## A.5 KESIMPULAN AUDIT UNTUK BAB 3

1. Migrasi FastAPI → Flask **tidak membuang logika bisnis**: 17 dari 27 file
   berpindah tanpa perubahan, 6 file adaptasi ringan, 4 file ditulis ulang.
2. Titik risiko teknis terletak pada **`database.py`** (pola session) dan
   **`aggregator.py:run_multi_scan()`** (sekuensial → paralel), bukan pada
   integrasi API yang sudah matang.
3. Terdapat 8 butir utang teknis yang harus dibereskan; dua di antaranya
   (butir 2 dan 4) **berdampak langsung pada kemampuan mengukur Key Results**,
   sehingga harus masuk fase awal, bukan fase akhir.
