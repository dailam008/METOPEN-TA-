# BAGIAN C — RENCANA MIGRASI BERTAHAP (FASE 0–11)

> Dasar untuk **BAB 3 (Metodologi Penelitian — tahapan pengembangan Agile SDLC)**.
> Estimasi memakai asumsi **4 jam kerja efektif per hari** (kuliah online + kerja di Jakarta).

---

## C.1 RINGKASAN FASE

| Fase | Nama | Hari | Risiko | Prasyarat |
|---|---|---|---|---|
| **0** | Persiapan & pembekuan lingkup | 2 | 🟢 Rendah | — |
| **1** | Bersih-bersih utang teknis | 2 | 🟢 Rendah | 0 |
| **2** | PostgreSQL + Alembic + migrasi data | 3 | 🟡 Sedang | 1 |
| **3** | Kerangka Flask (app factory) | 2 | 🟢 Rendah | 0 |
| **4** | Pindahkan models + services utuh | 2 | 🟢 Rendah | 2, 3 |
| **5** | Port endpoint lama ke Blueprint (sinkron) | 4 | 🟡 Sedang | 4 |
| **6** | Tabel `analyses` + persist + `response_time_ms` | 4 | 🟢 Rendah | 5 |
| **7** | Whitelist / Blacklist | 3 | 🟢 Rendah | 6 |
| **8** | **Celery + Redis (paralel)** | 6 | 🔴 **TINGGI** | 6 |
| **9** | Next.js — kerangka + port view lama | 6 | 🟡 Sedang | 5 |
| **10** | Laporan PDF | 4 | 🟡 Sedang | 6, 9 |
| **11** | Analytic Dashboard + pengujian + dokumentasi | 5 | 🟡 Sedang | 8, 9, 10 |
| | **TOTAL** | **43 hari kerja ≈ 9–10 minggu** | | |

Dengan ritme 4 hari kerja per minggu (menyesuaikan jadwal kerja), total
realistis ≈ **11 minggu ≈ 2,7 bulan** — masih aman dalam timeline 6 bulan PRD,
dengan sisa waktu untuk penulisan BAB 4–5.

---

## C.2 RINCIAN PER FASE

### FASE 0 — Persiapan & pembekuan lingkup · 2 hari · 🟢

**Dikerjakan**
- Buat repositori + struktur folder `backend/` dan `frontend/`
- Susun `docker-compose.yml`: PostgreSQL 16 + Redis 7
- Salin `.env` → `.env.example` (tanpa nilai rahasia)
- Konfirmasi tiga keputusan ke pembimbing dan **kunci**: Flask, Next.js, PostgreSQL, Celery+Redis

**File**: `docker-compose.yml` 🆕, `.env.example` 🆕, `.gitignore` 🆕, `README.md` 🆕

---

### FASE 1 — Bersih-bersih utang teknis · 2 hari · 🟢

Dikerjakan **di codebase FastAPI lama** yang masih jalan, supaya hasilnya bisa
langsung diuji sebelum diangkut.

**Dikerjakan** (mengacu audit §A.4)
- Hapus `analyze()` duplikat di `analyzer.py` baris 75–128
- Hapus `KeyResponse`, `_call_vt_api()`, `call_vt_with_cache()`, `fetch_keys_from_source()`
- Sambungkan `AUTO_REFRESH_INTERVAL_DAYS` → **TTL cache** di `_check_cache()`
- Satukan 4 endpoint bulk jadi 1

**File**: `analyzer.py`, `base_client.py`, `config.py`, `api/keys.py`, `api/scan.py`, `vt_client.py`, `scheduler/refresh_job.py`

> **Kenapa di awal:** TTL cache menutup risiko langsung terhadap KR3 (akurasi).
> Percuma mengukur akurasi 95% kalau sistem menyajikan hasil scan basi.

---

### FASE 2 — PostgreSQL + Alembic + migrasi data · 3 hari · 🟡

**Dikerjakan**
- Tambah cabang PostgreSQL di `build_engine()`
- Hapus jalur SQLite (`_prepare_sqlite_path`, PRAGMA, `IS_SQLITE`)
- Inisialisasi Alembic, buat revisi awal dari model yang ada
- Tulis `scripts/migrate_sqlite_to_postgres.py` — **pindahkan 33 API key + 11 cache**
- Ubah `JSON` → `JSONB`, enum Python → native `CREATE TYPE`

**File**: `config.py` 🟡, `database.py` 🟡, `models/*.py` 🟡, `migrations/` 🆕, `scripts/migrate_sqlite_to_postgres.py` 🆕

> **Aturan wajib:** jangan hapus `vt_proxy.db` setelah migrasi. Simpan sebagai
> arsip sampai sidang selesai. Verifikasi jumlah baris **sebelum dan sesudah**
> (33 key, 11 cache) dan catat di logbook — ini bukti validitas migrasi data
> untuk BAB 4.

---

### FASE 3 — Kerangka Flask · 2 hari · 🟢

**Dikerjakan**
- `create_app()` factory + `wsgi.py`
- `extensions.py`: session scoped, CORS, Migrate
- `database.py`: ganti `get_db()` generator FastAPI → `scoped_session` +
  `teardown_appcontext`
- Error handler terpusat pengganti `HTTPException`
- Endpoint `/health` sebagai uji hidup

**File**: `app/__init__.py` 🆕, `wsgi.py` 🆕, `extensions.py` 🆕, `api/errors.py` 🆕, `database.py` 🟡

> Fase ini **tidak bergantung pada Fase 1–2** dan bisa dikerjakan paralel bila
> ada waktu luang.

---

### FASE 4 — Pindahkan models + services utuh · 2 hari · 🟢

**Dikerjakan**
- Salin 12 file `services/` + 4 file `models/` + `utils/timeutil.py` **apa adanya**
- Jalankan uji asap: `key_detector`, `load_balancer`, `registry`, 4 client
- Tulis unit test pertama (`test_key_detector.py`) sebagai jaring pengaman

**File**: seluruh `app/services/`, `app/models/`, `app/utils/` ✅ + `tests/` 🆕

> Ini fase paling memuaskan: ±78% logika sistem berpindah tanpa disentuh.
> Kalau di sini banyak yang rusak, berarti asumsi audit meleset — hentikan dan
> evaluasi ulang sebelum lanjut.

---

### FASE 5 — Port endpoint lama ke Blueprint · 4 hari · 🟡

**Dikerjakan**
- `keys.py` → `keys_bp.py` (9 endpoint)
- `dashboard.py` → `dashboard_bp.py` (11 endpoint)
- `scan.py` → `scan_bp.py` (**masih sinkron** — Celery baru di Fase 8)
- Skema validasi pydantic dipindah ke `schemas/`

**File**: seluruh `app/api/` ❌ ditulis ulang, `schemas/` 🆕

> **Pertahankan endpoint tetap sinkron di fase ini.** Mengubah framework dan
> model eksekusi sekaligus membuat sumber kesalahan tidak bisa diisolasi.
> Di akhir fase ini sistem harus **sudah berfungsi penuh di Flask + PostgreSQL**.
> Ini *milestone* terpenting — tandai sebagai titik aman untuk kembali.

---

### FASE 6 — Tabel `analyses` + persist + `response_time_ms` · 4 hari · 🟢

**Dikerjakan**
- Model `Indicator`, `Analysis` + migrasi Alembic
- `risk_scorer.py`: angkat `build_final_verdict()` → `risk_score` (0–100) + `risk_level`
- `history_service.py`: setiap scan membuat/memperbarui `indicators`, menulis `analyses`
- **Ukur `response_time_ms`** dan mulai mengisi `api_usage_log`
- Endpoint `GET /api/analyses` + `GET /api/analyses/<id>`

**File**: `models/indicator.py` 🆕, `models/analysis.py` 🆕, `services/risk_scorer.py` 🆕, `services/history_service.py` 🆕, `api/analyses_bp.py` 🆕, `aggregator.py` 🟡

> **Fase penentu kelulusan pengujian.** Sebelum ini, tidak ada satu pun Key
> Result yang bisa diukur. Setelah ini, KR1/KR3/KR4 punya sumber data.
> **Kerjakan sebelum Celery**, supaya kamu punya angka *baseline sekuensial*
> untuk dibandingkan dengan hasil paralel di Fase 8 — itu menjadi grafik
> *before/after* di BAB 4.

---

### FASE 7 — Whitelist / Blacklist · 3 hari · 🟢

**Dikerjakan**
- Endpoint ubah `internal_status` + alasan + pencatat perubahan
- Cek whitelist/blacklist **sebelum** enqueue scan → hemat kuota API
- Penandaan otomatis: `risk_score >= 85` tiga kali berturut → usulkan BLACKLIST
  (usulan, **bukan** keputusan otomatis — analis tetap memutuskan)

**File**: `api/indicators_bp.py` 🆕, `services/history_service.py` 🟡

> Penandaan otomatis sengaja dibatasi pada "usulan" agar tidak melanggar batasan
> PRD (*monitoring & analysis only*, tanpa pencegahan otomatis).

---

### FASE 8 — Celery + Redis · 6 hari · 🔴 **RISIKO TERTINGGI**

**Dikerjakan**
- `celery_app.py`, 4 task provider, `chord` orkestrator, callback penggabung
- Ubah `POST /api/scan` → `202 Accepted` + `task_id`
- Endpoint polling status
- Celery Beat menggantikan APScheduler
- **Ukur ulang `response_time_ms`** → bandingkan dengan baseline Fase 6

**File**: `tasks/` 🆕 (4 file), `aggregator.py` 🟡, `scan_bp.py` 🟡, `scheduler/` ❌ dihapus

**Kenapa berisiko tinggi**
1. Model eksekusi berubah: sinkron → asinkron. Kontrak API ikut berubah,
   frontend harus menyesuaikan.
2. Session database di dalam worker **tidak boleh** memakai session request
   Flask — harus `session_scope()` sendiri. Ini sumber bug paling umum.
3. Menambah dua proses yang harus hidup saat demo sidang (Redis + worker).
4. Debugging task yang gagal lebih sulit daripada kode sinkron.

**Mitigasi**
- Simpan tag Git sebelum mulai, agar bisa kembali ke versi sinkron yang jalan
- Pertahankan jalur sinkron di balik *feature flag* (`USE_CELERY=false`) sebagai
  rencana cadangan saat demo
- Uji dengan 1 worker dulu, baru naikkan concurrency

---

### FASE 9 — Next.js · 6 hari · 🟡

**Dikerjakan**
- Inisialisasi Next.js 14 + React-Bootstrap + `lib/api.ts`
- Port view: Overview, Scan, Bulk, Keys, Cache
- Port logika JS dari `dashboard.html` (lihat tabel panen di §B.2)
- `useScanPolling.ts` untuk alur asinkron Fase 8

**File**: seluruh `frontend/` 🆕

> `dashboard.html` (5.400 baris) **jangan dibuang** — jadikan referensi visual
> dan sumber logika. Banyak bagian tinggal diterjemahkan ke JSX.

---

### FASE 10 — Laporan PDF · 4 hari · 🟡

**Dikerjakan**
- Template Jinja2 `analysis_report.html` (kop, ringkasan, vonis, detail 4 sumber, rekomendasi)
- `pdf_builder.py` + task `report.generate`
- Model `Report` + endpoint generate/download
- **Ukur `generation_ms`** → bukti KR2 (< 5 detik)

**File**: `reports/` 🆕, `models/report.py` 🆕, `api/reports_bp.py` 🆕, `tasks/report_tasks.py` 🆕

> **Catatan teknis penting:** WeasyPrint memerlukan pustaka GTK di Windows dan
> sering merepotkan saat instalasi. Bila terhambat lebih dari setengah hari,
> **langsung ganti ke ReportLab** — layout lebih manual, tetapi tanpa dependensi
> sistem. Jangan habiskan waktu di sini; PDF bukan kontribusi ilmiah utama.

---

### FASE 11 — Analytics + pengujian + dokumentasi · 5 hari · 🟡

**Dikerjakan**
- `analytics_service.py`: tren harian, komposisi vonis, temuan per sumber, top indikator
- 3 komponen chart di Next.js
- Pengujian: blackbox (matriks kasus uji), performa (KR1/KR2), akurasi (KR3), efisiensi cache (KR4)
- Dokumentasi kode + diagram untuk BAB 3

**File**: `services/analytics_service.py` 🆕, `api/analytics_bp.py` 🆕, `frontend/components/charts/` 🆕, `tests/` 🟡

---

## C.3 DAFTAR FILE: PINDAH UTUH vs DITULIS ULANG

### ✅ PINDAH UTUH — 17 file (nol perubahan)

```
app/services/key_detector.py          app/services/registry.py
app/services/key_validator.py         app/services/load_balancer.py
app/services/base_client.py           app/services/analyzer.py *
app/services/vt_client.py             app/utils/timeutil.py
app/services/urlhaus_client.py        app/utils/__init__.py
app/services/abuseipdb_client.py      app/services/__init__.py
app/services/mxtoolbox_client.py      app/api/__init__.py
app/models/__init__.py                (+ 2 __init__.py kosong lainnya)
```
\* `analyzer.py` pindah utuh **setelah** dead code dihapus di Fase 1.

### 🟡 ADAPTASI — 6 file

| File | Sifat perubahan | Perkiraan |
|---|---|---|
| `config.py` | + PostgreSQL/Redis/Celery, − SQLite | ~30% |
| `database.py` | Engine Postgres, pola session Flask | ~50% |
| `models/api_key.py` | Enum native PostgreSQL | ~10% |
| `models/cache.py` | JSONB + kolom `expires_at` | ~15% |
| `models/usage_log.py` | JSONB + 3 kolom baru | ~25% |
| `services/aggregator.py` | `run_multi_scan()` → orkestrasi Celery | ~40% |

### ❌ DITULIS ULANG — 6 file

| File lama | File baru | Alasan |
|---|---|---|
| `app/main.py` | `app/__init__.py` + `wsgi.py` | FastAPI → Flask factory |
| `api/keys.py` | `api/keys_bp.py` | APIRouter → Blueprint |
| `api/dashboard.py` | `api/dashboard_bp.py` | idem |
| `api/scan.py` | `api/scan_bp.py` | idem + asinkron |
| `scheduler/__init__.py` | `tasks/celery_app.py` (beat) | APScheduler → Celery Beat |
| `dashboard.html` | `frontend/` | HTML tunggal → Next.js |

**Catatan:** meskipun 6 file "ditulis ulang", **isi logikanya dipertahankan**.
Yang berubah hanya lapisan dekorator, validasi, dan penanganan error. Perkiraan
logika yang benar-benar baru: < 20% dari file-file tersebut.

---

## C.4 URUTAN MIGRASI AMAN

```text
        ┌─────────┐
        │ FASE 0  │ Persiapan
        └────┬────┘
             ├──────────────────┐
        ┌────▼────┐        ┌────▼────┐
        │ FASE 1  │        │ FASE 3  │  ← boleh paralel
        │ Bersih2 │        │ Kerangka│
        └────┬────┘        │  Flask  │
        ┌────▼────┐        └────┬────┘
        │ FASE 2  │             │
        │Postgres │             │
        └────┬────┘             │
             └────────┬─────────┘
                 ┌────▼────┐
                 │ FASE 4  │ Pindah services (inti aman)
                 └────┬────┘
                 ┌────▼────┐
                 │ FASE 5  │ ★ TITIK AMAN — sistem jalan penuh di Flask
                 └────┬────┘
                 ┌────▼────┐
                 │ FASE 6  │ ★ analyses + baseline pengukuran
                 └────┬────┘
            ┌─────────┼─────────┐
       ┌────▼───┐┌────▼───┐┌────▼───┐
       │ FASE 7 ││ FASE 8 ││ FASE 9 │  ← 7 & 9 boleh paralel dgn 8
       │ W/B    ││ CELERY ││Next.js │
       └────┬───┘└────┬───┘└────┬───┘
            └─────────┼─────────┘
                 ┌────▼────┐
                 │ FASE 10 │ PDF
                 └────┬────┘
                 ┌────▼────┐
                 │ FASE 11 │ Analytics + uji + dokumentasi
                 └─────────┘
```

### Tiga aturan main

1. **Jangan lewati Fase 5.** Sistem harus terbukti jalan penuh di Flask +
   PostgreSQL sebelum menyentuh Celery. Kalau dua perubahan besar digabung,
   kesalahan tidak bisa dilacak sumbernya.
2. **Fase 6 mendahului Fase 8.** Tanpa baseline sekuensial yang terukur, klaim
   "paralel mempercepat X%" di BAB 4 tidak punya pembanding — dan angka itu
   hilang selamanya begitu Celery masuk.
3. **Tandai Git di setiap akhir fase** (`git tag fase-5-selesai`). Fase 8
   berisiko tinggi; kemampuan kembali ke titik aman lebih berharga daripada
   kecepatan.

---

## C.5 PEMETAAN FASE → TIMELINE PRD

| Bulan PRD | Fokus PRD | Fase yang dikerjakan |
|---|---|---|
| Bulan 1 | Proposal, setup Celery/Redis & Flask | 0, 1, 2, 3 |
| Bulan 2 | Integrasi API, skoring, skema PostgreSQL | 4, 5, 6, 7 |
| Bulan 3 | Dashboard UI, analitik, export PDF | 8, 9, 10, 11 |
| Bulan 4 | Uji coba (blackbox, performa, akurasi) | Pengujian lanjutan |
| Bulan 5 | Laporan TA | Penulisan |
| Bulan 6 | Sidang | — |

Karena mata kuliah Metopen hanya mencakup **BAB 1–3**, maka yang wajib selesai
untuk Metopen adalah **dokumen perancangan** (Bagian A, B, C ini + outline
Bagian D) — bukan implementasinya. Implementasi Fase 0–11 dieksekusi pada
semester berikutnya untuk BAB 4–5.

**Yang bisa dicuri start dari sekarang tanpa risiko:** Fase 0 dan Fase 1.
Keduanya tidak mengubah arsitektur, hanya merapikan dan menyiapkan — aman
dikerjakan sebelum kuliah dimulai.
