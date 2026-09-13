# BAGIAN B — STRUKTUR FOLDER, SKEMA DATABASE & CELERY

> Dasar untuk **BAB 3 (Arsitektur Sistem & Perancangan Basis Data)**.

---

## B.0 ARSITEKTUR TARGET

```text
┌──────────────────────────────────────────────────────────┐
│  FRONTEND — Next.js 14 (App Router) + React Bootstrap 5   │
│  Port 3000                                               │
└───────────────────────┬──────────────────────────────────┘
                        │ REST/JSON (fetch)
┌───────────────────────▼──────────────────────────────────┐
│  BACKEND — Flask 3 (Blueprint) + Gunicorn                │
│  Port 5000                                               │
│  • Validasi request      • PDF Report Generator          │
│  • Cek Whitelist/Blacklist sebelum enqueue               │
└──────┬────────────────────────────────────┬──────────────┘
       │ (1) enqueue task                   │ (4) baca hasil
┌──────▼─────────────────┐        ┌─────────▼──────────────┐
│  REDIS 7               │        │  POSTGRESQL 16         │
│  db0 = broker          │        │  indicators            │
│  db1 = result backend  │        │  analyses              │
└──────┬─────────────────┘        │  reports               │
       │ (2) consume              │  vt_api_keys           │
┌──────▼─────────────────┐        │  cache_scans           │
│  CELERY WORKERS        │───(3)──▶  api_usage_log         │
│  queue: intel (4 task  │        └────────────────────────┘
│         paralel)       │
│  queue: scan  (chord)  │
│  queue: report (PDF)   │
└──┬──────┬──────┬─────┬─┘
   │      │      │     │
┌──▼──┐┌──▼───┐┌─▼───┐┌▼──────┐
│ VT  ││URLhaus││Abuse││MXTool │
│ API ││ API  ││IPDB ││box    │
└─────┘└──────┘└─────┘└───────┘
```

**Perubahan mendasar vs sistem lama:** empat pemanggilan API yang sekarang
berjalan berurutan dalam satu `for` loop (`aggregator.py:127`) dipecah menjadi
empat Celery task yang dieksekusi bersamaan, lalu disatukan kembali oleh satu
callback. Inilah yang mewujudkan klaim "paralel tanpa blocking" pada PRD.

---

## B.1 STRUKTUR FOLDER BACKEND (FLASK)

```text
backend/
├── app/
│   ├── __init__.py                 # 🆕 create_app() — application factory
│   ├── config.py                   # 🟡 PINDAH + tambah POSTGRES/REDIS/CELERY
│   ├── extensions.py               # 🆕 objek global: db session, migrate, cors, celery
│   ├── database.py                 # 🟡 ADAPTASI — engine Postgres + scoped_session
│   │
│   ├── models/                     # ═══ PINDAH UTUH (+3 model baru) ═══
│   │   ├── __init__.py
│   │   ├── api_key.py              # ✅ VTAPIKey
│   │   ├── cache.py                # 🟡 CacheScan (JSON → JSONB)
│   │   ├── usage_log.py            # 🟡 APIUsageLog (JSON → JSONB)
│   │   ├── indicator.py            # 🆕 Indicator + InternalStatus enum
│   │   ├── analysis.py             # 🆕 Analysis
│   │   └── report.py               # 🆕 Report
│   │
│   ├── services/                   # ═══ PINDAH UTUH 100% ═══
│   │   ├── __init__.py
│   │   ├── base_client.py          # ✅ tanpa perubahan
│   │   ├── vt_client.py            # ✅
│   │   ├── urlhaus_client.py       # ✅
│   │   ├── abuseipdb_client.py     # ✅
│   │   ├── mxtoolbox_client.py     # ✅
│   │   ├── registry.py             # ✅
│   │   ├── load_balancer.py        # ✅
│   │   ├── key_detector.py         # ✅
│   │   ├── key_validator.py        # ✅
│   │   ├── analyzer.py             # ✅ (hapus dead code dulu)
│   │   ├── aggregator.py           # 🟡 run_multi_scan() dirombak
│   │   ├── history_service.py      # 🆕 whitelist/blacklist + simpan analisis
│   │   ├── risk_scorer.py          # 🆕 angkat build_final_verdict() → skor 0-100
│   │   └── analytics_service.py    # 🆕 agregasi time-series untuk chart
│   │
│   ├── api/                        # ═══ DITULIS ULANG (Blueprint) ═══
│   │   ├── __init__.py             # register_blueprints()
│   │   ├── keys_bp.py              # ← dari api/keys.py
│   │   ├── dashboard_bp.py         # ← dari api/dashboard.py
│   │   ├── scan_bp.py              # ← dari api/scan.py (+ endpoint polling)
│   │   ├── indicators_bp.py        # 🆕 whitelist/blacklist
│   │   ├── analyses_bp.py          # 🆕 history
│   │   ├── reports_bp.py           # 🆕 generate & download PDF
│   │   ├── analytics_bp.py         # 🆕 data chart
│   │   └── errors.py               # 🆕 error handler terpusat (ganti HTTPException)
│   │
│   ├── schemas/                    # 🆕 validasi request/response (pydantic v2)
│   │   ├── scan_schema.py
│   │   ├── key_schema.py
│   │   └── indicator_schema.py
│   │
│   ├── tasks/                      # 🆕 ═══ CELERY ═══
│   │   ├── __init__.py
│   │   ├── celery_app.py           # instance + konfigurasi
│   │   ├── scan_tasks.py           # 4 task provider + chord callback
│   │   ├── report_tasks.py         # generate PDF async
│   │   └── maintenance_tasks.py    # ← dari scheduler/refresh_job.py
│   │
│   ├── reports/                    # 🆕 PDF
│   │   ├── pdf_builder.py
│   │   └── templates/
│   │       └── analysis_report.html
│   │
│   └── utils/
│       ├── __init__.py
│       └── timeutil.py             # ✅ PINDAH UTUH
│
├── migrations/                     # 🆕 Flask-Migrate (Alembic)
│   └── versions/
├── scripts/
│   └── migrate_sqlite_to_postgres.py   # 🆕 pindahkan 33 key + 11 cache
├── tests/                          # 🆕
│   ├── test_key_detector.py
│   ├── test_aggregator.py
│   └── test_risk_scorer.py
├── storage/
│   └── reports/                    # output PDF (di-gitignore)
├── wsgi.py                         # 🆕 entrypoint Gunicorn
├── celery_worker.py                # 🆕 entrypoint worker
├── .env.example                    # 🆕 template tanpa kredensial
└── requirements.txt                # 🟡 + flask, celery, redis, psycopg2, weasyprint
```

### Isi `requirements.txt` yang direncanakan

```text
# Web
flask==3.0.3
flask-cors==4.0.1
flask-migrate==4.0.7
gunicorn==22.0.0

# Data
sqlalchemy==2.0.25          # ← versi dipertahankan, model tidak perlu diubah
psycopg2-binary==2.9.9
alembic==1.13.1

# Async
celery[redis]==5.4.0
redis==5.0.4

# Tetap dari sistem lama
httpx==0.27.0               # ← dipakai semua client, jangan diganti
pydantic==2.6.0
pydantic-settings==2.2.0
python-dotenv==1.0.1

# Laporan
weasyprint==62.3            # alternatif: reportlab==4.2.0 (lihat catatan Fase 9)
jinja2==3.1.4
```

---

## B.2 STRUKTUR FOLDER FRONTEND (NEXT.JS)

Catatan: PRD menetapkan **Bootstrap 5**. Agar tidak menimbulkan deviasi kedua
dari dokumen yang sudah disetujui, dipakai **React-Bootstrap** (binding resmi
Bootstrap 5 untuk React), bukan Tailwind.

```text
frontend/
├── app/                            # App Router (Next.js 14)
│   ├── layout.tsx                  # shell + sidebar + theme switcher
│   ├── page.tsx                    # Overview (kartu statistik)
│   ├── scan/
│   │   ├── page.tsx                # Instant Scan (single)
│   │   └── bulk/page.tsx           # Bulk Scan
│   ├── history/
│   │   ├── page.tsx                # daftar analisis
│   │   └── [id]/page.tsx           # detail + tombol Export PDF
│   ├── indicators/page.tsx         # Whitelist / Blacklist
│   ├── analytics/page.tsx          # Tren ancaman (chart)
│   ├── reports/page.tsx            # riwayat PDF
│   ├── keys/page.tsx               # manajemen API key
│   └── api/health/route.ts         # proxy health check
│
├── components/
│   ├── layout/{Sidebar,Topbar,ThemeToggle}.tsx
│   ├── scan/
│   │   ├── ScanInput.tsx           # + auto-detect tipe input (port dari dashboard.html)
│   │   ├── SourceBox.tsx           # kotak per API (VT/URLhaus/AbuseIPDB/MXToolbox)
│   │   ├── VerdictCard.tsx         # vonis akhir + rekomendasi
│   │   └── ScanProgress.tsx        # 🆕 progress polling task Celery
│   ├── indicators/StatusBadge.tsx  # WHITELIST/BLACKLIST/UNKNOWN
│   ├── charts/
│   │   ├── ThreatTrendChart.tsx    # line — tren harian
│   │   ├── VerdictDonut.tsx        # donut — komposisi vonis
│   │   └── SourceBarChart.tsx      # bar — temuan per sumber
│   └── ui/{DataTable,Pager,Toast,ConfirmDialog}.tsx
│
├── lib/
│   ├── api.ts                      # wrapper fetch ke Flask
│   ├── types.ts                    # tipe TS mirror skema backend
│   ├── detectInputType.ts          # port dari dashboard.html
│   └── hooks/
│       ├── useScanPolling.ts       # 🆕 polling status task
│       └── useKeys.ts
│
├── public/
├── next.config.js                  # rewrites /api → http://localhost:5000
├── tsconfig.json
└── package.json
```

### Aset dari `dashboard.html` yang dipanen (jangan ditulis dari nol)

| Bagian di `dashboard.html` | Tujuan di Next.js |
|---|---|
| `detectInputType()`, `detectScanType()` | `lib/detectInputType.ts` |
| `detectKeyType()` (cermin key_detector) | `lib/detectKeyType.ts` |
| `SOURCE_META`, `apiChip()`, `verifyPill()` | `components/ui/` |
| Struktur kotak hasil per sumber | `components/scan/SourceBox.tsx` |
| `sortRows()`, `paginate()`, `pagerHtml()` | `components/ui/DataTable.tsx` |
| Palet warna + token tema CSS | `app/globals.css` |

---

## B.3 SKEMA POSTGRESQL LENGKAP

```sql
-- ============================================================
-- ENUM TYPES
-- ============================================================
CREATE TYPE internal_status_enum AS ENUM ('WHITELIST', 'BLACKLIST', 'UNKNOWN');
CREATE TYPE indicator_type_enum  AS ENUM ('URL', 'IP', 'DOMAIN', 'HASH', 'EMAIL');
CREATE TYPE risk_level_enum      AS ENUM ('CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE health_status_enum   AS ENUM ('fresh', 'rate_limited', 'dead', 'unknown');
CREATE TYPE scan_type_enum       AS ENUM ('hash', 'url', 'ip', 'domain', 'email');

-- ============================================================
-- TABEL BARU 1 — INDICATORS  (Objective #3: Whitelist/Blacklist)
-- ============================================================
CREATE TABLE indicators (
    id                SERIAL PRIMARY KEY,
    indicator_value   VARCHAR(2048) NOT NULL UNIQUE,
    indicator_type    indicator_type_enum NOT NULL,
    internal_status   internal_status_enum NOT NULL DEFAULT 'UNKNOWN',
    status_reason     TEXT,                  -- alasan analis menandai
    status_changed_by VARCHAR(100),
    status_changed_at TIMESTAMP,
    times_analyzed    INTEGER NOT NULL DEFAULT 0,   -- bukti KR4
    first_seen_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ind_status ON indicators (internal_status);
CREATE INDEX idx_ind_type   ON indicators (indicator_type);
CREATE INDEX idx_ind_value  ON indicators USING hash (indicator_value);

-- ============================================================
-- TABEL BARU 2 — ANALYSES  (history append-only + bukti KR1 & KR3)
-- ============================================================
CREATE TABLE analyses (
    id                 SERIAL PRIMARY KEY,
    indicator_id       INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,

    risk_score         INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level         risk_level_enum,
    final_verdict      VARCHAR(20),          -- MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN
    recommendation     VARCHAR(50),          -- BLOCK / MONITOR / ALLOW / ...

    virustotal_result  JSONB,
    urlhaus_result     JSONB,
    abuseipdb_result   JSONB,
    mxtoolbox_result   JSONB,

    sources_called     INTEGER NOT NULL DEFAULT 0,
    sources_from_cache INTEGER NOT NULL DEFAULT 0,   -- bukti KR4
    response_time_ms   INTEGER,                      -- bukti KR1
    celery_task_id     VARCHAR(64),                  -- untuk polling status
    task_status        VARCHAR(20) DEFAULT 'PENDING',-- PENDING/STARTED/SUCCESS/FAILURE
    analyzed_by        VARCHAR(100),
    analyzed_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ana_indicator ON analyses (indicator_id, analyzed_at DESC);
CREATE INDEX idx_ana_date      ON analyses (analyzed_at DESC);
CREATE INDEX idx_ana_risk      ON analyses (risk_level, analyzed_at DESC);
CREATE INDEX idx_ana_task      ON analyses (celery_task_id);
CREATE INDEX idx_ana_vt_gin    ON analyses USING gin (virustotal_result);

-- ============================================================
-- TABEL BARU 3 — REPORTS  (Objective #4, KR2)
-- ============================================================
CREATE TABLE reports (
    id             SERIAL PRIMARY KEY,
    analysis_id    INTEGER REFERENCES analyses(id) ON DELETE SET NULL,
    report_type    VARCHAR(20) NOT NULL DEFAULT 'SINGLE',  -- SINGLE / PERIODIC
    period_start   DATE,
    period_end     DATE,
    generated_by   VARCHAR(100),
    pdf_file_path  VARCHAR(500) NOT NULL,
    file_size_kb   INTEGER,
    generation_ms  INTEGER,                 -- bukti KR2 (< 5 detik)
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_rep_analysis ON reports (analysis_id);
CREATE INDEX idx_rep_date     ON reports (created_at DESC);

-- ============================================================
-- TABEL EXISTING 1 — VT_API_KEYS  (dimigrasi apa adanya, 33 baris)
-- ============================================================
CREATE TABLE vt_api_keys (
    id            SERIAL PRIMARY KEY,
    api_key       VARCHAR(255) NOT NULL UNIQUE,
    api_type      VARCHAR(30)  NOT NULL DEFAULT 'virustotal',
    usage_count   INTEGER DEFAULT 0,
    last_used     TIMESTAMP,
    is_active     BOOLEAN DEFAULT TRUE,
    is_error      BOOLEAN DEFAULT FALSE,
    error_count   INTEGER DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP,
    source        VARCHAR(100) DEFAULT 'manual',
    notes         TEXT,
    last_checked  TIMESTAMP,
    health_status health_status_enum DEFAULT 'unknown'
);
CREATE INDEX idx_active_error ON vt_api_keys (is_active, is_error);
CREATE INDEX idx_usage        ON vt_api_keys (usage_count, last_used);
CREATE INDEX idx_type_active  ON vt_api_keys (api_type, is_active, is_error);

-- ============================================================
-- TABEL EXISTING 2 — CACHE_SCANS  (dimigrasi apa adanya, 11 baris)
-- + kolom baru untuk TTL
-- ============================================================
CREATE TABLE cache_scans (
    id          SERIAL PRIMARY KEY,
    scan_type   scan_type_enum NOT NULL,
    identifier  VARCHAR(500) NOT NULL,
    source      VARCHAR(30)  NOT NULL DEFAULT 'virustotal',
    vt_response JSONB NOT NULL,          -- nama dipertahankan demi kompatibilitas
    hits        INTEGER NOT NULL DEFAULT 0,   -- bukti KR4
    scan_date   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP,               -- 🆕 TTL, menutup temuan audit A.4 butir 4
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_identifier_type_source UNIQUE (identifier, scan_type, source)
);
CREATE INDEX idx_identifier  ON cache_scans (identifier);
CREATE INDEX idx_scan_date   ON cache_scans (scan_date);
CREATE INDEX idx_source_type ON cache_scans (source, scan_type);
CREATE INDEX idx_cache_exp   ON cache_scans (expires_at);

-- ============================================================
-- TABEL EXISTING 3 — API_USAGE_LOG  (0 baris; mulai diisi Fase 5)
-- ============================================================
CREATE TABLE api_usage_log (
    id               SERIAL PRIMARY KEY,
    api_key_id       INTEGER REFERENCES vt_api_keys(id) ON DELETE SET NULL,
    analysis_id      INTEGER REFERENCES analyses(id) ON DELETE CASCADE,  -- 🆕
    source           VARCHAR(30),          -- 🆕 provider mana
    endpoint         VARCHAR(255),
    response_time_ms INTEGER,              -- bukti KR1 per-API
    status_code      INTEGER,
    from_cache       BOOLEAN DEFAULT FALSE,-- 🆕 bukti KR4
    request_payload  JSONB,
    response_payload JSONB,
    client_ip        VARCHAR(45),
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_log_analysis ON api_usage_log (analysis_id);
CREATE INDEX idx_log_created  ON api_usage_log (created_at DESC);
```

### Relasi antar tabel

```text
indicators (1) ──< (N) analyses (1) ──< (N) reports
                          │
                          └──< (N) api_usage_log >── (1) vt_api_keys

cache_scans  — berdiri sendiri (optimasi kuota, bukan bagian history)
```

### Catatan perancangan yang perlu dibela di sidang

1. **`cache_scans` bukan `analyses`.** `cache_scans` memakai *upsert* dengan
   unique constraint, sehingga scan berikutnya **menimpa** hasil sebelumnya —
   sifatnya cache, bukan riwayat. `analyses` bersifat *append-only* sehingga
   perubahan status sebuah indikator dari waktu ke waktu tetap terekam. Dua
   tabel ini sengaja dipisah karena tujuannya berbeda.
2. **`risk_score` disimpan, tidak dihitung ulang.** Skor dihitung saat analisis
   lalu dibekukan, agar laporan PDF lama tetap konsisten meskipun algoritma
   skoring diperbarui.
3. **Index GIN pada `virustotal_result`** memungkinkan query isi JSON
   (mis. cari semua analisis yang mendeteksi keluarga malware tertentu) —
   kemampuan yang tidak dimiliki SQLite.
4. **`sources_from_cache` dan `cache_scans.hits`** adalah instrumen pengukuran
   KR4 (pengurangan redundant check 30%).

---

## B.4 SKEMA CELERY + REDIS

### Konfigurasi broker & backend

```python
# app/tasks/celery_app.py
CELERY_BROKER_URL      = "redis://localhost:6379/0"   # antrean tugas
CELERY_RESULT_BACKEND  = "redis://localhost:6379/1"   # hasil task (dipisah dari broker)

task_serializer        = "json"
result_serializer      = "json"
accept_content         = ["json"]
timezone               = "Asia/Jakarta"
enable_utc             = False        # selaras dengan utils/timeutil.now_local()
result_expires         = 3600         # hasil disimpan 1 jam
task_track_started     = True         # agar status STARTED bisa dipolling frontend
task_acks_late         = True         # task diakui setelah selesai, bukan saat diambil
worker_prefetch_multiplier = 1        # cegah satu worker memborong antrean
```

### Pembagian queue

| Queue | Isi | Concurrency | Alasan |
|---|---|---|---|
| `intel` | 4 task pemanggil API eksternal | 8 | Terikat I/O (menunggu jaringan), boleh banyak |
| `scan` | Orkestrator + callback penggabung | 2 | Ringan, hanya mengatur |
| `report` | Generate PDF | 2 | Terikat CPU/memori, jangan banyak-banyak |
| `maintenance` | Refresh key, bersihkan cache kedaluwarsa | 1 | Terjadwal, tidak mendesak |

```python
task_routes = {
    "tasks.scan.provider.*":  {"queue": "intel"},
    "tasks.scan.orchestrate": {"queue": "scan"},
    "tasks.scan.finalize":    {"queue": "scan"},
    "tasks.report.*":         {"queue": "report"},
    "tasks.maintenance.*":    {"queue": "maintenance"},
}
```

### Pola orkestrasi paralel — inti kontribusi teknis skripsi

```python
from celery import chord, group

@celery.task(name="tasks.scan.orchestrate", bind=True)
def orchestrate_scan(self, indicator_value, input_type, analysis_id):
    """
    Menggantikan for-loop sekuensial di aggregator.run_multi_scan().
    ROUTING (dari aggregator.py) menentukan API mana yang relevan;
    hanya API relevan yang di-enqueue.
    """
    targets = ROUTING.get(input_type, [VIRUSTOTAL])
    header  = group(
        provider_scan.s(src, input_type, indicator_value) for src in targets
    )
    callback = finalize_analysis.s(analysis_id=analysis_id)
    return chord(header)(callback)     # 4 task jalan bersamaan → 1 penggabung


@celery.task(
    name="tasks.scan.provider.run",
    autoretry_for=(httpx.HTTPError, httpx.TimeoutException),
    retry_backoff=True,        # 1s, 2s, 4s, ...
    retry_backoff_max=30,
    retry_jitter=True,
    max_retries=3,
    time_limit=45,             # hard kill
    soft_time_limit=30,        # beri kesempatan cleanup
)
def provider_scan(source, scan_type, identifier):
    """Membungkus registry.get_client(source).report() — LOGIKA TIDAK BERUBAH."""
    with session_scope() as db:
        return get_client(source, db).report(scan_type, identifier)


@celery.task(name="tasks.scan.finalize")
def finalize_analysis(results, analysis_id):
    """Gabungkan 4 hasil → build_final_verdict() → simpan ke tabel analyses."""
    ...
```

### Penjadwalan (Celery Beat — pengganti APScheduler)

```python
beat_schedule = {
    "refresh-api-keys": {
        "task": "tasks.maintenance.refresh_api_keys",
        "schedule": crontab(hour=3, minute=0, day_of_week=0),   # Minggu 03:00
    },
    "purge-expired-cache": {                                    # menutup audit A.4 butir 4
        "task": "tasks.maintenance.purge_expired_cache",
        "schedule": crontab(hour=4, minute=0),                  # harian 04:00
    },
    "revalidate-keys": {
        "task": "tasks.maintenance.revalidate_all_keys",
        "schedule": crontab(hour=2, minute=0, day_of_week=1),
    },
}
```

### Alur request asinkron (yang berubah di frontend)

```text
POST /api/scan          → 202 Accepted {"task_id": "...", "analysis_id": 42}
GET  /api/scan/42/status→ 200 {"status": "STARTED", "progress": "2/4 sumber"}
GET  /api/scan/42/status→ 200 {"status": "SUCCESS", "result": {...}}
```

Frontend melakukan polling tiap ~1 detik lewat `useScanPolling.ts`.
Alternatif yang lebih elegan (Server-Sent Events) **sengaja tidak dipakai**
untuk menjaga kompleksitas tetap wajar pada lingkup skripsi.

### Risiko operasional yang harus diantisipasi

| Risiko | Mitigasi |
|---|---|
| Redis mati saat demo sidang | Sediakan `docker-compose up` + skrip cek kesehatan sebelum demo; siapkan mode fallback sinkron |
| Rate limit VirusTotal (4 req/menit tier gratis) | Sudah tertangani `LoadBalancer` (33 key, prioritas key ber-usage tinggi). Tambahkan `rate_limit` per task sebagai lapis kedua |
| Worker mati di tengah task | `task_acks_late=True` → task dikembalikan ke antrean |
| Hasil task menumpuk di Redis | `result_expires=3600` |
