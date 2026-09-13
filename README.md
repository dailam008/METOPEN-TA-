# Threat Analysis Management Platform (SOC)

> **Rancang Bangun Platform Manajemen Analisis Ancaman Terpusat (URL & Hash) untuk SOC**
> Tugas Akhir — Sistem Informasi, Telkom University

![Status](https://img.shields.io/badge/status-Persiapan%20Metopen%20(BAB%201--3)-blue)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20Next.js%20%7C%20PostgreSQL%20%7C%20Celery-informational)

---

## 📌 Status Proyek

**Tahap saat ini: Persiapan Metodologi Penelitian (BAB 1–3).**

Repositori ini berisi **blueprint perancangan**, bukan implementasi final.
Implementasi (Fase 0–11) dieksekusi pada semester berikutnya untuk BAB 4–5.

| Komponen | Status |
|---|---|
| Audit kode prototipe | ✅ Selesai |
| Rancangan arsitektur & basis data | ✅ Selesai |
| Rencana migrasi bertahap (Fase 0–11) | ✅ Selesai |
| Outline BAB 1–3 | ✅ Selesai |
| Implementasi Flask + Next.js | ⏳ Belum dimulai |
| Prototipe berjalan (FastAPI) | 🟡 Ada, menjadi basis migrasi |

---

## 📖 Deskripsi

Sistem otomasi untuk menganalisis tautan (URL) phishing dan lampiran malware
(hash) dengan mengintegrasikan **empat threat intelligence API secara paralel**
menggunakan *asynchronous task queue*. Sistem diperluas menjadi platform
manajemen ancaman terpusat yang dilengkapi basis data riwayat dan pelaporan
otomatis untuk meningkatkan efisiensi operasional SOC.

**Masalah yang diselesaikan**

- Analis SOC menghabiskan ±15 menit per kasus untuk memeriksa tautan dan hash
  secara manual ke berbagai platform threat intelligence.
- Tidak ada basis data riwayat internal (whitelist/blacklist), sehingga ancaman
  yang sama dianalisis berulang kali.
- Pembuatan laporan manual memakan waktu dan rawan *human error*.

**Sumber threat intelligence yang diintegrasikan**

| Sumber | Peran |
|---|---|
| VirusTotal | Pemindaian URL, domain, IP, dan file hash |
| URLhaus (abuse.ch) | Pencocokan dengan basis data URL penyebar malware |
| AbuseIPDB | Analisis reputasi alamat IP |
| MXToolbox | Analisis status blacklist domain/DNS |

---

## 🛠️ Stack Teknologi

| Lapisan | Teknologi | Keterangan |
|---|---|---|
| Backend | **Flask 3** | Ditetapkan pembimbing (menggantikan prototipe FastAPI) |
| Frontend | **Next.js 14** + React-Bootstrap 5 | Menggantikan dashboard HTML tunggal |
| Basis data | **PostgreSQL 16** | JSONB untuk respons API, GIN index |
| Task queue | **Celery 5** | Orkestrasi paralel empat API (pola *chord*) |
| Broker | **Redis 7** | db0 = broker, db1 = result backend |
| ORM | SQLAlchemy 2 + Alembic | Dipertahankan dari prototipe |
| HTTP client | httpx | Dipertahankan dari prototipe |
| Laporan | WeasyPrint / ReportLab + Jinja2 | Generator PDF |

---

## 📚 Dokumentasi Blueprint

| Dokumen | Isi | Untuk |
|---|---|---|
| [`docs/01-AUDIT-KODE-INTI.md`](docs/01-AUDIT-KODE-INTI.md) | Audit 27 file prototipe, tabel pindah/adaptasi/tulis-ulang, daftar utang teknis | BAB 3 — Desain Sistem |
| [`docs/02-ARSITEKTUR-DAN-SKEMA.md`](docs/02-ARSITEKTUR-DAN-SKEMA.md) | Struktur folder Flask & Next.js, skema PostgreSQL lengkap, konfigurasi Celery/Redis | BAB 3 — Arsitektur & Basis Data |
| [`docs/03-RENCANA-MIGRASI.md`](docs/03-RENCANA-MIGRASI.md) | Rencana bertahap Fase 0–11, estimasi effort, urutan aman, peta risiko | BAB 3 — Metodologi |
| [`docs/04-OUTLINE-BAB-1-2-3.md`](docs/04-OUTLINE-BAB-1-2-3.md) | Kerangka penulisan BAB 1, 2, 3 + strategi pencarian literatur | Penulisan proposal |
| [`PRODUCT REQUIREMENTS DOCUMENT (PRD) - FINAL V4 (APPROVED).md`](PRODUCT%20REQUIREMENTS%20DOCUMENT%20(PRD)%20-%20FINAL%20V4%20(APPROVED).md) | PRD yang telah disetujui pembimbing | Acuan utama |

**Temuan audit utama:** hanya 4 dari 27 file prototipe yang terikat pada
framework lama. Seluruh lapisan logika bisnis (`app/services/`) dan model data
(`app/models/`) bersifat *framework-agnostic*, sehingga **±78% kode inti dapat
dipindahkan ke Flask tanpa perubahan**.

---

## 🗂️ Struktur Folder Target

```text
.
├── backend/                    # Flask (implementasi mendatang)
│   ├── app/
│   │   ├── models/             # ✅ pindah utuh dari prototipe (+3 tabel baru)
│   │   ├── services/           # ✅ pindah utuh 100% — logika bisnis
│   │   ├── api/                # ❌ ditulis ulang sebagai Blueprint
│   │   ├── tasks/              # 🆕 Celery
│   │   ├── reports/            # 🆕 generator PDF
│   │   └── utils/              # ✅ pindah utuh
│   ├── migrations/             # Alembic
│   ├── scripts/                # migrasi SQLite → PostgreSQL
│   └── tests/
├── frontend/                   # Next.js (implementasi mendatang)
│   ├── app/                    # App Router
│   ├── components/
│   └── lib/
├── docs/                       # 📘 blueprint (repositori ini)
└── app/                        # prototipe FastAPI (referensi migrasi)
```

Rincian lengkap: [`docs/02-ARSITEKTUR-DAN-SKEMA.md`](docs/02-ARSITEKTUR-DAN-SKEMA.md)

---

## 🚀 Cara Menjalankan

> ⚠️ **Belum berlaku.** Implementasi Flask + Next.js belum dimulai.
> Petunjuk berikut adalah rencana untuk tahap implementasi.

### Prasyarat
- Python 3.12+, Node.js 20+, Docker & Docker Compose

### 1. Infrastruktur
```bash
docker compose up -d          # PostgreSQL 16 + Redis 7
```

### 2. Backend
```bash
cd backend
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                # isi kredensial sendiri
flask db upgrade                                    # migrasi skema
flask run --port 5000
```

### 3. Celery Worker
```bash
cd backend
celery -A celery_worker.celery worker -Q intel,scan,report --loglevel=info
celery -A celery_worker.celery beat --loglevel=info     # terminal terpisah
```

### 4. Frontend
```bash
cd frontend
npm install
npm run dev                                         # http://localhost:3000
```

### 5. API Key
API key **tidak** disimpan di `.env`. Key dimasukkan lewat dasbor
(menu API Keys); jenis providernya dideteksi otomatis dari format dan
**diverifikasi melalui test ping** ke API penyedia sebelum disimpan.

---

## 🔐 Keamanan

Berkas berikut **sengaja tidak disertakan** dalam repositori
(lihat [`.gitignore`](.gitignore)):

| Berkas | Alasan |
|---|---|
| `.env` | Kredensial basis data dan secret key |
| `vt_proxy.db` | Berisi 33 API key asli + cache hasil pemindaian |
| `backups/` | Dump basis data berisi API key |
| `venv/`, `node_modules/`, `__pycache__/` | Artefak build |
| `storage/reports/` | Laporan PDF hasil generate (artefak runtime) |

Gunakan `.env.example` sebagai templat konfigurasi.

---

## 📊 Key Results yang Diukur

| Kode | Target | Instrumen pengukuran |
|---|---|---|
| KR1 | Analisis selesai < 15 detik | `analyses.response_time_ms` |
| KR2 | Generate PDF < 5 detik | `reports.generation_ms` |
| KR3 | Akurasi klasifikasi ≥ 95% | Perbandingan vonis sistem vs penilaian analis |
| KR4 | Pemeriksaan berulang turun ≥ 30% | `cache_scans.hits`, `analyses.sources_from_cache` |

---

## 👤 Kontributor

**Mochammad Dailam Al Muhibi**
Program Studi Sistem Informasi — Telkom University
Pembimbing: Pak Rosyid

---

## 📄 Lisensi

Repositori akademik untuk keperluan Tugas Akhir.
