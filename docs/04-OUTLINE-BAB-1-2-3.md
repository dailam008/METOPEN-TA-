# BAGIAN D — OUTLINE BAB 1, 2, 3

> Kerangka penulisan untuk mata kuliah **Metodologi Penelitian** (BAB 1–3).
> BAB 4–5 dikerjakan pada semester berikutnya.

---

> ## ⚠️ CATATAN JUJUR TENTANG SITASI
>
> Pada bagian **2.2 Penelitian Terdahulu**, saya **tidak mencantumkan judul
> jurnal, nama penulis, atau tahun terbit apa pun.** Alasannya: saya tidak
> memiliki akses untuk memverifikasi keberadaan publikasi tersebut dari sesi
> ini, dan sitasi palsu pada skripsi berakibat fatal — mulai dari revisi total
> sampai tuduhan pemalsuan data.
>
> Yang saya sediakan sebagai gantinya adalah **strategi pencarian**: kata kunci,
> basis data, kriteria inklusi, dan format tabel sintesis yang tinggal diisi.
> Cari sendiri di Google Scholar/IEEE/Garuda, lalu isi tabelnya. Kalau mau,
> saya bisa bantu carikan dan verifikasi di sesi terpisah.

---

# BAB 1 — PENDAHULUAN

## 1.1 Latar Belakang

**Alur argumentasi (dari umum ke khusus):**

1. **Eskalasi ancaman siber di Indonesia.**
   Phishing dan malware sebagai vektor serangan dominan terhadap organisasi.
   *Data pendukung: statistik insiden BSSN/ID-SIRTII tahun terbaru, laporan
   APJII. → cari & sitasi.*

2. **Peran Security Operation Center (SOC).**
   SOC sebagai lini pertahanan: memantau, mendeteksi, menganalisis, merespons.
   Beban kerja analis meningkat seiring volume alert.

3. **Masalah operasional yang nyata.**
   Verifikasi satu indikator (URL/hash mencurigakan) menuntut analis membuka
   beberapa platform threat intelligence satu per satu — VirusTotal, URLhaus,
   AbuseIPDB, MXToolbox — lalu menyimpulkan secara manual. Waktu rata-rata
   **±15 menit per kasus**.
   *Data pendukung: hasil observasi/wawancara di SOC tempat penelitian.
   → ini data primer, wajib dikumpulkan sendiri.*

4. **Tiga akibat langsung.**
   (a) Waktu analis habis untuk pekerjaan mekanis, bukan analisis;
   (b) tidak ada memori organisasi — indikator yang sama diperiksa berulang
   oleh analis berbeda;
   (c) pelaporan manual memakan waktu dan rawan *human error*.

5. **Celah yang belum terisi.**
   Platform komersial (Anomali ThreatStream, MISP, ThreatConnect) menawarkan
   agregasi threat intel, tetapi berbiaya tinggi atau menuntut kompleksitas
   penyiapan yang tidak sebanding untuk SOC berskala menengah.
   *→ bahas di 2.2, bandingkan dengan sistem yang diusulkan.*

6. **Solusi yang diusulkan.**
   Platform manajemen analisis ancaman terpusat yang mengagregasi empat sumber
   threat intelligence **secara paralel** menggunakan *asynchronous task queue*,
   dilengkapi basis data riwayat internal (whitelist/blacklist) dan pelaporan
   otomatis.

> **Tips penulisan:** paragraf 3 dan 4 adalah inti latar belakang. Beri porsi
> terbesar di sana, karena di situlah masalah penelitian berakar. Paragraf 1–2
> cukup ringkas — penguji biasanya sudah paham konteksnya.

## 1.2 Rumusan Masalah

1. Bagaimana merancang platform terpusat yang mengintegrasikan empat sumber
   *threat intelligence* (VirusTotal, URLhaus, AbuseIPDB, MXToolbox) untuk
   menganalisis URL dan *file hash*?
2. Bagaimana menerapkan *asynchronous task queue* agar pemanggilan keempat API
   berjalan paralel tanpa *blocking*, sehingga analisis selesai < 15 detik?
3. Bagaimana merancang basis data riwayat internal berklasifikasi
   *whitelist*/*blacklist* untuk mengurangi pemeriksaan berulang?
4. Bagaimana menghasilkan laporan analisis berformat PDF secara otomatis?

## 1.3 Tujuan Penelitian

| # | Tujuan | Menjawab rumusan |
|---|---|---|
| 1 | Merancang dan membangun platform analisis ancaman terpusat berbasis web | 1 |
| 2 | Mengimplementasikan orkestrasi paralel empat API dengan Celery & Redis | 2 |
| 3 | Merancang basis data riwayat internal dengan klasifikasi whitelist/blacklist | 3 |
| 4 | Mengembangkan fitur pelaporan otomatis berformat PDF dan dasbor analitik | 4 |
| 5 | Menguji sistem menggunakan data operasional SOC | 1–4 |

## 1.4 Manfaat Penelitian

**Praktis (bagi SOC)**
- Memangkas waktu verifikasi indikator dari ±15 menit menjadi < 15 detik
- Mengurangi pemeriksaan berulang ≥ 30% melalui riwayat internal dan cache
- Menyeragamkan format laporan dan menekan *human error*
- Membentuk memori organisasi atas indikator yang pernah dianalisis

**Teoretis / akademis**
- Kajian penerapan pola *asynchronous task queue* pada agregasi threat intelligence
- Rancangan algoritma *risk scoring* yang menggabungkan vonis dari empat sumber
  dengan karakteristik berbeda, termasuk penanganan saat sumber saling
  bertentangan

## 1.5 Batasan Masalah

1. Indikator terbatas pada **URL, IP, domain, dan file hash** (MD5, SHA-1, SHA-256).
   Sistem **tidak** memindai isi berkas — hanya nilai hash-nya.
2. Sumber threat intelligence terbatas pada **empat** API tersebut.
3. **Tidak** menggunakan *machine learning* — klasifikasi berbasis aturan dan
   agregasi skor.
4. **Tidak** terintegrasi ke firewall/SOAR; sistem bersifat *monitoring &
   analysis only*, keputusan akhir tetap di tangan analis.
5. Tidak mencakup aplikasi *mobile*.
6. Bergantung pada ketersediaan dan kuota API pihak ketiga (tier gratis).

## 1.6 Sistematika Penulisan

Paragraf ringkas per bab (BAB 1–5).

---

# BAB 2 — TINJAUAN PUSTAKA

## 2.1 Landasan Teori

### 2.1.1 Security Operation Center (SOC)
Definisi, fungsi, tingkatan analis (Tier 1–3), alur kerja penanganan insiden.
Posisi penelitian: mendukung **Tier 1** pada tahap verifikasi indikator.

### 2.1.2 Cyber Threat Intelligence (CTI)
Definisi dan klasifikasi (strategis, taktis, operasional, teknis).
**Indicator of Compromise (IoC)** sebagai objek utama penelitian.
Posisi penelitian: CTI **teknis**, memanfaatkan IoC berupa URL/IP/domain/hash.

### 2.1.3 Sumber Threat Intelligence yang digunakan
| Sumber | Cakupan | Peran dalam sistem |
|---|---|---|
| VirusTotal | 70+ mesin antivirus, sandbox, relasi file | Sumber utama seluruh jenis indikator |
| URLhaus (abuse.ch) | Basis data URL penyebar malware | Verifikasi URL & host |
| AbuseIPDB | Reputasi IP dari laporan komunitas | Verifikasi alamat IP |
| MXToolbox | Status blacklist domain/DNS | Verifikasi domain email |

Bahas juga: keterbatasan tiap sumber dan **mengapa agregasi diperlukan** —
tidak ada satu sumber yang memadai sendirian.

### 2.1.4 REST API dan Integrasi Sistem
Konsep REST, metode HTTP, kode status, autentikasi berbasis API key,
*rate limiting*.

### 2.1.5 Pemrosesan Asinkron dan Task Queue
- Keterbatasan model *request–response* sinkron pada operasi terikat I/O
- Konsep *message broker*, *worker*, *task queue*
- **Celery** sebagai *distributed task queue*; **Redis** sebagai broker
- Pola **chord** (sekumpulan task paralel + satu callback penggabung)
- Perbandingan: sinkron vs *threading* vs *asyncio* vs *task queue* terdistribusi

> **Ini subbab paling penting di BAB 2** — di sinilah kontribusi teknis skripsi
> berpijak. Beri porsi paling besar.

### 2.1.6 Basis Data Relasional dan PostgreSQL
Konsep relasional, normalisasi, indexing.
**JSONB** pada PostgreSQL untuk menyimpan respons API yang strukturnya
beragam — beserta alasan memilihnya dibanding menormalisasi penuh.

### 2.1.7 Arsitektur Web Modern
Pemisahan *frontend*–*backend*, REST sebagai kontrak, *Server-Side Rendering*
pada Next.js, Flask sebagai *micro-framework*.

### 2.1.8 Metodologi Agile SDLC
Tahapan, iterasi, alasan pemilihan untuk penelitian ini.

## 2.2 Penelitian Terdahulu

> **Belum diisi — lihat catatan di awal dokumen.**

**Strategi pencarian:**

| Aspek | Kata kunci (ID) | Kata kunci (EN) |
|---|---|---|
| Platform CTI | "platform threat intelligence", "agregasi threat intel" | "threat intelligence platform", "IoC aggregation", "CTI sharing platform" |
| Otomasi SOC | "otomasi SOC", "efisiensi analis keamanan" | "SOC automation", "security analyst workload", "alert triage automation" |
| Task queue | "antrean tugas asinkron", "Celery" | "asynchronous task queue", "Celery distributed task", "parallel API orchestration" |
| Deteksi phishing | "deteksi URL phishing" | "phishing URL detection", "malicious URL analysis" |
| Multi-sumber | — | "multi-source threat intelligence correlation", "IoC enrichment" |

**Basis data:** Google Scholar · IEEE Xplore · ScienceDirect · SpringerLink ·
Portal Garuda (garuda.kemdikbud.go.id) · SINTA · repositori Telkom University

**Kriteria inklusi:** terbit ≤ 5 tahun terakhir; membahas platform/otomasi
threat intelligence **atau** penerapan task queue pada sistem terdistribusi;
jurnal terindeks SINTA 1–4 atau Scopus; minimal **8–10 referensi** untuk BAB 2.

**Format tabel sintesis yang harus diisi:**

| No | Penulis (Tahun) | Judul | Metode | Hasil | Perbedaan dengan penelitian ini |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |

Kolom terakhir adalah yang paling ditagih penguji — pastikan setiap baris
menjelaskan **celah** yang diisi penelitian ini. Posisi pembeda yang bisa
ditonjolkan:
- Menggabungkan **empat** sumber sekaligus dengan *smart routing* (sumber
  dipilih sesuai jenis indikator, tidak semua dipanggil membabi buta)
- Orkestrasi **paralel** dengan task queue, bukan pemanggilan berurutan
- **Pengelolaan pool API key ber-*load balancing*** untuk menyiasati batas
  kuota tier gratis — aspek yang jarang dibahas literatur
- Riwayat internal whitelist/blacklist sebagai memori organisasi

## 2.3 Kerangka Berpikir

```text
┌──────────────────── MASALAH ────────────────────┐
│ • Verifikasi manual ±15 menit/kasus             │
│ • Tidak ada riwayat → pemeriksaan berulang      │
│ • Pelaporan manual, rawan human error           │
└────────────────────────┬────────────────────────┘
                         ▼
┌──────────────────── PENDEKATAN ─────────────────┐
│ • Agregasi 4 sumber CTI dalam satu antarmuka    │
│ • Task queue asinkron (Celery + Redis)          │
│ • Basis data riwayat + whitelist/blacklist      │
│ • Generator laporan PDF otomatis                │
└────────────────────────┬────────────────────────┘
                         ▼
┌──────────────────── PENGEMBANGAN ───────────────┐
│ Agile SDLC — Fase 0–11 (lihat BAB 3)            │
│ Flask + Next.js + PostgreSQL + Celery + Redis   │
└────────────────────────┬────────────────────────┘
                         ▼
┌──────────────────── PENGUJIAN ──────────────────┐
│ Blackbox · Performa (KR1,KR2) · Akurasi (KR3)   │
│ Efisiensi cache (KR4) · Data operasional SOC    │
└────────────────────────┬────────────────────────┘
                         ▼
┌──────────────────── LUARAN ─────────────────────┐
│ Platform manajemen analisis ancaman terpusat    │
│ Waktu analisis < 15 detik · redundansi −30%     │
└─────────────────────────────────────────────────┘
```

---

# BAB 3 — METODOLOGI PENELITIAN

## 3.1 Metode Penelitian
Jenis: penelitian terapan (*applied research*) dengan pendekatan
*Design Science Research* / *Research & Development*.
Model pengembangan: **Agile SDLC**, alasan pemilihan, dan kesesuaiannya dengan
rencana bertahap Fase 0–11.

## 3.2 Tahapan Penelitian
Diagram alur: Identifikasi Masalah → Studi Literatur → Pengumpulan Kebutuhan →
Perancangan Sistem → Implementasi (iteratif) → Pengujian → Analisis Hasil →
Kesimpulan.

## 3.3 Metode Pengumpulan Data
- **Observasi**: alur kerja analis SOC saat memverifikasi indikator
- **Wawancara**: analis SOC — validasi angka ±15 menit per kasus
- **Studi dokumen**: dokumentasi resmi keempat API
- **Studi pustaka**: BAB 2

## 3.4 Analisis Kebutuhan
### 3.4.1 Kebutuhan Fungsional
Tabel `KF-01 … KF-n`: analisis indikator, deteksi tipe otomatis, agregasi
paralel, skoring risiko, riwayat, whitelist/blacklist, laporan PDF, dasbor
analitik, manajemen API key, bulk scan.

### 3.4.2 Kebutuhan Non-Fungsional
Tabel `KNF-01 … KNF-n`: waktu respons < 15 detik, generate PDF < 5 detik,
akurasi ≥ 95%, antarmuka responsif, keamanan penyimpanan API key,
ketersediaan saat salah satu sumber gagal (*graceful degradation*).

## 3.5 Perancangan Sistem
### 3.5.1 Arsitektur Sistem
→ diagram pada **Bagian B.0**

### 3.5.2 Perancangan Proses
- Use Case Diagram (aktor: Analis SOC, Administrator)
- Activity Diagram: alur analisis indikator
- **Sequence Diagram: orkestrasi paralel empat API** ← gambar kunci skripsi
- Flowchart: algoritma *risk scoring* dan penentuan vonis akhir

### 3.5.3 Perancangan Basis Data
→ **Bagian B.3** (ERD, skema tabel, kamus data, justifikasi JSONB)

### 3.5.4 Perancangan Antarmuka
→ **Bagian B.2** (struktur halaman + *wireframe*)

### 3.5.5 Perancangan Task Queue
→ **Bagian B.4** (pembagian queue, pola chord, kebijakan *retry*, penjadwalan)

## 3.6 Rancangan Implementasi
### 3.6.1 Lingkungan Pengembangan
Perangkat keras, sistem operasi, Python 3.12, Node.js 20, PostgreSQL 16,
Redis 7, Docker.

### 3.6.2 Tahapan Implementasi Bertahap
→ **Bagian C** (Fase 0–11 beserta estimasi, risiko, dan ketergantungan)

> Subbab ini menjadi pembeda: alih-alih menyajikan rencana implementasi yang
> generik, penelitian ini menyusun rencana migrasi terukur yang bertumpu pada
> **hasil audit kode** terhadap sistem prototipe yang telah berjalan
> (Bagian A) — termasuk pemetaan komponen mana yang dipertahankan, diadaptasi,
> atau ditulis ulang.

## 3.7 Rancangan Pengujian
| Jenis uji | Metode | Indikator keberhasilan | Sumber data |
|---|---|---|---|
| Fungsional | Blackbox, matriks kasus uji | 100% kasus lolos | Skenario buatan |
| Performa | Ukur `response_time_ms` | KR1: < 15 detik | 100 indikator |
| Performa | Ukur `generation_ms` | KR2: < 5 detik | 30 laporan |
| Akurasi | Bandingkan vonis sistem vs penilaian analis | KR3: ≥ 95% | Data operasional SOC |
| Efisiensi | Rasio `sources_from_cache` & `cache_scans.hits` | KR4: ≥ 30% | Log operasional |
| Komparatif | Sekuensial (Fase 6) vs paralel (Fase 8) | Ada percepatan bermakna | 100 indikator |

> Baris terakhir memerlukan pencatatan `response_time_ms` **sejak Fase 6**,
> sebelum Celery diterapkan. Bila dilewatkan, data pembanding hilang permanen.

## 3.8 Jadwal Penelitian
Tabel enam bulan (mengacu PRD) + pemetaan Fase 0–11 pada **Bagian C.5**.

---

## D.1 CATATAN PENUTUP

**Yang sudah siap untuk Metopen:** BAB 3 subbab 3.5 dan 3.6 sudah memiliki
bahan matang dari Bagian A, B, dan C — ini justru bagian yang biasanya paling
lemah pada proposal mahasiswa, karena umumnya masih berupa rencana di atas
kertas. Penelitian ini memilikinya dalam bentuk audit atas sistem yang sudah
berjalan.

**Yang masih harus dikerjakan sendiri:**
1. Sitasi BAB 2 (8–10 referensi) — **jangan sampai dikarang**
2. Data primer: observasi dan wawancara di SOC untuk memvalidasi klaim ±15 menit
3. Penggambaran UML (Use Case, Activity, Sequence) — gunakan draw.io atau PlantUML
4. Wireframe antarmuka

**Urutan pengerjaan yang disarankan saat kuliah dimulai:**
BAB 1 → BAB 3 (bahannya sudah ada) → BAB 2 (paling menyita waktu karena
menuntut pencarian literatur).
