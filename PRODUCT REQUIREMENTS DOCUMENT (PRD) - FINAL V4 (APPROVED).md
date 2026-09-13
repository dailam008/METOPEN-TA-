# PRODUCT REQUIREMENTS DOCUMENT (PRD) - FINAL V4 (APPROVED)

## Rancang Bangun Platform Manajemen Analisis Ancaman Terpusat (URL & Hash) untuk SOC

---

## 📋 EXECUTIVE SUMMARY

**Project Name:** Threat Analysis Management Platform (SOC)  
**Duration:** 6 Bulan (1 Semester Akademik)  
**Status:** Approved by Advisor  
**Owner:** [Nama Anda]  
**Advisor:** Pak Rosyid (Dosen SI)  
**Institution:** Telkom University

### Project Overview
Sistem otomasi untuk menganalisis tautan (URL) phishing dan lampiran *malware* (Hash) dengan mengintegrasikan 4 *threat intelligence APIs* secara paralel menggunakan *Asynchronous Task Queue*. Sistem ini telah diperluas cakupannya menjadi platform manajemen ancaman terpusat yang dilengkapi fitur *history database* dan pelaporan otomatis untuk meningkatkan efisiensi operasional SOC.

**Problem Statement:**
* Analis SOC membuang waktu (±15 menit per kasus) untuk mengecek *link* dan *file hash* secara manual ke berbagai platform *Threat Intel*.
* Tidak ada *database history* internal (Whitelist/Blacklist) yang mencatat temuan sebelumnya, sehingga analis sering menganalisis ancaman yang sama berulang kali.
* Pembuatan laporan hasil analisis memakan waktu dan berpotensi terjadi *human error*.

**Solution:**
* Web platform terpusat untuk menganalisis URL dan File Hash secara instan.
* Backend mengorkestrasi 4 APIs (**VirusTotal, AbuseIPDB, MXToolbox, URLhaus**) secara paralel menggunakan Celery & Redis.
* Fitur *Database History* internal untuk klasifikasi *Whitelist/Blacklist*.
* *Dashboard* analitik dan pembuatan laporan otomatis berformat PDF.

---

## 🎯 OBJECTIVES & KEY RESULTS

### Primary Objectives
1. ✅ Desain & implementasi web dashboard untuk analisis URL dan Hash *Malware*.
2. ✅ Integrasi 4 threat intelligence APIs secara paralel tanpa *blocking*.
3. ✅ Implementasi *Database History* untuk *Whitelist* dan *Blacklist* ancaman internal.
4. ✅ Pengembangan fitur rekap pelaporan otomatis (PDF) dan *Dashboard* Analitik.
5. ✅ Pengujian menggunakan data operasional dari SOC.

### Key Results (Measurable)
* **KR1:** Analisis URL/Hash selesai dalam < 15 detik per permintaan.
* **KR2:** Proses *generate* laporan PDF dari hasil analisis < 5 detik.
* **KR3:** Akurasi klasifikasi ancaman mencapai 95%+ dibandingkan tinjauan manual analis.
* **KR4:** Mengurangi beban *redundant check* sebesar 30% dengan adanya *Database History* lokal.

---

## 📊 SCOPE & METODOLOGI

**Metodologi Pengembangan:** *Agile Systems Development Life Cycle (SDLC)*.

### IN-SCOPE (✅ INCLUDED)
* **Pengecekan Tautan (URL & IP) dan Lampiran Malware (Hash MD5/SHA256).**
* Dashboard web responsif (Bootstrap 5) dengan *Analytic Dashboard* (Tren ancaman).
* Python Flask REST API terintegrasi dengan **Celery & Redis** untuk pemrosesan asinkron.
* 4 Modul Integrasi API:
  * **VirusTotal:** Pemindaian URL/Domain dan File Hash.
  * **URLhaus:** Pencocokan dengan *database malware/phishing URL* komunitas.
  * **AbuseIPDB:** Analisis reputasi *IP Address*.
  * **MXToolbox:** Analisis status *Blacklist* pada *Domain/DNS*.
* **Database History Internal:** Pencatatan dan penandaan *Whitelist/Blacklist* otomatis.
* **Automated Reporting:** Fitur cetak/rekap pelaporan hasil analisis dalam format PDF.
* PostgreSQL database untuk penyimpanan *history* dan *user actions*.

### OUT-OF-SCOPE (❌ NOT INCLUDED)
* Mobile app.
* Machine Learning / AI Classification (Fokus pada agregasi Threat Intel).
* Integrasi pencegahan langsung ke Firewall/SOAR (*Monitoring & Analysis only*).

---

## 🏗️ TECHNICAL ARCHITECTURE

### System Architecture Diagram
```text
┌─────────────────────────────────────────────────────┐
│                   USER (Analyst)                    │
└────────────────────┬────────────────────────────────┘
                     │ HTTP Request (URL / Hash)
        ┌────────────v────────────────────┐
        │   Flask Backend Server          │
        │   - API Endpoints & Validation  │
        │   - PDF Report Generator        │
        └────────┬──────────┬─────────────┘
                 │ (1) Enqueue Task
        ┌────────v──────────v─────────────┐
        │   Redis (Message Broker)        │
        └────────┬──────────┬─────────────┘
                 │ (2) Process Task
        ┌────────v──────────v─────────────┐
        │   Celery Workers (Async)        │
        │   - Parallel API Orchestration  │
        │   - Risk Scoring Logic          │
        └─┬───────┬─────────┬───────────┬─┘
          │       │         │           │
    ┌─────v──┐ ┌──v─────┐ ┌─v────────┐ ┌v────────┐
    │ Virus  │ │URLhaus │ │AbuseIPDB │ │MXToolbox│
    │ Total  │ │API     │ │API       │ │API      │
    └────────┘ └────────┘ └──────────┘ └─────────┘
```

### Database Schema (Updated with New Features)

```sql
-- Identifiers table (URL, IP, or Hash)
CREATE TABLE indicators (
    id SERIAL PRIMARY KEY,
    indicator_value VARCHAR(2048) NOT NULL UNIQUE,
    indicator_type VARCHAR(50), -- 'URL', 'IP', 'DOMAIN', 'HASH'
    internal_status VARCHAR(20) DEFAULT 'UNKNOWN', -- 'WHITELIST', 'BLACKLIST', 'UNKNOWN'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analyses table
CREATE TABLE analyses (
    id SERIAL PRIMARY KEY,
    indicator_id INTEGER REFERENCES indicators(id),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level VARCHAR(20), 
    
    -- API Results
    virustotal_result JSONB,
    urlhaus_result JSONB,
    abuseipdb_result JSONB,
    mxtoolbox_result JSONB,
    
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    response_time_ms INTEGER
);

-- Reports history
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id),
    generated_by VARCHAR(100),
    pdf_file_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## ⏳ IMPLEMENTATION TIMELINE (6 MONTHS)

| Bulan | Fokus Pengerjaan |
|-------|------------------|
| **Bulan 1** | Pengajuan Proposal, Finalisasi Kebutuhan Sistem, Setup Celery/Redis & Flask. |
| **Bulan 2** | Integrasi API (URL & Hash), Skoring Algoritma, Skema PostgreSQL (Whitelist/Blacklist). |
| **Bulan 3** | Pembuatan Dashboard UI, Fitur Analitik, Fitur Export Laporan PDF. |
| **Bulan 4** | Uji Coba Sistem (Blackbox, Performance, Accuracy Testing dengan SOC Data). |
| **Bulan 5** | Pembuatan Laporan TA (Bab 4 & Bab 5), Dokumentasi Kode, Persiapan Demo. |
| **Bulan 6** | Sidang Akhir Tugas Akhir, Revisi Dosen Penguji. |

---
*Document Version: 4.0 (Final Approved MD)*  
*Status: Approved by Pak Rosyid*
