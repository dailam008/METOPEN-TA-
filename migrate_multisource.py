"""
Migrasi ke MULTI-SOURCE THREAT INTELLIGENCE.

Yang dikerjain:
  1. vt_api_keys  : + kolom api_type (default 'virustotal') + index
  2. cache_scans  : + kolom source   (default 'virustotal') + index
  3. cache_scans  : unique key (identifier, scan_type) -> (identifier, scan_type, source)
  4. cache_scans  : scan_type nerima nilai baru 'email' (khusus MySQL/MariaDB)
  5. Backfill semua row lama jadi 'virustotal' -> data & key lama tetap jalan

Aman dijalanin berkali-kali (idempotent). Bikin backup dulu buat SQLite.

Pakai:
    python migrate_multisource.py
    python migrate_multisource.py --dry-run     # cuma lihat rencananya
"""

import shutil
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url

from app.config import settings
from app.database import engine

DRY_RUN = "--dry-run" in sys.argv

VT = "virustotal"

# Console Windows default-nya cp1252 dan bakal crash kena emoji di log.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(msg: str):
    print(msg, flush=True)


def run(conn, sql: str, label: str = None):
    if DRY_RUN:
        log(f"   [dry-run] {label or sql}")
        return
    conn.execute(text(sql))
    if label:
        log(f"   ✓ {label}")


# ============================================================
# BACKUP (SQLite)
# ============================================================
def backup_sqlite():
    url = make_url(settings.DATABASE_URL)
    if not url.database or url.database == ":memory:":
        return None
    src = Path(url.database)
    if not src.exists():
        return None

    backups = src.parent / "backups"
    backups.mkdir(exist_ok=True)
    dst = backups / f"{src.stem}_premultisource_{datetime.now():%Y%m%d_%H%M%S}{src.suffix}"
    if DRY_RUN:
        log(f"   [dry-run] backup -> {dst}")
        return dst
    shutil.copy2(src, dst)
    log(f"   ✓ Backup: {dst}")
    return dst


# ============================================================
# HELPERS
# ============================================================
# PENTING: inspeksi harus lewat connection yang SAMA dengan yang dipakai DDL.
# Kalau pakai inspect(engine), dia buka koneksi baru dan gak bisa lihat
# perubahan yang belum di-commit (di SQLite malah bisa kena "database locked").
def columns_of(conn, table: str) -> set:
    insp = inspect(conn)
    if table not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns(table)}


def indexes_of(conn, table: str) -> set:
    insp = inspect(conn)
    if table not in insp.get_table_names():
        return set()
    return {i["name"] for i in insp.get_indexes(table)}


def table_exists(conn, table: str) -> bool:
    return table in inspect(conn).get_table_names()


# Di mode dry-run gak ada DDL yang benar-benar jalan, jadi perubahan "seolah-olah"
# dicatat di sini supaya langkah berikutnya tetap kelihatan rencananya.
_PENDING = set()


def has_column(conn, table: str, col: str) -> bool:
    if DRY_RUN and (table, col) in _PENDING:
        return True
    return col in columns_of(conn, table)


def has_index(conn, table: str, name: str) -> bool:
    if DRY_RUN and (table, name) in _PENDING:
        return True
    return name in indexes_of(conn, table)


# ============================================================
# 1 & 2. TAMBAH KOLOM
# ============================================================
def add_columns(conn):
    log("\n[1/4] Menambah kolom api_type & source…")

    if not table_exists(conn, "vt_api_keys"):
        log("   ! Tabel vt_api_keys belum ada — jalankan aplikasi sekali dulu.")
    elif has_column(conn, "vt_api_keys", "api_type"):
        log("   · vt_api_keys.api_type sudah ada, dilewati")
    else:
        run(conn,
            "ALTER TABLE vt_api_keys ADD COLUMN api_type VARCHAR(30) NOT NULL DEFAULT 'virustotal'",
            "vt_api_keys.api_type ditambahkan")
        _PENDING.add(("vt_api_keys", "api_type"))

    if not table_exists(conn, "cache_scans"):
        log("   ! Tabel cache_scans belum ada — jalankan aplikasi sekali dulu.")
    elif has_column(conn, "cache_scans", "source"):
        log("   · cache_scans.source sudah ada, dilewati")
    else:
        run(conn,
            "ALTER TABLE cache_scans ADD COLUMN source VARCHAR(30) NOT NULL DEFAULT 'virustotal'",
            "cache_scans.source ditambahkan")
        _PENDING.add(("cache_scans", "source"))


# ============================================================
# 3. BACKFILL
# ============================================================
def backfill(conn):
    log("\n[2/4] Backfill data lama -> 'virustotal'…")

    if has_column(conn, "vt_api_keys", "api_type"):
        if DRY_RUN:
            log("   [dry-run] UPDATE vt_api_keys SET api_type='virustotal' WHERE api_type IS NULL OR api_type=''")
        else:
            r = conn.execute(text(
                "UPDATE vt_api_keys SET api_type = :vt WHERE api_type IS NULL OR api_type = ''"
            ), {"vt": VT})
            log(f"   ✓ {r.rowcount} API key lama ditandai sebagai VirusTotal")

    if has_column(conn, "cache_scans", "source"):
        if DRY_RUN:
            log("   [dry-run] UPDATE cache_scans SET source='virustotal' WHERE source IS NULL OR source=''")
        else:
            r = conn.execute(text(
                "UPDATE cache_scans SET source = :vt WHERE source IS NULL OR source = ''"
            ), {"vt": VT})
            log(f"   ✓ {r.rowcount} entri cache lama ditandai sebagai VirusTotal")


# ============================================================
# 4. UNIQUE KEY cache_scans -> (identifier, scan_type, source)
# ============================================================
UNIQUE_OLD = "unique_identifier_type"
UNIQUE_NEW = "unique_identifier_type_source"


def _sqlite_unique_is_new(conn) -> bool:
    """Cek apakah unique constraint cache_scans sudah termasuk kolom source."""
    row = conn.execute(text(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='cache_scans'"
    )).fetchone()
    if not row or not row[0]:
        return True
    ddl = row[0].lower()
    return "unique (identifier, scan_type, source)" in ddl.replace("  ", " ")


def rebuild_unique_sqlite(conn):
    log("\n[3/4] Perbarui unique key cache_scans (SQLite: rebuild tabel)…")

    if not table_exists(conn, "cache_scans"):
        log("   · cache_scans belum ada, dilewati")
        return

    if _sqlite_unique_is_new(conn):
        log("   · Unique key sudah (identifier, scan_type, source), dilewati")
        return

    if DRY_RUN:
        log("   [dry-run] rebuild cache_scans dengan UNIQUE (identifier, scan_type, source)")
        return

    # SQLite gak bisa DROP CONSTRAINT — harus bikin tabel baru lalu copy.
    conn.execute(text("PRAGMA foreign_keys=OFF"))
    conn.execute(text("""
        CREATE TABLE cache_scans_new (
            id INTEGER NOT NULL,
            scan_type VARCHAR(10) NOT NULL,
            identifier VARCHAR(500) NOT NULL,
            source VARCHAR(30) NOT NULL DEFAULT 'virustotal',
            vt_response JSON NOT NULL,
            hits INTEGER DEFAULT '0',
            scan_date DATETIME DEFAULT (CURRENT_TIMESTAMP),
            created_at DATETIME DEFAULT (CURRENT_TIMESTAMP),
            PRIMARY KEY (id),
            CONSTRAINT unique_identifier_type_source UNIQUE (identifier, scan_type, source)
        )
    """))
    conn.execute(text("""
        INSERT INTO cache_scans_new (id, scan_type, identifier, source, vt_response, hits, scan_date, created_at)
        SELECT id, scan_type, identifier,
               COALESCE(NULLIF(source, ''), 'virustotal'),
               vt_response, hits, scan_date, created_at
        FROM cache_scans
    """))
    conn.execute(text("DROP TABLE cache_scans"))
    conn.execute(text("ALTER TABLE cache_scans_new RENAME TO cache_scans"))
    conn.execute(text("PRAGMA foreign_keys=ON"))
    log("   ✓ cache_scans dibangun ulang dengan unique (identifier, scan_type, source)")


def rebuild_unique_mysql(conn):
    log("\n[3/4] Perbarui unique key cache_scans (MySQL)…")

    unique_names = {
        r[2] for r in conn.execute(text("SHOW INDEXES FROM cache_scans")).fetchall()
    }

    if UNIQUE_NEW in unique_names:
        log("   · Unique key baru sudah ada, dilewati")
    else:
        if UNIQUE_OLD in unique_names:
            run(conn, f"ALTER TABLE cache_scans DROP INDEX {UNIQUE_OLD}", "unique key lama dihapus")
        run(conn,
            f"ALTER TABLE cache_scans ADD CONSTRAINT {UNIQUE_NEW} UNIQUE (identifier, scan_type, source)",
            "unique key (identifier, scan_type, source) dibuat")

    # ENUM scan_type perlu nerima 'email'
    run(conn,
        "ALTER TABLE cache_scans MODIFY COLUMN scan_type "
        "ENUM('hash','url','ip','domain','email') NOT NULL",
        "scan_type sekarang menerima 'email'")


# ============================================================
# 5. INDEX TAMBAHAN
# ============================================================
def add_indexes(conn):
    log("\n[4/4] Menambah index pendukung…")

    if not table_exists(conn, "vt_api_keys"):
        pass
    elif has_index(conn, "vt_api_keys", "idx_type_active"):
        log("   · idx_type_active sudah ada, dilewati")
    else:
        run(conn,
            "CREATE INDEX idx_type_active ON vt_api_keys (api_type, is_active, is_error)",
            "idx_type_active (vt_api_keys)")

    if not table_exists(conn, "cache_scans"):
        return

    # Catatan: rebuild tabel di langkah 3 ikut menghapus index lama cache_scans,
    # jadi semuanya dibuat ulang di sini.
    for name, ddl in [
        ("ix_cache_scans_source", "CREATE INDEX ix_cache_scans_source ON cache_scans (source)"),
        ("idx_source_type", "CREATE INDEX idx_source_type ON cache_scans (source, scan_type)"),
        ("idx_identifier", "CREATE INDEX idx_identifier ON cache_scans (identifier)"),
        ("idx_scan_date", "CREATE INDEX idx_scan_date ON cache_scans (scan_date)"),
        ("ix_cache_scans_id", "CREATE INDEX ix_cache_scans_id ON cache_scans (id)"),
    ]:
        if has_index(conn, "cache_scans", name):
            log(f"   · {name} sudah ada, dilewati")
        else:
            run(conn, ddl, name)


# ============================================================
# VERIFIKASI
# ============================================================
def verify(conn):
    log("\n=== VERIFIKASI ===")
    try:
        rows = conn.execute(text(
            "SELECT api_type, COUNT(*) FROM vt_api_keys GROUP BY api_type"
        )).fetchall()
        log("API key per provider:")
        for t, n in rows:
            log(f"   {t or '(null)'}: {n}")

        rows = conn.execute(text(
            "SELECT source, COUNT(*), COALESCE(SUM(hits),0) FROM cache_scans GROUP BY source"
        )).fetchall()
        log("Cache per sumber:")
        for s, n, h in rows:
            log(f"   {s or '(null)'}: {n} entri, {h} hits")
    except Exception as e:
        log(f"   ! Verifikasi gagal: {e}")


def main():
    log("=" * 62)
    log("  MIGRASI MULTI-SOURCE THREAT INTELLIGENCE")
    log("=" * 62)
    log(f"Backend : {settings.DB_BACKEND}")
    log(f"Database: {settings.DATABASE_URL}")
    if DRY_RUN:
        log(">>> MODE DRY-RUN — tidak ada perubahan yang ditulis <<<")

    is_sqlite = settings.IS_SQLITE
    if is_sqlite:
        log("\n[0/4] Backup database…")
        backup_sqlite()

    with engine.begin() as conn:
        add_columns(conn)
        backfill(conn)
        if is_sqlite:
            rebuild_unique_sqlite(conn)
        else:
            rebuild_unique_mysql(conn)
        add_indexes(conn)

    if not DRY_RUN:
        with engine.connect() as conn:
            verify(conn)

    log("\n✅ Migrasi selesai. Restart aplikasi: uvicorn app.main:app --reload")


if __name__ == "__main__":
    main()
