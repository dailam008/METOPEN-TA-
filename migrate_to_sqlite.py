"""
Migrasi data MySQL -> SQLite untuk VT Proxy Balancer.

AMAN by design:
  - MySQL cuma DIBACA. Tidak ada satu pun statement tulis ke MySQL.
  - Backup dulu (mysqldump kalau tersedia + backup file SQLite lama).
  - Semua insert dalam SATU transaksi. Gagal di tengah -> rollback penuh
    dan file SQLite yang setengah jadi dihapus.
  - Verifikasi otomatis setelah migrasi (jumlah baris + perbandingan isi baris).

Pemakaian:
    python migrate_to_sqlite.py                 # backup -> migrasi -> verifikasi
    python migrate_to_sqlite.py --dry-run       # cuma baca & laporan, tidak nulis
    python migrate_to_sqlite.py --force         # timpa vt_proxy.db yang sudah ada
    python migrate_to_sqlite.py --verify-only   # bandingin MySQL vs SQLite yang ada
    python migrate_to_sqlite.py --no-dump       # skip mysqldump
    python migrate_to_sqlite.py --source ... --target ...
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import subprocess
import sys
import glob

from sqlalchemy import select, func
from sqlalchemy.engine import make_url

# app.* diimport setelah path project ditambahkan
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings                      # noqa: E402
from app.database import Base, build_engine          # noqa: E402
from app import models                               # noqa: E402,F401  (daftarin tabel ke metadata)

# Urutan penting: parent dulu, baru yang punya foreign key.
TABLE_ORDER = ["vt_api_keys", "api_usage_log", "cache_scans"]

# Kolom pembanding waktu verifikasi (identitas logis tiap baris)
IDENTITY_COLUMNS = {
    "vt_api_keys": ("api_key",),
    "api_usage_log": ("id",),
    "cache_scans": ("identifier", "scan_type"),
}

BATCH_SIZE = 500


# ---------------------------------------------------------------- utilities
def log(msg: str = "") -> None:
    # Console Windows sering cp1252, jadi jangan sampai print bikin script mati
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"), flush=True)


def section(title: str) -> None:
    log("")
    log("=" * 66)
    log(f"  {title}")
    log("=" * 66)


def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def sqlite_file_of(url: str) -> str | None:
    u = make_url(url)
    if u.get_backend_name() != "sqlite" or not u.database or u.database == ":memory:":
        return None
    return os.path.abspath(u.database)


# ---------------------------------------------------------------- backup
def find_mysqldump() -> str | None:
    found = shutil.which("mysqldump")
    if found:
        return found
    # Laragon menaruh binary MySQL di luar PATH
    for pattern in (
        r"C:\laragon\bin\mysql\*\bin\mysqldump.exe",
        r"C:\xampp\mysql\bin\mysqldump.exe",
    ):
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[-1]
    return None


def backup_mysql(source_url: str, backup_dir: str) -> str | None:
    """Dump MySQL ke file .sql. Balikin path-nya, atau None kalau tidak bisa."""
    dump = find_mysqldump()
    if not dump:
        log("  [!] mysqldump tidak ketemu -> skip dump SQL.")
        log("      (migrasi tetap aman: MySQL tidak pernah ditulis)")
        return None

    u = make_url(source_url)
    os.makedirs(backup_dir, exist_ok=True)
    out = os.path.join(backup_dir, f"mysql-{u.database}-{timestamp()}.sql")

    cmd = [
        dump,
        f"--host={u.host or 'localhost'}",
        f"--port={u.port or 3306}",
        f"--user={u.username}",
        f"--password={u.password or ''}",
        "--single-transaction",
        "--routines",
        "--events",
        u.database,
    ]
    try:
        with open(out, "w", encoding="utf-8") as fh:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
    except Exception as exc:
        log(f"  [!] mysqldump gagal dijalankan: {exc}")
        return None

    if proc.returncode != 0:
        log(f"  [!] mysqldump exit {proc.returncode}: {proc.stderr.strip()[:300]}")
        return None

    log(f"  [OK] Backup MySQL -> {out} ({os.path.getsize(out):,} bytes)")
    return out


def backup_existing_sqlite(db_path: str, backup_dir: str) -> str | None:
    if not os.path.exists(db_path):
        return None
    os.makedirs(backup_dir, exist_ok=True)
    dest = os.path.join(backup_dir, f"{os.path.basename(db_path)}-{timestamp()}.bak")
    shutil.copy2(db_path, dest)
    log(f"  [OK] Backup SQLite lama -> {dest}")
    return dest


def remove_sqlite_files(db_path: str) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)


# ---------------------------------------------------------------- read/copy
def read_table(conn, table) -> list[dict]:
    rows = conn.execute(select(table).order_by(*table.primary_key.columns)).mappings().all()
    return [dict(r) for r in rows]


def copy_rows(target_conn, table, rows: list[dict]) -> int:
    """Insert per batch. Kolom disebut eksplisit, termasuk id, biar PK terjaga."""
    if not rows:
        return 0
    cols = [c.name for c in table.columns]
    payload = [{c: row.get(c) for c in cols} for row in rows]
    for i in range(0, len(payload), BATCH_SIZE):
        target_conn.execute(table.insert(), payload[i:i + BATCH_SIZE])
    return len(payload)


# ---------------------------------------------------------------- verify
def normalize(value):
    """Samain bentuk nilai dari dua dialect sebelum dibandingkan."""
    if isinstance(value, dt.datetime):
        return value.replace(microsecond=0).isoformat()
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    if hasattr(value, "value"):          # enum member -> nilai stringnya
        return value.value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


def row_key(table_name: str, row: dict):
    return tuple(normalize(row.get(c)) for c in IDENTITY_COLUMNS[table_name])


def verify(src_engine, tgt_engine) -> bool:
    section("VERIFIKASI")
    ok = True

    with src_engine.connect() as src, tgt_engine.connect() as tgt:
        for name in TABLE_ORDER:
            table = Base.metadata.tables[name]

            src_count = src.execute(select(func.count()).select_from(table)).scalar_one()
            tgt_count = tgt.execute(select(func.count()).select_from(table)).scalar_one()

            status = "OK " if src_count == tgt_count else "BEDA"
            log(f"  [{status}] {name:<16} MySQL={src_count:<6} SQLite={tgt_count}")
            if src_count != tgt_count:
                ok = False
                continue

            src_rows = {row_key(name, r): r for r in read_table(src, table)}
            tgt_rows = {row_key(name, r): r for r in read_table(tgt, table)}

            missing = set(src_rows) - set(tgt_rows)
            extra = set(tgt_rows) - set(src_rows)
            if missing:
                ok = False
                log(f"         !! {len(missing)} baris hilang di SQLite: {list(missing)[:3]}")
            if extra:
                ok = False
                log(f"         !! {len(extra)} baris asing di SQLite: {list(extra)[:3]}")

            diffs = 0
            for key in set(src_rows) & set(tgt_rows):
                a, b = src_rows[key], tgt_rows[key]
                for col in table.columns.keys():
                    if normalize(a.get(col)) != normalize(b.get(col)):
                        diffs += 1
                        if diffs <= 5:
                            log(f"         !! {key} kolom '{col}': "
                                f"MySQL={a.get(col)!r} vs SQLite={b.get(col)!r}")
            if diffs:
                ok = False
                log(f"         !! total {diffs} kolom beda di {name}")

    # Cek spesifik yang paling penting: API key jangan sampai hilang/berubah
    with src_engine.connect() as src, tgt_engine.connect() as tgt:
        t = Base.metadata.tables["vt_api_keys"]
        src_keys = {r[0] for r in src.execute(select(t.c.api_key))}
        tgt_keys = {r[0] for r in tgt.execute(select(t.c.api_key))}
        if src_keys == tgt_keys:
            log(f"\n  [OK ] {len(src_keys)} API key cocok persis (string penuh dibandingkan)")
        else:
            ok = False
            log(f"\n  [GAGAL] API key TIDAK cocok! hilang={len(src_keys - tgt_keys)} "
                f"asing={len(tgt_keys - src_keys)}")

    log("")
    log("  HASIL: " + ("SEMUA DATA COCOK" if ok else "ADA SELISIH - JANGAN pakai SQLite dulu"))
    return ok


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Migrasi MySQL -> SQLite (VT Proxy)")
    ap.add_argument("--source", default=settings.MYSQL_URL, help="URL MySQL sumber")
    ap.add_argument("--target", default=settings.SQLITE_URL, help="URL SQLite tujuan")
    ap.add_argument("--force", action="store_true", help="timpa file SQLite yang sudah ada")
    ap.add_argument("--dry-run", action="store_true", help="baca saja, tidak menulis apa pun")
    ap.add_argument("--verify-only", action="store_true", help="cuma bandingin dua database")
    ap.add_argument("--no-dump", action="store_true", help="skip mysqldump")
    ap.add_argument("--backup-dir", default="backups")
    args = ap.parse_args()

    src_url, tgt_url = args.source.strip(), args.target.strip()
    db_path = sqlite_file_of(tgt_url)

    section("VT PROXY - MIGRASI MySQL ke SQLite")
    log(f"  Sumber : {make_url(src_url).render_as_string(hide_password=True)}")
    log(f"  Tujuan : {tgt_url}")
    log(f"  File   : {db_path}")

    src_engine = build_engine(src_url)
    try:
        with src_engine.connect() as conn:
            conn.execute(select(1))
    except Exception as exc:
        log(f"\n  [GAGAL] Tidak bisa connect ke MySQL: {exc}")
        log("  Pastikan MySQL (Laragon) sedang jalan.")
        return 1

    # ---- laporan isi sumber
    section("ISI DATABASE SUMBER")
    counts = {}
    with src_engine.connect() as conn:
        for name in TABLE_ORDER:
            table = Base.metadata.tables[name]
            counts[name] = conn.execute(select(func.count()).select_from(table)).scalar_one()
            log(f"  {name:<16} : {counts[name]} baris")

    if args.verify_only:
        if not db_path or not os.path.exists(db_path):
            log(f"\n  [GAGAL] File SQLite belum ada: {db_path}")
            return 1
        return 0 if verify(src_engine, build_engine(tgt_url)) else 1

    if args.dry_run:
        log("\n  [DRY-RUN] Berhenti di sini. Tidak ada yang ditulis.")
        return 0

    # ---- backup
    section("BACKUP")
    if not args.no_dump:
        backup_mysql(src_url, args.backup_dir)
    else:
        log("  Dump MySQL di-skip (--no-dump)")

    if db_path and os.path.exists(db_path):
        if not args.force:
            log(f"\n  [GAGAL] {db_path} sudah ada.")
            log("  Pakai --force kalau memang mau ditimpa (file lama otomatis di-backup).")
            return 1
        backup_existing_sqlite(db_path, args.backup_dir)
        remove_sqlite_files(db_path)
        log("  [OK] File SQLite lama dibersihkan")

    # ---- bikin schema + copy
    section("MIGRASI")
    tgt_engine = build_engine(tgt_url)
    created_fresh = True

    try:
        Base.metadata.create_all(bind=tgt_engine)
        log("  [OK] Schema SQLite dibuat dari model SQLAlchemy")

        total = 0
        with src_engine.connect() as src, tgt_engine.begin() as tgt:
            for name in TABLE_ORDER:
                table = Base.metadata.tables[name]
                rows = read_table(src, table)
                written = copy_rows(tgt, table, rows)
                total += written
                log(f"  [OK] {name:<16} {written} baris disalin")
            # transaksi commit otomatis saat blok `begin()` selesai tanpa error
        log(f"  [OK] Commit. Total {total} baris.")

    except Exception as exc:
        log(f"\n  [GAGAL] Migrasi dibatalkan: {type(exc).__name__}: {exc}")
        log("  Transaksi di-rollback. MySQL tidak tersentuh sama sekali.")
        tgt_engine.dispose()
        if created_fresh and db_path:
            remove_sqlite_files(db_path)
            log(f"  File SQLite setengah jadi dihapus: {db_path}")
        return 1

    # ---- verifikasi
    passed = verify(src_engine, tgt_engine)

    section("LANGKAH BERIKUTNYA")
    if passed:
        log("  1. Edit .env  ->  DB_BACKEND=sqlite")
        log("  2. Restart server: uvicorn app.main:app --reload")
        log("  3. Cek: http://localhost:8000/health dan /dashboard/stats")
        log("  4. Balik ke MySQL kapan pun: DB_BACKEND=mysql")
        log(f"\n  File SQLite: {db_path}")
    else:
        log("  Verifikasi GAGAL. Jangan ganti DB_BACKEND.")
        log("  MySQL masih utuh - server tetap bisa jalan seperti biasa.")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
