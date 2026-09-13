"""
Script untuk fix MySQL ENUM kolom scan_type di tabel cache_scans.
Mengubah ENUM dari UPPERCASE (HASH, URL, IP, DOMAIN) ke lowercase (hash, url, ip, domain)
supaya match dengan Python ScanType enum values.

AMAN: Tidak menyentuh tabel vt_api_keys sama sekali.
"""
from sqlalchemy import create_engine, text
from app.config import settings

engine = create_engine(settings.DATABASE_URL)

with engine.connect() as conn:
    # Step 1: Update data yang sudah ada dari UPPERCASE ke lowercase
    print("[1/3] Updating existing data to lowercase...")
    conn.execute(text("""
        UPDATE cache_scans SET scan_type = LOWER(scan_type)
        WHERE scan_type IN ('HASH', 'URL', 'IP', 'DOMAIN')
    """))
    conn.commit()
    print("      Done!")

    # Step 2: ALTER kolom ENUM ke lowercase values
    print("[2/3] Altering ENUM column to lowercase values...")
    conn.execute(text("""
        ALTER TABLE cache_scans 
        MODIFY COLUMN scan_type ENUM('hash', 'url', 'ip', 'domain') NOT NULL
    """))
    conn.commit()
    print("      Done!")

    # Step 3: Verifikasi
    print("[3/3] Verifying...")
    result = conn.execute(text("SHOW COLUMNS FROM cache_scans LIKE 'scan_type'"))
    row = result.fetchone()
    print(f"      Column type: {row[1]}")
    
    count = conn.execute(text("SELECT COUNT(*) FROM cache_scans")).fetchone()[0]
    print(f"      Total rows preserved: {count}")

print("\n✅ Fix complete! Restart server kamu sekarang.")
