from sqlalchemy import Column, Integer, String, DateTime, JSON, Enum, Index, UniqueConstraint
from sqlalchemy.sql import func
from app.database import Base
from app.utils.timeutil import now_local
import enum

class ScanType(str, enum.Enum):
    HASH = "hash"
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    # Dipakai routing MxToolbox (email / mail header). Ditaruh di enum yang sama
    # supaya cache multi-source tetap satu tabel.
    EMAIL = "email"

class CacheScan(Base):
    __tablename__ = "cache_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(
        Enum(ScanType, name='scan_type_enum', values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    identifier = Column(String(500), nullable=False)
    # Sumber intel yang ngasih response ini: virustotal | abuseipdb | urlhaus | mxtoolbox.
    # Row lama (sebelum multi-source) otomatis dianggap 'virustotal'.
    source = Column(
        String(30),
        default="virustotal",
        server_default="virustotal",
        nullable=False,
        index=True,
    )
    # Nama kolomnya tetap vt_response biar row lama & query lama gak pecah,
    # walaupun sekarang isinya bisa response dari API mana pun (lihat kolom source).
    vt_response = Column(JSON, nullable=False)
    hits = Column(Integer, default=0, server_default='0')
    # default= sisi Python: CURRENT_TIMESTAMP SQLite itu UTC, MySQL lokal
    scan_date = Column(DateTime, default=now_local, server_default=func.now())
    created_at = Column(DateTime, default=now_local, server_default=func.now())

    # Constraint & index ini sudah ada di MySQL tapi belum pernah ditulis di model,
    # jadi kalau bikin DB baru (SQLite) dedupe cache-nya bakal hilang. Ditulis ulang
    # di sini biar kedua backend punya schema yang sama.
    # source ikut masuk unique key: satu identifier boleh punya 1 cache per API.
    __table_args__ = (
        UniqueConstraint('identifier', 'scan_type', 'source', name='unique_identifier_type_source'),
        Index('idx_identifier', 'identifier'),
        Index('idx_scan_date', 'scan_date'),
        Index('idx_source_type', 'source', 'scan_type'),
    )
