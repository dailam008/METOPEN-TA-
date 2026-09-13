from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Index, Enum
from sqlalchemy.sql import func
from app.database import Base
from app.utils.timeutil import now_local

class VTAPIKey(Base):
    __tablename__ = "vt_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    api_key = Column(String(255), unique=True, nullable=False, index=True)
    # Jenis API pemilik key ini. Sengaja String biasa (bukan Enum) supaya nambah
    # provider baru gak perlu ALTER/migrasi constraint. Default 'virustotal'
    # dipasang di dua sisi (Python + server) biar row lama tetap kebaca sebagai VT.
    api_type = Column(
        String(30),
        default="virustotal",
        server_default="virustotal",
        nullable=False,
        index=True,
    )
    usage_count = Column(Integer, default=0)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    is_error = Column(Boolean, default=False)
    error_count = Column(Integer, default=0)
    # default= (sisi Python) sengaja dipasang: CURRENT_TIMESTAMP-nya SQLite itu UTC,
    # sedangkan MySQL pakai waktu lokal. Tanpa ini, timestamp baru di SQLite
    # bakal mundur 7 jam. server_default dibiarkan sebagai cadangan untuk raw SQL.
    created_at = Column(DateTime, default=now_local, server_default=func.now())
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)
    source = Column(String(100), default="manual")
    notes = Column(Text, nullable=True)
    last_checked = Column(DateTime, nullable=True)
    # name= dibutuhin SQLite: enum di-render jadi VARCHAR + CHECK constraint,
    # dan constraint-nya harus punya nama. Di MySQL tetap jadi ENUM native.
    health_status = Column(
        Enum('fresh', 'rate_limited', 'dead', 'unknown', name='health_status_enum'),
        default='unknown',
        server_default='unknown',
    )

    __table_args__ = (
        Index('idx_active_error', 'is_active', 'is_error'),
        Index('idx_usage', 'usage_count', 'last_used'),
        # Load balancer selalu query per api_type + is_active, jadi indeks
        # gabungannya dibikin eksplisit.
        Index('idx_type_active', 'api_type', 'is_active', 'is_error'),
    )