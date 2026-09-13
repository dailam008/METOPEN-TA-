from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.models import VTAPIKey
from app.services.key_detector import VIRUSTOTAL
from app.utils.timeutil import now_local

class LoadBalancer:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------
    # Filter per jenis API.
    # Row lama (sebelum kolom api_type ada) bisa NULL / string kosong —
    # itu diperlakukan sebagai 'virustotal' supaya key lama tetap kepakai
    # walau migrasi belum dijalanin.
    # ------------------------------------------------------------
    @staticmethod
    def _type_filter(api_type: str):
        api_type = (api_type or VIRUSTOTAL).lower()
        if api_type == VIRUSTOTAL:
            return or_(
                VTAPIKey.api_type == VIRUSTOTAL,
                VTAPIKey.api_type.is_(None),
                VTAPIKey.api_type == "",
            )
        return VTAPIKey.api_type == api_type

    def count_active(self, api_type: str = VIRUSTOTAL) -> int:
        """Jumlah key aktif untuk satu jenis API."""
        return self.db.query(VTAPIKey).filter(
            VTAPIKey.is_active == True,
            self._type_filter(api_type),
        ).count()

    def has_key(self, api_type: str = VIRUSTOTAL) -> bool:
        return self.count_active(api_type) > 0

    def get_best_key(self, api_type: str = VIRUSTOTAL) -> VTAPIKey:
        """
        SMART QUEUE: Pilih API key dengan:
        1. Prioritas: usage_count TERTINGGI (yang mau limit dipake duluan)
        2. Kalo sama: last_used PALING LAMA
        3. Hanya key yang aktif dan health_status fresh/rate_limited/unknown
        4. Hanya key yang api_type-nya cocok (default: virustotal)
        """
        type_filter = self._type_filter(api_type)

        key = self.db.query(VTAPIKey).filter(
            VTAPIKey.is_active == True,
            VTAPIKey.is_error == False,
            VTAPIKey.health_status.in_(['fresh', 'rate_limited', 'unknown']),
            type_filter,
        ).order_by(
            VTAPIKey.usage_count.desc(),  # Usage tinggi = prioritas
            VTAPIKey.last_used.asc()       # Paling lama dipake (MySQL compatible)
        ).first()

        if not key:
            # Fallback: coba key lain yang masih aktif (tetap dibatasi per tipe)
            key = self.db.query(VTAPIKey).filter(
                VTAPIKey.is_active == True,
                type_filter,
            ).order_by(
                VTAPIKey.usage_count.desc()
            ).first()

        return key

    def mark_error(self, key_id: int):
        """Tandai key sebagai error"""
        key = self.db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
        if key:
            key.is_error = True
            key.error_count += 1
            self.db.commit()

    def mark_success(self, key_id: int):
        """Update usage count setelah sukses"""
        key = self.db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
        if key:
            key.usage_count += 1
            # bukan func.now(): di SQLite itu UTC, di MySQL lokal
            key.last_used = now_local()
            self.db.commit()
