"""
Sumber waktu tunggal buat kolom timestamp.

Kenapa perlu: CURRENT_TIMESTAMP di SQLite selalu UTC, sedangkan di MySQL
ikut timezone server (lokal). Kalau timestamp diserahin ke database,
data lama (dari MySQL, waktu lokal) dan data baru (dari SQLite, UTC)
bakal beda 7 jam dan urutan di dashboard jadi kacau.

Solusinya: waktu dibikin di sisi Python, jadi dua backend hasilnya sama.
"""
import datetime


def now_local() -> datetime.datetime:
    """Waktu lokal tanpa tzinfo, sama seperti NOW() di MySQL."""
    return datetime.datetime.now().replace(microsecond=0)
