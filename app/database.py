from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
import os

Base = declarative_base()


def _prepare_sqlite_path(url_str: str) -> None:
    """Pastikan folder tujuan file .db ada (kalau URL-nya pakai subfolder)."""
    url = make_url(url_str)
    if not url.database or url.database == ":memory:":
        return
    folder = os.path.dirname(os.path.abspath(url.database))
    if folder:
        os.makedirs(folder, exist_ok=True)


def build_engine(url: str, echo: bool = False):
    """
    Bikin engine yang cocok buat dialect-nya.
    Dipakai app maupun script migrasi, jadi konfigurasinya selalu sama.
    """
    if url.startswith("sqlite"):
        _prepare_sqlite_path(url)
        engine = create_engine(
            url,
            echo=echo,
            future=True,
            # FastAPI jalanin endpoint sync di threadpool + ada APScheduler
            # di thread lain, jadi koneksi harus boleh lintas-thread.
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            # FK ondelete di api_usage_log cuma jalan kalau ini ON
            cur.execute("PRAGMA foreign_keys=ON")
            # WAL: baca & tulis bisa barengan (dashboard + scheduler)
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            # Jangan langsung "database is locked" kalau lagi rebutan
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

        return engine

    # MySQL / MariaDB
    return create_engine(
        url,
        echo=echo,
        future=True,
        pool_pre_ping=True,   # buang koneksi yang udah mati
        pool_recycle=3600,    # MySQL wait_timeout default 8 jam
    )


engine = build_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    # import models supaya semua tabel kedaftar di metadata sebelum create_all
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
