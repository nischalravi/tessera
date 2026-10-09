import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = f"sqlite:///{BACKEND_DIR / 'tessera.db'}"


def make_engine(url: str | None = None):
    url = url or os.environ.get("TESSERA_DB", DEFAULT_DB)
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragma(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
    return engine


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db(eng=None, drop: bool = False) -> None:
    eng = eng or engine
    if drop:
        Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)


def get_session():
    s: Session = SessionLocal()
    try:
        yield s
    finally:
        s.close()
