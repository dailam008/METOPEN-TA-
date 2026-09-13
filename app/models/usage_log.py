from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from app.database import Base
from app.utils.timeutil import now_local

class APIUsageLog(Base):
    __tablename__ = "api_usage_log"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("vt_api_keys.id", ondelete="SET NULL"))
    endpoint = Column(String(255))
    response_time_ms = Column(Integer)
    status_code = Column(Integer)
    request_payload = Column(JSON)
    response_payload = Column(JSON)
    client_ip = Column(String(45))
    created_at = Column(DateTime, default=now_local, server_default=func.now())