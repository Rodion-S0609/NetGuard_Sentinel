from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func
from app.database import Base

class BlockedIP(Base):
  __tablename__ = "blocked_ips"
  id = Column(Integer, primary_key=True, index=True)
  ip_address = Column(String(45), unique=True, nullable=False)
  reason = Column(String(255))
  blocked_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)  # NULL — если авто
  is_auto = Column(Boolean, nullable=False, default=False)
  blocked_at = Column(DateTime, server_default=func.now())
