from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class Threat(Base):
    __tablename__ = "threats"
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id", ondelete="CASCADE"), nullable=False)
    threat_type = Column(String(30), nullable=False) 
    severity = Column(String(10), nullable=False, default="medium")
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    dst_port = Column(Integer)
    description = Column(Text)
    packet_count = Column(Integer, nullable=False, default=0)
    detected_at = Column(DateTime, server_default=func.now())
    is_resolved = Column(Boolean, nullable=False, default=False)
