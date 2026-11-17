from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func
from app.database import Base

class Packet(Base):
  __tablename__ = "packets"
  id = Column(BigInteger, primary_key=True, index=True)
  capture_id = Column(Integer, ForeignKey("captures.id", ondelete="CASCADE"), nullable=False, index=True,)
  timestamp = Column(DateTime)
  src_ip = Column(String(45))
  dst_ip = Column(String(45))
  src_port = Column(Integer, nullable=True)
  dst_port = Column(Integer, nullable=True)
  protocol = Column(String(10), nullable=False)
  length = Column(Integer, nullable=False)
  tcp_flags = Column(String(20), nullable=True)
