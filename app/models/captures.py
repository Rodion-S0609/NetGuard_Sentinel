from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func
from app.database import Base

class Capture(Base):
  __tablename__ = "captures"
  id = Column(Integer, primary_key=True, index=True)
  user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,)
  filename = Column(String(255), nullable=False)
  uploaded_at = Column(DateTime, server_default=func.now())
  total_packets = Column(Integer, nullable=False, default=0)
  status = Column(String(20), nullable=False, default="processing")
