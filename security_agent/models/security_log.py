"""
安全日志数据模型
"""
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class SecurityLog(Base):
    """安全日志数据模型"""
    __tablename__ = "security_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    source_ip = Column(String(50), index=True)
    destination_ip = Column(String(50), index=True)
    event_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)
    protocol = Column(String(20))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    user_id = Column(String(100))
    action = Column(String(50))
    status = Column(String(50))
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    session_duration = Column(Integer)
    description = Column(Text)
    raw_log = Column(Text)
    
    def __repr__(self):
        return f"<SecurityLog(id={self.id}, timestamp={self.timestamp}, event_type={self.event_type})>" 