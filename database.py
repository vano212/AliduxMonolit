from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    devices = relationship("Device", back_populates="owner")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    chip_id = Column(String, unique=True, index=True)
    token = Column(String, unique=True)
    name = Column(String, default="Датчик Alidux")

    # Состояние
    leak_status = Column(Integer, default=0)
    voltage = Column(Float, default=0.0)
    battery = Column(Integer, default=0)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Флаг для удаленного сброса (когда юзер нажал "Удалить")
    pending_reset = Column(Boolean, default=False)

    owner = relationship("User", back_populates="devices")


class PairingCode(Base):
    __tablename__ = "pairing_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    code = Column(String(6), unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String)  # INFO, WARN, ERROR
    message = Column(String)
    user_id = Column(Integer, nullable=True)