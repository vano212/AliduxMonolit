from contextlib import asynccontextmanager
import re
import random
import secrets
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, Form, HTTPException, Request, Body
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Boolean, ForeignKey, Text, Index, UniqueConstraint, Float
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import jwt
from pydantic import BaseModel, field_validator

# ─── DATABASE CONFIGURATION ──────────────────────────────────────────────────
DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_size=10,
    max_overflow=20,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─── MODELS ──────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owned_devices = relationship("Device", back_populates="owner", foreign_keys="Device.user_id")
    shared_accesses = relationship("DeviceAccess", back_populates="user", foreign_keys="DeviceAccess.user_id")
    pairing_codes = relationship("PairingCode", back_populates="user", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    chip_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False, default="Новое устройство")
    token = Column(String(128), unique=True, index=True, nullable=False)
    device_type = Column(String(32), default="water_sensor")

    is_active = Column(Boolean, default=True)
    is_confirmed = Column(Boolean, default=False)
    leak_status = Column(Boolean, default=False)
    valve_open = Column(Boolean, default=True)
    valve_percent = Column(Integer, default=100)

    voltage = Column(Float, default=0.0)
    battery = Column(Integer, default=100)

    # Флаг для удаленного сброса (когда юзер удаляет устройство из приложения)
    pending_reset = Column(Boolean, default=False)

    last_seen = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    valve_open = Column(Boolean, default=True)
    valve_pending = Column(Boolean, default=False)

    owner = relationship("User", back_populates="owned_devices", foreign_keys=[user_id])
    logs = relationship("DeviceLog", back_populates="device", cascade="all, delete-orphan",
                        order_by="DeviceLog.timestamp.desc()")
    accesses = relationship("DeviceAccess", back_populates="device", cascade="all, delete-orphan")


class PairingCode(Base):
    """6-значный код привязки, живет 5 минут"""
    __tablename__ = "pairing_codes"
    id = Column(Integer, primary_key=True)
    code = Column(String(6), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="pairing_codes")


class DeviceLog(Base):
    __tablename__ = "device_logs"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    message = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    device = relationship("Device", back_populates="logs")


class SystemLog(Base):
    """Общий журнал системы (аудит)"""
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True)
    level = Column(String(16), default="INFO")  # INFO, WARN, ERROR
    message = Column(Text)
    user_id = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class DeviceAccess(Base):
    __tablename__ = "device_access"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(16), default="viewer")  # 'viewer' | 'full'
    created_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="accesses")
    user = relationship("User", back_populates="shared_accesses", foreign_keys=[user_id])
    __table_args__ = (UniqueConstraint("device_id", "user_id", name="uq_device_access"),)


Base.metadata.create_all(bind=engine)


# ─── HELPERS ──────────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_event(db: Session, message: str, level="INFO", user_id=None):
    print(f"[{level}] {message}")
    db.add(SystemLog(message=message, level=level, user_id=user_id))
    db.commit()


SECRET_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_BEFORE_DEPLOY"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(pw): return pwd_context.hash(pw)


def verify_password(pl, ha): return pwd_context.verify(pl, ha)


def create_access_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(days=30)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("token")
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: return None
        return db.query(User).filter(User.username == username).first()
    except:
        return None


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    # Здесь мы используем await, так как get_current_user асинхронный
    # Но так как Depends работает по-разному, правильно сделать так:
    return user  # Заглушка, реальная зависимость ниже


async def get_required_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = await get_current_user(request, db)
    if not user: raise HTTPException(401, "Unauthorized")
    return user


def get_device_with_role(device_id: int, user: User, db: Session):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device: raise HTTPException(404, "Устройство не найдено")
    if device.user_id == user.id: return device, "owner"
    access = db.query(DeviceAccess).filter(DeviceAccess.device_id == device_id, DeviceAccess.user_id == user.id).first()
    if access: return device, access.role
    raise HTTPException(404, "Устройство не найдено")


# ─── LIFESPAN & APP INIT ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    if not db.query(User).first():
        db.add(User(username="admin", hashed_password=hash_password("admin123")))
        db.commit()
    db.close()
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")


# Заглушка для favicon, чтобы не было ошибки 404
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


# ─── WEB PAGES (HTML) ─────────────────────────────────────────────────────────

@app.get("/")
async def index(request: Request, db: Session = Depends(get_db)):
    user = await get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("index.html", {"request": request, "username": user.username})


@app.get("/login")
async def login_get(request: Request, db: Session = Depends(get_db)):
    user = await get_current_user(request, db)
    if user: return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_post(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")

    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(key="token", value=create_access_token({"sub": username}), httponly=True, samesite="lax",
                    max_age=60 * 60 * 24 * 30)
    log_event(db, f"Пользователь {username} вошел в систему", user_id=user.id)
    return resp


@app.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("token")
    return resp


@app.get("/register")
async def register_get(request: Request, db: Session = Depends(get_db)):
    user = await get_current_user(request, db)
    if user: return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_post(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if not re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username):
        raise HTTPException(400, "Логин: 3–32 символа, буквы, цифры, _")
    if len(password) < 6:
        raise HTTPException(400, "Пароль должен быть не менее 6 символов")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Пользователь с таким логином уже существует")

    new_user = User(username=username, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()

    resp = RedirectResponse("/?registered=1", status_code=303)
    resp.set_cookie(key="token", value=create_access_token({"sub": username}), httponly=True, samesite="lax",
                    max_age=60 * 60 * 24 * 30)
    log_event(db, f"Зарегистрирован новый пользователь {username}", user_id=new_user.id)
    return resp


# ─── USER API (FRONTEND FETCH) ───────────────────────────────────────────────

@app.get("/api/devices")
async def list_devices(user: User = Depends(get_required_user), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    owned = db.query(Device).filter(Device.user_id == user.id).all()
    shared = db.query(DeviceAccess).filter(DeviceAccess.user_id == user.id).all()

    result = []
    for d in owned:
        result.append({
            "id": d.id, "name": d.name, "chip_id": d.chip_id, "device_type": d.device_type, "role": "owner",
            "is_active": d.is_active, "online": (now - d.last_seen).total_seconds() < 40 if d.last_seen else False,
            "leak": d.leak_status, "valve_open": d.valve_open, "valve_percent": d.valve_percent,
            "battery": d.battery, "voltage": d.voltage, "last_seen": d.last_seen.isoformat() if d.last_seen else None
        })
    for sa in shared:
        d = sa.device
        result.append({
            "id": d.id, "name": d.name, "chip_id": d.chip_id, "device_type": d.device_type, "role": sa.role,
            "is_active": d.is_active, "online": (now - d.last_seen).total_seconds() < 40 if d.last_seen else False,
            "leak": d.leak_status, "valve_open": d.valve_open, "valve_percent": d.valve_percent,
            "battery": d.battery, "voltage": d.voltage, "last_seen": d.last_seen.isoformat() if d.last_seen else None
        })
    return result


@app.get("/api/get-pairing-code")
@app.post("/api/generate-claim-code")  # Добавили этот псевдоним для совместимости
async def api_get_code(user: User = Depends(get_required_user), db: Session = Depends(get_db)):
    """Выдает 6-значный код привязки"""
    # Проверяем, есть ли уже активный код
    existing = db.query(PairingCode).filter(
        PairingCode.user_id == user.id,
        PairingCode.expires_at > datetime.utcnow()
    ).first()

    if existing:
        return {"code": existing.code, "expires_at": existing.expires_at.isoformat()}

    # Если кода нет, генерируем новый
    db.query(PairingCode).filter(PairingCode.user_id == user.id).delete()
    while True:
        code = "".join([str(random.randint(0, 9)) for _ in range(6)])
        if not db.query(PairingCode).filter(PairingCode.code == code).first():
            break

    expires = datetime.utcnow() + timedelta(minutes=5)
    new_code = PairingCode(code=code, user_id=user.id, expires_at=expires)
    db.add(new_code)
    db.commit()
    return {"code": code, "expires_at": expires.isoformat()}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: int, user: User = Depends(get_required_user), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == user.id).first()
    if not device: raise HTTPException(404, "Устройство не найдено")

    # Ставим метку сброса, чтобы плата получила команду стереть настройки при следующем выходе на связь
    device.pending_reset = True
    db.add(DeviceLog(device_id=device.id, event_type="info",
                     message="Устройство помечено на удаление (ожидание сброса платы)"))
    db.commit()
    log_event(db, f"Пользователь {user.username} удалил устройство {device.chip_id}. Метка Reset установлена.",
              user_id=user.id)
    return {"ok": True}


class UpdateRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    valve_open: Optional[bool] = None
    valve_percent: Optional[int] = None # Добавили проценты


@app.patch("/api/devices/{device_id}")
async def update_device(device_id: int, body: UpdateRequest, user: User = Depends(get_required_user),
                        db: Session = Depends(get_db)):
    device, role = get_device_with_role(device_id, user, db)
    if role == "viewer": raise HTTPException(403, "У вас только права просмотра")

    if body.name is not None: device.name = body.name.strip() or device.name
    if body.is_active is not None: device.is_active = body.is_active

    # Логика управления краном
    if body.valve_open is not None:
        if device.valve_open != body.valve_open:
            device.valve_open = body.valve_open
            # Если открываем кнопкой, ставим 100%, если закрываем - 0%
            device.valve_percent = 100 if body.valve_open else 0
            device.valve_pending = True
            msg = "открыть" if body.valve_open else "закрыть"
            db.add(DeviceLog(device_id=device.id, event_type="info", message=f"Запрос: {msg} кран"))

    if body.valve_percent is not None:
        device.valve_percent = max(0, min(100, body.valve_percent))
        device.valve_open = True if device.valve_percent > 0 else False
        device.valve_pending = True
        db.add(DeviceLog(device_id=device.id, event_type="info", message=f"Запрос: установить кран на {device.valve_percent}%"))

    db.commit()
    return {"ok": True}



@app.get("/api/devices/{device_id}/logs")
async def get_logs(device_id: int, user: User = Depends(get_required_user), db: Session = Depends(get_db)):
    device, _ = get_device_with_role(device_id, user, db)
    logs = db.query(DeviceLog).filter(DeviceLog.device_id == device.id).order_by(DeviceLog.timestamp.desc()).limit(
        100).all()
    return [{"time": l.timestamp.isoformat(), "event": l.event_type, "msg": l.message} for l in logs]


class ShareRequest(BaseModel):
    username: str
    role: str = "viewer"


@app.post("/api/devices/{device_id}/share")
async def share_device(device_id: int, body: ShareRequest, user: User = Depends(get_required_user),
                       db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == user.id).first()
    if not device: raise HTTPException(403, "Только владелец может делиться доступом")

    target = db.query(User).filter(User.username == body.username).first()
    if not target or target.id == user.id: raise HTTPException(404, "Некорректный пользователь")

    existing = db.query(DeviceAccess).filter(DeviceAccess.device_id == device_id,
                                             DeviceAccess.user_id == target.id).first()
    if existing:
        existing.role = body.role
        db.commit()
        return {"ok": True, "updated": True}

    db.add(DeviceAccess(device_id=device_id, user_id=target.id, role=body.role))
    db.add(DeviceLog(device_id=device_id, event_type="shared", message=f"Доступ выдан {target.username}"))
    db.commit()
    return {"ok": True}


# ─── HARDWARE API (ДЛЯ ПЛАТЫ ESP8266) ────────────────────────────────────────

@app.post("/device/register")
async def device_register(body: dict = Body(...), db: Session = Depends(get_db)):
    # 1. Получаем данные и чистим их от лишних пробелов
    chip_id = str(body.get("chip_id", "")).strip()
    p_code = str(body.get("pairing_code", "")).strip()

    if not chip_id or not p_code:
        raise HTTPException(400, "chip_id и pairing_code обязательны")

    # 2. Ищем код привязки в базе (проверяем и время жизни)
    code_entry = db.query(PairingCode).filter(
        PairingCode.code == p_code,
        PairingCode.expires_at > datetime.utcnow()
    ).first()

    if not code_entry:
        log_event(db, f"Попытка привязки с неверным/истекшим кодом: {p_code}", "WARN")
        raise HTTPException(404, "Код не найден или истек. Сгенерируйте новый в ЛК.")

    # 3. Проверяем, существует ли уже такое устройство
    device = db.query(Device).filter(Device.chip_id == chip_id).first()

    # Создаем новый токен для безопасности
    new_token = secrets.token_urlsafe(32)

    if device:
        # Если устройство уже было, просто обновляем владельца и токен
        device.user_id = code_entry.user_id
        device.token = new_token
        device.is_active = True
        device.pending_reset = False
    else:
        # Создаем новую запись
        device = Device(
            chip_id=chip_id,
            user_id=code_entry.user_id,
            token=new_token,
            name=f"Датчик {chip_id[-4:]}"  # Берем последние 4 символа ID для имени
        )
        db.add(device)

    # 4. Удаляем использованный код, чтобы его нельзя было юзать дважды
    db.delete(code_entry)

    try:
        db.commit()
        log_event(db, f"Устройство {chip_id} успешно привязано к пользователю ID:{device.user_id}", "INFO")
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Ошибка базы данных: {str(e)}")

    return {"ok": True, "token": new_token}


@app.post("/device/telemetry")
async def hw_telemetry(body: dict = Body(...), db: Session = Depends(get_db)):
    chip_id = str(body.get("chip_id", ""))
    token = str(body.get("token", ""))

    device = db.query(Device).filter(Device.chip_id == chip_id, Device.token == token).first()
    if not device:
        raise HTTPException(401, "Неверный token")

    if device.pending_reset:
        device.pending_reset = False
        device.user_id = None
        device.token = secrets.token_urlsafe(32)
        db.commit()
        return {"command": "reset"}

    # Читаем данные от Lolin
    is_leak = body.get("leak") == 1
    voltage = float(body.get("voltage", 0.0))
    battery = int(body.get("battery", 0))  # Проценты от Lolin

    # Логика протечки
    if is_leak and not device.leak_status:
        db.add(DeviceLog(device_id=device.id, event_type="leak", message=f"⚠️ ПРОТЕЧКА! Напряжение: {voltage}V"))
        device.valve_open = False
        device.valve_percent = 0
        device.valve_pending = True
    elif not is_leak and device.leak_status:
        db.add(DeviceLog(device_id=device.id, event_type="info", message="✅ Датчик высох"))

    device.leak_status = is_leak
    device.voltage = voltage
    device.battery = battery
    device.last_seen = datetime.utcnow()

    # ФОРМИРОВАНИЕ КОМАНДЫ
    response_cmd = "none"
    if device.valve_pending:
        # Если это просто открыть/закрыть
        if device.valve_percent == 100:
            response_cmd = "open"
        elif device.valve_percent == 0:
            response_cmd = "close"
        else:
            response_cmd = f"p{device.valve_percent}"  # Например "p50"

        device.valve_pending = False

    db.commit()
    return {
        "command": response_cmd,
        "valve_open": device.valve_open,
        "valve_percent": device.valve_percent
    }