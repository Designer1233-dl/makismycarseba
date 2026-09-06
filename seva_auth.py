"""Сайт-Севы: Telegram auth bot + API.

Установка: pip install aiogram fastapi uvicorn python-dotenv
Запуск: set BOT_TOKEN=...; python seva_auth.py
"""
import asyncio, hashlib, hmac, os, secrets, sqlite3, time
from contextlib import asynccontextmanager, closing
from threading import Lock

from aiogram import Bot, Dispatcher, Router
from aiogram.filters import CommandStart
from aiogram.types import Message
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
CODE_SECRET = os.environ.get("CODE_SECRET", "").strip()
DB_PATH = os.environ.get("SEVA_DB", "seva.sqlite3")
CODE_TTL = 600
MAX_ATTEMPTS = 5
db_lock = Lock()

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE NOT NULL, username TEXT UNIQUE COLLATE NOCASE, name TEXT NOT NULL, created_at INTEGER NOT NULL)")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(accounts)")}
    if "username" not in columns:
        conn.execute("ALTER TABLE accounts ADD COLUMN username TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username COLLATE NOCASE)")
    conn.execute("CREATE TABLE IF NOT EXISTS login_codes (telegram_id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS login_states (state TEXT PRIMARY KEY, telegram_id INTEGER, username TEXT, name TEXT, expires_at INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0)")
    conn.commit(); return conn

def hash_code(tg_id: int, code: str) -> str:
    return hmac.new(CODE_SECRET.encode(), f"{tg_id}:{code}".encode(), hashlib.sha256).hexdigest()

bot_router = Router()
@bot_router.message(CommandStart())
async def start(message: Message):
    tg_id = message.from_user.id
    payload = (message.text or "").split(maxsplit=1)[1] if " " in (message.text or "") else ""
    if payload.startswith("web_"):
        state = payload[4:]
        with db_lock, closing(db()) as conn:
            exists = conn.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (tg_id,)).fetchone()
            conn.execute("UPDATE login_states SET telegram_id=?,username=?,name=?,verified=1 WHERE state=? AND expires_at>?", (tg_id, message.from_user.username or "", message.from_user.full_name or "Пользователь", state, int(time.time())))
            conn.commit()
        await message.answer("Готово! Вернись на сайт Сайт-Севы — вход завершится автоматически." if not exists else "Этот Telegram уже привязан к аккаунту Сайт-Севы.")
        return
    with db_lock, closing(db()) as conn:
        exists = conn.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (tg_id,)).fetchone()
        if exists:
            await message.answer("Этот Telegram уже привязан к аккаунту Сайт-Севы. Создать второй аккаунт нельзя.")
            return
        code = f"{secrets.randbelow(1_000_000):06d}"
        conn.execute("INSERT INTO login_codes VALUES(?,?,?,?,0) ON CONFLICT(telegram_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0, used=0", (tg_id, hash_code(tg_id, code), int(time.time()) + CODE_TTL, 0))
        conn.commit()
    await message.answer(f"Код для входа в Сайт-Севы: {code}\nТвой Telegram ID: {tg_id}\nВведи оба значения на сайте. Код действует 10 минут и одноразовый. Никому его не пересылай.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not BOT_TOKEN or ":" not in BOT_TOKEN:
        raise RuntimeError("Заполни BOT_TOKEN в файле .env")
    if len(CODE_SECRET) < 32 or CODE_SECRET.startswith("ЗАМЕНИ_"):
        raise RuntimeError("CODE_SECRET в .env должен содержать минимум 32 символа")
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher(); dp.include_router(bot_router)
    task = asyncio.create_task(dp.start_polling(bot))
    try:
        yield
    finally:
        await dp.stop_polling()
        task.cancel()
        await bot.session.close()

app = FastAPI(title="Сайт-Севы Auth API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","), allow_methods=["POST","GET"], allow_headers=["*"])
class VerifyRequest(BaseModel):
    telegram_id: int = Field(gt=0)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    name: str = Field(min_length=2, max_length=24)
    username: str = Field(default="", max_length=32)

@app.post("/api/auth/verify")
def verify(payload: VerifyRequest):
    now = int(time.time())
    with db_lock, closing(db()) as conn:
        if conn.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (payload.telegram_id,)).fetchone():
            raise HTTPException(409, "Этот Telegram уже зарегистрирован")
        row = conn.execute("SELECT * FROM login_codes WHERE telegram_id=?", (payload.telegram_id,)).fetchone()
        if not row or row["used"] or row["expires_at"] < now:
            raise HTTPException(401, "Код истёк. Запроси новый через /start")
        if row["attempts"] >= MAX_ATTEMPTS:
            raise HTTPException(429, "Слишком много попыток. Запроси новый код через /start")
        if not hmac.compare_digest(row["code_hash"], hash_code(payload.telegram_id, payload.code)):
            conn.execute("UPDATE login_codes SET attempts=attempts+1 WHERE telegram_id=?", (payload.telegram_id,)); conn.commit()
            raise HTTPException(401, "Неверный код")
        username = payload.username.strip().lstrip("@").lower() or f"user_{payload.telegram_id}"
        if not __import__('re').fullmatch(r"[a-z][a-z0-9_]{4,31}", username):
            raise HTTPException(400, "Username: латинские буквы, цифры и _ (от 5 символов)")
        try:
            conn.execute("INSERT INTO accounts(telegram_id,username,name,created_at) VALUES(?,?,?,?)", (payload.telegram_id, username, payload.name.strip(), now))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Этот @username уже занят")
        conn.execute("UPDATE login_codes SET used=1 WHERE telegram_id=?", (payload.telegram_id,)); conn.commit()
        account_id = conn.execute("SELECT id FROM accounts WHERE telegram_id=?", (payload.telegram_id,)).fetchone()[0]
    return {"ok": True, "account_id": account_id, "name": payload.name.strip()}

@app.post("/api/auth/start")
def start_login():
    state = secrets.token_urlsafe(24)
    with db_lock, closing(db()) as conn:
        conn.execute("INSERT INTO login_states(state,expires_at) VALUES(?,?)", (state, int(time.time()) + 300)); conn.commit()
    return {"state": state, "bot_url": f"https://t.me/seva_Sot_Set_bot?start=web_{state}"}

@app.get("/api/auth/poll/{state}")
def poll_login(state: str):
    with db_lock, closing(db()) as conn:
        row = conn.execute("SELECT * FROM login_states WHERE state=?", (state,)).fetchone()
        if not row or row["expires_at"] < int(time.time()): raise HTTPException(401, "Ссылка истекла")
        if not row["verified"]: return {"verified": False}
        existing = conn.execute("SELECT id,name,username FROM accounts WHERE telegram_id=?", (row["telegram_id"],)).fetchone()
        if existing: return {"verified": True, "account_id": existing["id"], "name": existing["name"], "username": existing["username"]}
        username = (row["username"] or f"user_{row['telegram_id']}").lower()
        if not __import__('re').fullmatch(r"[a-z][a-z0-9_]{4,31}", username): username = f"user_{row['telegram_id']}"
        try: conn.execute("INSERT INTO accounts(telegram_id,username,name,created_at) VALUES(?,?,?,?)", (row["telegram_id"], username, row["name"] or "Пользователь", int(time.time()))); conn.commit()
        except sqlite3.IntegrityError: username = f"user_{row['telegram_id']}"; conn.execute("INSERT OR IGNORE INTO accounts(telegram_id,username,name,created_at) VALUES(?,?,?,?)", (row["telegram_id"], username, row["name"] or "Пользователь", int(time.time()))); conn.commit()
        account = conn.execute("SELECT id,name,username FROM accounts WHERE telegram_id=?", (row["telegram_id"],)).fetchone()
    return {"verified": True, "account_id": account["id"], "name": account["name"], "username": account["username"]}

@app.get("/api/users/{username}")
def find_user(username: str):
    username = username.lstrip("@").lower()
    if len(username) < 5:
        raise HTTPException(400, "Введи полный @username")
    with db_lock, closing(db()) as conn:
        row = conn.execute("SELECT id, username, name FROM accounts WHERE username=?", (username,)).fetchone()
    if not row: raise HTTPException(404, "Пользователь не найден")
    return {"id": row["id"], "username": "@" + row["username"], "name": row["name"]}

@app.get("/api/health")
def health(): return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
