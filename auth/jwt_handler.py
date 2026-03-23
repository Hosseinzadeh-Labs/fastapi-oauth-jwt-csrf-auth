from datetime import datetime, timedelta, timezone
import os

from dotenv import load_dotenv
from jose import jwt

load_dotenv()

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
SECRET_KEY = os.getenv("JWT_SECRET")


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    if not SECRET_KEY:
        raise RuntimeError("JWT_SECRET is not set in the environment")

    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
