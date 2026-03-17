import os
import jwt
from fastapi import Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if not SECRET_KEY:
    # Fallback for dev/demo — warn loudly but don't crash
    import warnings
    warnings.warn(
        "JWT_SECRET_KEY environment variable is not set! Using insecure default. "
        "Set JWT_SECRET_KEY in your .env file before any real deployment.",
        stacklevel=2,
    )
    SECRET_KEY = "insecure-dev-only-secret-change-me"

ALGORITHM = "HS256"


def create_token(payload: dict) -> str:
    """Generate a JWT token. Used by the /token endpoint so that
    SECRET_KEY never needs to be exported from this module."""
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_jwt(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
