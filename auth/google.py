from fastapi import APIRouter, Request, HTTPException, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from auth.jwt_handler import SECRET_KEY
import httpx
import os
import secrets
from urllib.parse import urlencode

from dotenv import load_dotenv
from jose import jwt, ExpiredSignatureError, JWTError

from auth.jwt_handler import create_access_token

load_dotenv()

router = APIRouter()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"


def validate_google_oauth_config() -> None:
    missing_vars = [
        name
        for name, value in (
            ("CLIENT_ID", CLIENT_ID),
            ("CLIENT_SECRET", CLIENT_SECRET),
        )
        if not value
    ]
    if missing_vars:
        raise HTTPException(
            status_code=500,
            detail=f"Missing environment variables: {', '.join(missing_vars)}",
        )


def get_redirect_uri(request: Request) -> str:
    # Prefer the current request host/port so the auth request and token exchange match.
    return str(request.url_for("callback"))


# =========================
# Step 1: Redirect to Google
# =========================
@router.get("/login")
def login(request: Request):
    validate_google_oauth_config()
    redirect_uri = get_redirect_uri(request)
    state = secrets.token_urlsafe(16)

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent"
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    response = RedirectResponse(auth_url)

    # Store state securely
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=False,  # ⚠️ True in production (HTTPS)
        samesite="lax"
    )

    return response


# =========================
# Step 2: Verify ID Token
# =========================
async def verify_google_token(id_token: str):
    validate_google_oauth_config()
    async with httpx.AsyncClient(timeout=5.0) as client:
        certs_response = await client.get(GOOGLE_CERTS_URL)

    if certs_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch Google certs")

    certs = certs_response.json()

    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")

    key = next((k for k in certs["keys"] if k["kid"] == kid), None)

    if not key:
        raise HTTPException(status_code=401, detail="Invalid token key")

    try:
        payload = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            options={"verify_at_hash": False}
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")

    issuer = payload.get("iss")
    if issuer not in {"accounts.google.com", "https://accounts.google.com"}:
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    # 🔒 Extra validation
    if not payload.get("email_verified"):
        raise HTTPException(status_code=401, detail="Email not verified")

    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid user")

    return payload


# =========================
# Step 3: Callback
# =========================
@router.get("/callback")
async def callback(request: Request):
    validate_google_oauth_config()
    redirect_uri = get_redirect_uri(request)
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    auth_error = request.query_params.get("error")
    stored_state = request.cookies.get("oauth_state")

    if auth_error:
        raise HTTPException(status_code=400, detail=f"Google authorization failed: {auth_error}")

    # 🔒 CSRF Protection
    if not state or state != stored_state:
        raise HTTPException(status_code=400, detail="Invalid state")

    if not code:
        raise HTTPException(status_code=400, detail="No authorization code")

    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        token_response = await client.post(
            GOOGLE_TOKEN_URL,
            data=data,
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        try:
            error_data = token_response.json()
        except ValueError:
            error_data = {"error": token_response.text}
        raise HTTPException(
            status_code=400,
            detail=f"Token exchange failed: {error_data}"
        )

    token_data = token_response.json()

    id_token = token_data.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="No ID token received")

    # ✅ Verify Google ID token
    user_data = await verify_google_token(id_token)

    # ✅ Create your app JWT
    app_jwt = create_access_token({
        "sub": user_data["sub"],
        "email": user_data["email"],
        "name": user_data.get("name")
    })

    response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="session_token",
        value=app_jwt,
        httponly=True,
        secure=False,  # Set to True in production when using HTTPS.
        samesite="lax",
    )
    return response



@router.get("/profile")
def profile(session_token: str = Cookie(None)):

    # 1. اگر cookie نبود
    if not session_token:
        raise HTTPException(status_code=401, detail="Not logged in")

    try:
        # 2. decode JWT
        payload = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # 3. گرفتن اطلاعات user
    return {
        "email": payload.get("email"),
        "name": payload.get("name")
    }



    
