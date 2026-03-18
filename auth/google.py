from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from fastapi import Request
import httpx
import jwt
import os
from dotenv import load_dotenv
load_dotenv()

router = APIRouter()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
Redirect_url ="http://localhost:8001/auth/google/callback"

@router.get("/login")
def login():
    google_auth_url1 =(
        "https://accounts.google.com/o/oauth2/v2/auth"## define a url to send user to google 
        "?response_type=code"# it means i need authorization code 
        f"&client_id={Client_ID}"
        f"&redirect_uri={Redirect_url}"
        "&scope=openid email profile" # we're saying I need OpenID Connect > send me email and profile 
    )
    return RedirectResponse(google_auth_url1)




@router.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("code")# this syntax gets Authorization code from url 

## this step FastAPI exchange code >>token 
    token_url = "https://oauth2.googleapis.com/token" 

    data = {
        "code": code,
        "client_id": Client_ID,
        "client_secret": "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",
        "redirect_uri": Redirect_url,
        "grant_type": "authorization_code" # means I want to exchange code for token
    }

### here FastAPI directly speaks with google
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)

    token_data = response.json()
    id_token = token_data.get("id_token")
    decode = jwt.decode(id_token, options={"verify_signature": False})

    return decode