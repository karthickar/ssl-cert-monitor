import logging

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from src.auth import get_optional_user, require_user, upsert_user
from src.config import get_settings
from src.database import get_db
from src.models import User
from src.schemas import DevLoginRequest, UserResponse

router = APIRouter()
logger = logging.getLogger(__name__)
settings = get_settings()
oauth = OAuth()
if settings.google_client_id and settings.google_client_secret:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def google_oauth_configured() -> bool:
    return bool(settings.google_client_id and settings.google_client_secret)


@router.get("/auth/google")
async def login_with_google(request: Request):
    if not google_oauth_configured():
        return RedirectResponse(url="/ssl#account", status_code=302)
    redirect_uri = settings.oauth_redirect_url or str(request.url_for("auth_google_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/auth/google/callback", name="auth_google_callback")
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    if not google_oauth_configured():
        raise HTTPException(status_code=503, detail="Google sign-in is not configured")
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as error:
        logger.info("Google OAuth callback failed: %s", error)
        raise HTTPException(status_code=401, detail="Google sign-in failed") from error
    userinfo = token.get("userinfo") or {}
    email = (userinfo.get("email") or "").strip().lower()
    if not email or not userinfo.get("email_verified", True):
        raise HTTPException(status_code=401, detail="A verified Google email is required")
    user = upsert_user(
        db,
        google_id=str(userinfo.get("sub") or email),
        email=email,
        name=userinfo.get("name") or email.split("@")[0],
        picture=userinfo.get("picture"),
    )
    request.session["user_id"] = user.id
    return RedirectResponse(url="/ssl", status_code=302)


@router.post("/auth/dev-login", response_model=UserResponse)
def dev_login(payload: DevLoginRequest, request: Request, db: Session = Depends(get_db)):
    if not settings.auth_allow_dev_login:
        raise HTTPException(status_code=404, detail="Development login is disabled")
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=422, detail="A valid email address is required")
    user = upsert_user(db, google_id=f"dev:{email}", email=email, name=payload.name)
    request.session["user_id"] = user.id
    return user


@router.get("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/ssl", status_code=302)


@router.get("/auth/me", response_model=UserResponse)
def current_user(user: User = Depends(require_user)):
    return user


@router.get("/auth/session")
def session_status(user: User | None = Depends(get_optional_user)):
    if not user:
        return {"authenticated": False, "user": None}
    return {"authenticated": True, "user": UserResponse.model_validate(user).model_dump()}
