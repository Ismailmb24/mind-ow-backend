"""Security utils for authentication"""
from typing import Annotated
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import secrets
import hashlib

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select, Session
from pwdlib import PasswordHash
import jwt
from jwt.exceptions import InvalidTokenError
import resend

from .models.models import User, RefreshToken
from .dependencies import get_session
from .config import settings

SECRETE_KEY = settings.SECRETE_KEY
ALGORITHM = settings.ALGORITHM
RESEND_API_KEY = settings.RESEND_API_KEY

resend.api_key = RESEND_API_KEY

password_hash = PasswordHash.recommended()


def get_hash_password(password: str):
    """Get hash password"""
    return password_hash.hash(password)


def verify_password(plain_password, hashed_password):
    """Verify password"""
    return password_hash.verify(plain_password, hashed_password)


def get_user(email: str):
    """Get user by email"""
    for session in get_session():
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        return user


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")


def get_curent_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Get current user"""
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRETE_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credential_exception
    except InvalidTokenError as e:
        raise credential_exception from e
    user = get_user(email)
    if not user:
        raise credential_exception
    return user


def get_active_current_user(current_user: Annotated[User, Depends(get_curent_user)]):
    """Get active current user"""
    if not current_user.status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid user"
        )
    return current_user


def authenticate_user(email: str, password: str):
    """Authenticate user"""
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_at: datetime | None = None):
    """Create access token"""
    to_copy = data.copy()
    if expires_at:
        expire = expires_at
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_copy.update({"exp": expire})
    encode_jwt = jwt.encode(to_copy, SECRETE_KEY, algorithm=ALGORITHM)
    return encode_jwt


def create_refresh_token():
    """Create refresh token string"""
    return secrets.token_urlsafe(64)

def hash_token(token: str):
    """Hash token string"""
    return hashlib.sha256(token.encode()).hexdigest()

def revoke_chained_fresh_tokens(token: RefreshToken | None, session: Session) -> None:
    """Revoke chained refresh tokens"""
    while token is not None:
        token.revoked_at = datetime.now(timezone.utc)

        if not token.replaced_by:
            break

        token = session.get(RefreshToken, token.replaced_by)

    session.commit()

def create_email_verification_token():
    """Create email verification token string"""
    return secrets.token_urlsafe(48)

def send_verification_email(params: resend.Emails.SendParams):
    """Send verification email using Resend API"""

    email = resend.Emails.send(params)