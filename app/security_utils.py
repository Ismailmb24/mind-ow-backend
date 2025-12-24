"""Security utils for authentication"""
from typing import Annotated
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select
from pwdlib import PasswordHash
import jwt
from jwt.exceptions import InvalidTokenError

from .models import User
from .dependencies import get_session
from .config import settings

SECRETE_KEY = settings.SECRETE_KEY
ALGORITHM = settings.ALGORITHM

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


def create_access_token(data: dict, expire_delta: timedelta | None = None):
    """Create access token"""
    to_copy = data.copy()
    if expire_delta:
        expire = datetime.now(timezone.utc) + expire_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=30)
    to_copy.update({"exp": expire})
    encode_jwt = jwt.encode(to_copy, SECRETE_KEY, algorithm=ALGORITHM)
    return encode_jwt


def create_refresh_token():
    """Create refresh token string"""
    return str(uuid4())
