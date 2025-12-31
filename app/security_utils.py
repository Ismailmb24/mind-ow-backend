"""Security utils for authentication"""
from typing import Annotated
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import secrets
import hashlib

from fastapi import HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select, Session
from pwdlib import PasswordHash
import jwt
from jwt.exceptions import InvalidTokenError
import resend

from .models.models import User, RefreshToken, EmailVerificationToken
from .dependencies import get_session
from .config import settings

SECRETE_KEY = settings.SECRETE_KEY
ALGORITHM = settings.ALGORITHM
RESEND_API_KEY = settings.RESEND_API_KEY
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS

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

def set_verification_token(background_tasks: BackgroundTasks, user: User, session: Session):
    """Set email verification token and send verification email"""
    # setup verification token data
    expires_hours = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    verification_token = create_email_verification_token()
    hash_verification_token = hash_token(verification_token)

    # store email verification token row
    if user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User does not have an ID"
        )

    verification_token_row = EmailVerificationToken(
        hash_token=hash_verification_token,
        expired_at=expires_hours,
        user_id=user.id
    )

    session.add(verification_token_row)
    session.commit()
    session.refresh(verification_token_row)


    # create email params
    params: resend.Emails.SendParams = {
        "from": "Welcome Team <onboarding@resend.dev>",
        "to": [user.email],
        "subject": "Welcome to MindOw! Please verify your email",
        "html": f"<h1>Welcome to MindOw, {user.full_name or user.email}!</h1>"
                f"<p>Please verify your email by clicking the link below:</p>"
                f"<a href='https://your-frontend-domain.com/verify-email?token={verification_token}'>Verify Email</a>" # token to be replaced
    }

    # send verification email
    background_tasks.add_task(send_verification_email, params)