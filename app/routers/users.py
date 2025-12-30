from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlmodel import Session
import resend

from ..models.models import User, UserCreate, UserPublic, EmailVerificationToken
from ..dependencies import get_session
from ..security_utils import get_user, get_hash_password, get_active_current_user, hash_token, create_email_verification_token,send_verification_email
from ..config import settings

EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS

router = APIRouter(
    prefix="/users",
    tags=["users"]
)


@router.post("/", response_model=UserPublic, status_code=201)
def create_user(session: Annotated[Session, Depends(get_session)], user_data: UserCreate, background_tasks: BackgroundTasks):
    """Create new user"""

    # check if user already exist
    user = get_user(user_data.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exist"
        )

    # hash password and create user
    hashed_password = get_hash_password(user_data.password)
    password_data = {"hashed_password": hashed_password}
    db_user = User.model_validate(user_data, update=password_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    # check user created
    if not db_user.id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User creation failed"
        )
    

    # setup verification token data
    expires_hours = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    verification_token = create_email_verification_token()
    hash_verification_token = hash_token(verification_token)

    # store email verification token row
    verification_token_row = EmailVerificationToken(
        hash_token=hash_verification_token,
        expired_at=expires_hours,
        user_id=db_user.id
    )

    session.add(verification_token_row)
    session.commit()
    session.refresh(verification_token_row)


    # create email params
    params: resend.Emails.SendParams = {
        "from": "Welcome Team <onboarding@resend.dev>",
        "to": [user_data.email],
        "subject": "Welcome to MindOw! Please verify your email",
        "html": f"<h1>Welcome to MindOw, {user_data.full_name or user_data.email}!</h1>"
                f"<p>Please verify your email by clicking the link below:</p>"
                f"<a href='https://your-frontend-domain.com/verify-email?token={verification_token}'>Verify Email</a>" # token to be replaced
    }

    # send verification email
    background_tasks.add_task(send_verification_email, params)


    return db_user


@router.get("/me", response_model=UserPublic)
def reader_users_me(current_user: Annotated[User, Depends(get_active_current_user)]):
    """Get current user"""
    return current_user
