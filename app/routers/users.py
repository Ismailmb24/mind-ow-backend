from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlmodel import Session
import resend

from ..models.models import User, UserCreate, UserPublic, EmailVerificationToken
from ..dependencies import get_session
from ..utils.security_utils import get_user, get_hash_password, get_active_current_user, set_verification_token
from ..config import settings

EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS

router = APIRouter(
    prefix="/users",
    tags=["users"]
)


@router.post("/", response_model=UserPublic, status_code=201)
def create_user(
    session: Annotated[Session, Depends(get_session)], 
    user_data: UserCreate, 
    background_tasks: BackgroundTasks
    ):
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

    # set email verification token and send email
    set_verification_token(background_tasks, db_user, session)


    return db_user


@router.get("/me", response_model=UserPublic)
def reader_users_me(current_user: Annotated[User, Depends(get_active_current_user)]):
    """Get current user"""
    return current_user
