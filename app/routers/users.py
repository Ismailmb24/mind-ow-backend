from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from ..models.models import User, UserCreate, UserPublic
from ..dependencies import get_session
from ..security_utils import get_user, get_hash_password, get_active_current_user


router = APIRouter(
    prefix="/users",
    tags=["users"]
)


@router.post("/", response_model=UserPublic, status_code=201)
def create_user(session: Annotated[Session, Depends(get_session)], user_data: UserCreate):
    user = get_user(user_data.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exist"
        )

    hashed_password = get_hash_password(user_data.password)
    password_data = {"hashed_password": hashed_password}
    db_user = User.model_validate(user_data, update=password_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


@router.get("/me", response_model=UserPublic)
def reader_users_me(current_user: Annotated[User, Depends(get_active_current_user)]):
    """Get current user"""
    return current_user
