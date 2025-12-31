from typing import Annotated
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Session, select

from ..dependencies import get_session
from ..models.models import EmailVerificationToken, Token, RefreshToken, User
from ..security_utils import hash_token, authenticate_user, create_access_token, create_refresh_token, revoke_chained_fresh_tokens, set_verification_token
from ..config import settings

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


# Sign in endpoint
@router.post("/signin", response_model=Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)]
):
    """
    Login with user credencials formdata.

    - **username**: user email
    - **password**: user password
    \f
    :param form_data: Description
    :type form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
    """

    # try:
    #     email = EmailStr(form_data.username)
    # except Exception:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="Invalid email format"
    #     )

    # authenticate user
    user = authenticate_user(form_data.username, form_data.password)
    if not user or not user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect email or password"
        )

    # create access token
    access_token_expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_at=access_token_expire
    )

    # create refresh token
    refresh_token = create_refresh_token()
    # hash the refresh token before storing
    hash_refresh_token = hash_token(refresh_token)

    # store refresh token in  database
    refresh_token_row = RefreshToken(
        user_id=user.id,
        hash_token=hash_refresh_token,
        expired_at=datetime.now(timezone.utc) + timedelta(days=30)
    )
    session.add(refresh_token_row)
    session.commit()

    # return tokens
    return Token(
        access_token=access_token, 
        token_type="bearer", 
        expires_at=access_token_expire,
        refresh_token=refresh_token
    )

class RefreshTokenRequest(SQLModel):
    refresh_token: str


# Refresh access token endpoint
@router.post("/refresh-token", response_model=Token)
def refresh_access_token(data: RefreshTokenRequest, session: Annotated[Session, Depends(get_session)]):
    """
    Refresh access token.

    - **refresh_token**: refresh token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """

    # check if refresh token is provided
    refresh_token = data.refresh_token
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")
    
    # check if refresh token is valid
    hash_refresh_token = hash_token(refresh_token)
    statement = select(RefreshToken).where(RefreshToken.hash_token == hash_refresh_token)
    token_row = session.exec(statement).first()

    # if token not found, reject
    if not token_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # access expired and normalize to UTC if naive
    expired_at = token_row.expired_at
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=timezone.utc)

    # if token expired, revoke chained fresh tokens and reject
    if expired_at < datetime.now(timezone.utc):
        revoke_chained_fresh_tokens(token_row, session)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    
    # revoke chained fresh tokens
    new_fresh_token = create_refresh_token()
    hash_new_fresh_token = hash_token(new_fresh_token)
    new_token_row = RefreshToken(
        user_id=token_row.user_id,
        hash_token=hash_new_fresh_token,
        expired_at=datetime.now(timezone.utc) + timedelta(days=30)
    )
    session.add(new_token_row)
    session.commit()

    # mark old token as revoked
    token_row.revoked_at = datetime.now(timezone.utc)
    token_row.replaced_by = new_token_row.id
    session.commit()
    
    

    # create new access token
    payload = {"sub": token_row.user.email}
    acces_token_expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_acces_token = create_access_token(
        payload, 
        expires_at=acces_token_expire
    )
    
    return Token(
        access_token=new_acces_token, 
        token_type="bearer", 
        expires_at=acces_token_expire,
        refresh_token=new_fresh_token
    )


# Sign out endpoint
@router.get("/signout")
def signout(data: RefreshTokenRequest, session: Annotated[Session, Depends(get_session)]):
    """
    Sign out user.

    - **refresh_token**: refresh token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """

    # hash the refresh token
    refresh_token = data.refresh_token
    hash_refresh_token = hash_token(refresh_token)

    statement = select(RefreshToken).where(RefreshToken.hash_token == hash_refresh_token)
    token_row = session.exec(statement).first()

    if token_row:
        token_row.revoked_at = datetime.now(timezone.utc)
        session.commit()

    return {"detail": "Signed out"}


# Resend verification email request
class ResendVerificationEmailRequest(SQLModel):
    email: str

@router.post("/resend-verification-email")
def resend_verification_email(
    data: ResendVerificationEmailRequest, 
    session: Annotated[Session, Depends(get_session)], 
    background_tasks: BackgroundTasks
):
    """
    Resend verification email.
    """ 

    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    set_verification_token(background_tasks, user, session)

    return {"detail": "Verification email resent"}


# Email verification request
class EmailVerificationRequest(SQLModel):
    token: str 

# Verify email endpoint
@router.post("/verify-email")
def verify_email(
    data: EmailVerificationRequest, 
    session: Annotated[Session, Depends(get_session)]
):
    """
    Verify email using token.

    - **token**: verification token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """

    # hash the token
    token = data.token
    hash_email_token = hash_token(token)

    statement = select(EmailVerificationToken).where(EmailVerificationToken.hash_token == hash_email_token)
    token_row = session.exec(statement).first()

    if not token_row:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    # access expired and normalize to UTC if naive
    expired_at = token_row.expired_at
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=timezone.utc)

    # if token expired, reject
    if expired_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expired")

    # mark user's email as verified
    user = token_row.user
    user.email_verified_at = datetime.now(timezone.utc)
    session.delete(token_row)
    session.commit()

    return {"detail": "Email verified"}
