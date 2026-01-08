from typing import Annotated
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Session, select

from app.dependencies import get_session
from app.models.models import EmailVerificationToken, PasswordResetToken, Token, RefreshToken, User, UserCreate, UserUpdate
from app.utils.security_utils import get_hash_password, hash_token, authenticate_user, create_access_token, create_refresh_token, revoke_chained_fresh_tokens, set_reset_password_token, set_verification_token, verify_google_token
from app.config import settings

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


# Refresh access token endpoint
@router.post("/refresh-token", response_model=Token)
def refresh_access_token(
    refresh_token: Annotated[str, Body(embed=True)], 
    session: Annotated[Session, Depends(get_session)]
    ):
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


# Resend verification email endpoint
@router.post("/resend-verification-email")
def resend_verification_email(
    email: Annotated[str, Body(embed=True)],
    session: Annotated[Session, Depends(get_session)], 
    background_tasks: BackgroundTasks
):
    """
    Resend verification email.
    """ 

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.email_verified_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already verified")

    set_verification_token(background_tasks, user, session)

    return {"detail": "Verification email resent"}


# Email verification request endpoint
@router.post("/verify-email")
def verify_email(
    token: Annotated[str, Body(embed=True)],
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


# Google sign-in endpoint
@router.post("/google-signin", response_model=Token)
def google_signin(
    token: Annotated[str, Body(embed=True)],
    session: Annotated[Session, Depends(get_session)]
):
    """
    Sign in with Google OAuth2 token.

    - **token**: Google OAuth2 token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """

    # check if token is provided
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No token provided"
        )
    
    # verify google token and get email
    google_data = verify_google_token(token)
    email = google_data.get("email")
    full_name = google_data.get("name")

    # check if user exists
    user = session.exec(select(User).where(User.email == email)).first()

    # if user does not exist, create new user
    if not user:
        new_user = User(
            email=email,
            full_name=full_name,
            email_verified_at=datetime.now(timezone.utc),
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        # set user to newly created user
        user = new_user

    # check if user has an ID
    if not user.id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User does not have an ID"
        )
    
    # create access token
    access_token_expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_at=access_token_expire
    )

    # create refresh token
    refresh_token = create_refresh_token()
    hash_refresh_token = hash_token(refresh_token)

    # store refresh token in database
    refresh_token_row = RefreshToken(
        user_id=user.id,
        hash_token=hash_refresh_token,
        expired_at=datetime.now(timezone.utc) + timedelta(days=30)
    )
    session.add(refresh_token_row)
    session.commit()

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_at=access_token_expire,
        refresh_token=refresh_token
    )


# Sign out endpoint
@router.get("/signout")
def signout(
    refresh_token: Annotated[str, Body(embed=True)], 
    session: Annotated[Session, Depends(get_session)]
):
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
    hash_refresh_token = hash_token(refresh_token)

    statement = select(RefreshToken).where(RefreshToken.hash_token == hash_refresh_token)
    token_row = session.exec(statement).first()

    if token_row:
        token_row.revoked_at = datetime.now(timezone.utc)
        session.commit()

    return {"detail": "Signed out"}


# Forgot password request
@router.post("/forgot-password", response_model=dict)
def forgot_password(
    email: Annotated[str, Body(embed=True)],
    background_tasks: BackgroundTasks,
    session: Annotated[Session, Depends(get_session)]
):
    """
    Request a password reset.

    - **email**: User's email address
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """

    # check if email is provided
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )

    # check if user exists
    user = session.exec(select(User).where(User.email == email)).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # set reset password token and send reset password email
    set_reset_password_token(background_tasks, user, session)

    return {"detail": "Password reset email sent"}


# Reset password endpoint
@router.post("/reset-password")
def reset_password(
    user_update: Annotated[UserUpdate, Body()], 
    token: Annotated[str, Body()],
    session: Annotated[Session, Depends(get_session)]):
    """
    Reset user password using reset token.

    - **token**: Password reset token
    - **new_password**: New password
    \f
    :param request: 
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """
    
    # Check if token is provided
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token provided"
        )
    
    # Hash the token
    hash_reset_token = hash_token(token)

    statement = select(PasswordResetToken).where(PasswordResetToken.hash_token == hash_reset_token)
    token_row = session.exec(statement).first()

    # If token not found, reject
    if not token_row:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    # Access expired and normalize to UTC if naive
    expired_at = token_row.expired_at
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=timezone.utc)
    # If token expired, reject
    if expired_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expired")
    
    # Update user's password
    user = token_row.user
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user_update.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password is required"
        )
    
    user_data = user_update.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        hashed_password = get_hash_password(user_data["password"])
        extra_data["hashed_password"] = hashed_password

    updatedated_user = user.sqlmodel_update(user_data, update=extra_data)
    session.add(updatedated_user)
    # Mark the token as used
    token_row.used_at = datetime.now(timezone.utc)
    session.commit()

    return {"detail": "Password reset successful"}