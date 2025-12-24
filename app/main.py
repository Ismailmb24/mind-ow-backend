"""Main module for the To-Do application."""
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from .config import settings
from .database import create_db_and_tables
from .dependencies import get_session
from .models import Token, RefreshToken
from .routers import tasks, users
from .security_utils import authenticate_user, create_access_token, create_refresh_token

ACCESS_TOKEN_EXPIRE_DAYS = settings.ACCESS_TOKEN_EXPIRE_DAYS

app = FastAPI(
    title="To-Do",
    description="Smart to-do list app"
)


# startup events
@app.on_event("startup")
def on_startup():
    """Statup event function."""
    create_db_and_tables()

#middleware cors
origins = [
    "http://localhost:3000",
    "http://localhost"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# routers
app.include_router(tasks.router)
app.include_router(users.router)



@app.post("/signin")
def login_for_access_token(
    response: Response,
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

    user = authenticate_user(form_data.username, form_data.password)
    if not user or not user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect email or password"
        )

    access_token_expire = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.email}, expire_delta=access_token_expire
    )
    refresh_token = create_refresh_token()

    token_row = RefreshToken(
        user_id=user.id,
        token=refresh_token,
        expired_at=datetime.now(timezone.utc)
    )
    session.add(token_row)
    session.commit()

    response.set_cookie(key="refresh_token",
                        value=refresh_token, secure=True, samesite="strict")

    return Token(access_token=access_token, token_type="bearer")


@app.post("/refresh")
def refresh_access_token(request: Request, session: Annotated[Session, Depends(get_session)]):
    """
    Refresh access token.

    - **refresh_token**: refresh token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    statement = select(RefreshToken).where(RefreshToken.token == refresh_token)
    token_row = session.exec(statement).first()

    if not token_row:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not token_row.expired_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    payload = {"sub": token_row.user.email}
    acces_token_expire = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    new_acces_token = create_access_token(
        payload, expire_delta=acces_token_expire)

    return {"access_token": new_acces_token, "type": "bearer"}


@app.get("/signout")
def signout(request: Request, session: Annotated[Session, Depends(get_session)]):
    """
    Sign out user.

    - **refresh_token**: refresh token
    \f
    :param request: Description
    :type request: Request
    :param session: Description
    :type session: Annotated[Session, Depends(get_session)]
    """
    refresh_token = request.cookies.get("refresh_token")

    statement = select(RefreshToken).where(RefreshToken.token == refresh_token)
    token_row = session.exec(statement).first()

    if token_row:
        session.delete(token_row)
        session.commit()

    return {"detail": "Signed out"}
