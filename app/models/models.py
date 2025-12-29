from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime, timezone
from uuid import UUID, uuid4
from enum import Enum
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, DateTime
from datetime import datetime, timezone
from uuid import UUID, uuid4

# User model

# now function to get current UTC time
def now():
    return datetime.now(timezone.utc)

# User status enumeration
class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"
    DELETED = "deleted"

# User authentication enumeration
class UserRoleEnum(str, Enum):
    USER = "user"
    ADMIN = "admin"
    OWNER = "owner"

class UserBase(SQLModel):
    # identification fields
    email: str = Field(unique=True, index=True)
    email_verified_at: datetime | None = None

    # profile fields
    username: str | None = None
    full_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    
    # status fields
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)

    # Authorization fields
    role: UserRoleEnum = Field(default=UserRoleEnum.USER)  # e.g., user, admin

    #meta data
    created_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string
    updated_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string


class User(UserBase, table=True):
    id: UUID | None = Field(default_factory=uuid4, primary_key=True)
    hashed_password: str

    refresh_tokes: list["RefreshToken"] = Relationship(back_populates="user")

class UserCreate(UserBase):
    password: str

class UserPublic(UserBase):
    id: UUID


#token models
class Token(SQLModel):
    access_token: str
    token_type: str
    expires_at: datetime # should be a timezone-aware datetime (e.g., UTC)
    refresh_token: str | None = None

class TokenData(SQLModel):
    user_id: str | None = None

class RefreshToken(SQLModel, table=True):
    id: UUID | None = Field(default_factory=uuid4, primary_key=True)
    hash_token: str
    expired_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    revoked_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    replaced_by: UUID | None = Field(default=None)

    user_id: UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="refresh_tokes")