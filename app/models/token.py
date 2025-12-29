from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, DateTime
from datetime import datetime, timezone
from uuid import UUID, uuid4
from .user import User

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