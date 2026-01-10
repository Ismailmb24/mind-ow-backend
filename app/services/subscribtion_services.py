from datetime import datetime, timedelta, timezone
from sqlmodel import Session
from app.models.models import Subscription, User, UserPublic


def grant_pro(user: User, days: int, session: Session):
    user.tier = "pro"
    user.tier_expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    session.add(user)
    session.commit()


def activate_subscription(
    user: UserPublic,
    provider_id: str,
    expires_at: datetime,
    session: Session
):
    subscription = Subscription(
        user_id=user.id,
        provider="stripe",
        provider_subscription_id=provider_id,
        tier="pro",
        started_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )

    user.tier = "pro"
    user.tier_expires_at = expires_at

    session.add(subscription)
    session.add(user)
    session.commit()