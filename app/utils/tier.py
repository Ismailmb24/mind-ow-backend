from datetime import datetime
from datetime import timezone

from app.models.models import User

CAPABILITIES = {
    "free": {
        "max_projects": 3,
        "max_tasks_per_project": 50,
        "collaboration_limits": 3,
        "analytics": False
    },
    "pro": {
        "max_projects": 999,
        "max_tasks_per_project": 999,
        "collaboration_limits": 999,
        "analytics": True
    },
}

def resolve_user_tier(user: User) -> str:
    """Resolve the tier of a user based on their subscription status."""
    if user.tier == "pro" and user.tier_expires_at:
        if user.tier_expires_at > datetime.now(timezone.utc):
            return "pro"
        else:
            return "free"
    return "free"

def can(user: User, capability: str) -> bool:
    """Check if a user has a specific capability based on their tier."""
    tier = resolve_user_tier(user)
    tier_capabilities = CAPABILITIES.get(tier, {})
    return tier_capabilities.get(capability, False)
