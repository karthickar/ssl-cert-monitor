from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from src.database import get_db
from src.models import Monitor, User


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def require_user(user: User | None = Depends(get_optional_user)) -> User:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in with Google to manage monitors")
    return user


def require_monitor_owner(monitor: Monitor, user: User) -> None:
    if monitor.owner_id is not None and monitor.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only change monitors you created")


def upsert_user(db: Session, google_id: str, email: str, name: str, picture: str | None = None) -> User:
    user = db.query(User).filter((User.google_id == google_id) | (User.email == email.lower())).first()
    if user:
        user.google_id = google_id
        user.email = email.lower()
        user.name = name
        user.picture = picture
    else:
        user = User(google_id=google_id, email=email.lower(), name=name, picture=picture)
        db.add(user)
    db.commit()
    db.refresh(user)
    return user
