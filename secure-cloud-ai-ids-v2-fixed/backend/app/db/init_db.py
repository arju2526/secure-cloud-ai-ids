from app.db.database import Base, engine, SessionLocal
from app.models.entities import User
from app.security.jwt import get_password_hash
from app.schemas.auth import UserRole


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        defaults = [
            ("admin", "admin@soc.cloud.internal", "admin123", UserRole.ADMIN),
            ("analyst", "analyst@soc.cloud.internal", "analyst123", UserRole.ANALYST),
        ]
        for username, email, password, role in defaults:
            if not db.query(User).filter(User.username == username).first():
                db.add(User(username=username, email=email, hashed_password=get_password_hash(password), role=role))
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
