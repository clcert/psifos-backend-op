from app.database import SessionLocal


def get_db():
    """
    Database dependency: allows a single Session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
