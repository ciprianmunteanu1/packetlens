from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine


# Initialize SQLAlchemy engine, declarative Base class, and session factory
engine = create_engine("sqlite:///backend/app/database/packets.db", echo=True)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_session():
    """
    Yields a SQLAlchemy session for use in FastAPI endpoints
    Ensures the session is closed after the request lifecycle
    """
    
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
