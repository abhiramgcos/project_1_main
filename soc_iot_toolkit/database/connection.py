"""
Database Connection Module.

Handles PostgreSQL database connections and session management.
"""

from typing import Optional, Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError
from loguru import logger

from ..config import get_settings
from .models import Base


class DatabaseConnection:
    """
    Manages database connections and sessions.
    
    Provides connection pooling, session management,
    and database initialization utilities.
    """
    
    def __init__(
        self,
        connection_string: Optional[str] = None,
        pool_size: int = 5,
        max_overflow: int = 10,
        echo: bool = False,
    ):
        """
        Initialize the database connection.
        
        Args:
            connection_string: PostgreSQL connection string.
                             If None, uses settings from configuration.
            pool_size: Number of connections in the pool.
            max_overflow: Maximum overflow connections.
            echo: Whether to echo SQL statements (debug).
        """
        if connection_string is None:
            settings = get_settings()
            connection_string = settings.database.connection_string
            pool_size = settings.database.pool_size
            max_overflow = settings.database.max_overflow
        
        self._connection_string = connection_string
        self._engine = None
        self._session_factory = None
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._echo = echo
        
        self._initialize_engine()
    
    def _initialize_engine(self) -> None:
        """Initialize the SQLAlchemy engine."""
        try:
            self._engine = create_engine(
                self._connection_string,
                poolclass=QueuePool,
                pool_size=self._pool_size,
                max_overflow=self._max_overflow,
                pool_pre_ping=True,  # Enable connection health checks
                echo=self._echo,
            )
            
            self._session_factory = sessionmaker(
                bind=self._engine,
                autocommit=False,
                autoflush=False,
            )
            
            logger.info("Database engine initialized successfully")
        
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    @property
    def engine(self):
        """Get the SQLAlchemy engine."""
        return self._engine
    
    def create_tables(self) -> None:
        """Create all database tables."""
        try:
            Base.metadata.create_all(self._engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def drop_tables(self) -> None:
        """Drop all database tables."""
        try:
            Base.metadata.drop_all(self._engine)
            logger.info("Database tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """
        Get a new database session.
        
        Returns:
            SQLAlchemy Session object.
        """
        if self._session_factory is None:
            raise RuntimeError("Database not initialized")
        return self._session_factory()
    
    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope around a series of operations.
        
        Usage:
            with db.session_scope() as session:
                session.add(obj)
        
        Yields:
            SQLAlchemy Session object.
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database transaction error: {e}")
            raise
        finally:
            session.close()
    
    def test_connection(self) -> bool:
        """
        Test the database connection.
        
        Returns:
            True if connection successful, False otherwise.
        """
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection test successful")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def get_pool_status(self) -> dict:
        """Get connection pool status."""
        pool = self._engine.pool
        return {
            "pool_size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "invalid": pool.invalidatedcount() if hasattr(pool, 'invalidatedcount') else 0,
        }
    
    def close(self) -> None:
        """Close all connections and dispose of the engine."""
        if self._engine:
            self._engine.dispose()
            logger.info("Database connections closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


# Singleton instance
_db_connection: Optional[DatabaseConnection] = None


def get_db_connection() -> DatabaseConnection:
    """
    Get the singleton database connection instance.
    
    Returns:
        DatabaseConnection instance.
    """
    global _db_connection
    if _db_connection is None:
        _db_connection = DatabaseConnection()
    return _db_connection


def init_database(connection_string: Optional[str] = None) -> DatabaseConnection:
    """
    Initialize the database connection and create tables.
    
    Args:
        connection_string: Optional custom connection string.
    
    Returns:
        DatabaseConnection instance.
    """
    global _db_connection
    _db_connection = DatabaseConnection(connection_string)
    _db_connection.create_tables()
    return _db_connection


def close_database() -> None:
    """Close the database connection."""
    global _db_connection
    if _db_connection:
        _db_connection.close()
        _db_connection = None
