"""
Base database models and utilities
SQLAlchemy base classes with common functionality
"""

from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, Boolean
from sqlalchemy.ext.declarative import declared_attr

from app.config.database import Base


class TimestampMixin:
    """Mixin for adding timestamp fields to models"""
    
    @declared_attr
    def created_at(cls):
        return Column(DateTime, default=datetime.utcnow, nullable=False)
    
    @declared_attr
    def updated_at(cls):
        return Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class SoftDeleteMixin:
    """Mixin for soft delete functionality"""
    
    @declared_attr
    def is_deleted(cls):
        return Column(Boolean, default=False, nullable=False)
    
    @declared_attr
    def deleted_at(cls):
        return Column(DateTime, nullable=True)
    
    def soft_delete(self):
        """Mark record as deleted"""
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()


class BaseModel(Base, TimestampMixin):
    """Base model class with common functionality"""
    
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, index=True)
    
    def to_dict(self):
        """Convert model instance to dictionary"""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }
    
    def __repr__(self):
        return f"<{self.__class__.__name__}(id={self.id})>"
