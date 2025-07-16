# coding: utf-8
"""
Database base classes and common utilities
Extracted from large models.py file to improve maintainability
"""

from typing import Optional, Generic, TypeVar
from sqlalchemy import Float, Index, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Session, DeclarativeBase, Mapped, mapped_column
from ...util.linq import flow

T = TypeVar('T')

class Base(DeclarativeBase, Generic[T]):
    """Base class for all database models with query utilities"""
    
    @classmethod
    def query(cls, session: Session) -> flow[T]:
        return flow(session.query(cls).all())

__all__ = ['Base']