"""
Repository pattern for database access.

This module provides abstraction layer for database operations,
improving testability and reducing coupling between business logic and data access.
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, TypeVar, Generic
from dataclasses import dataclass
from enum import Enum

T = TypeVar('T')


class QueryOrder(Enum):
    """Query ordering options."""
    ASC = "asc"
    DESC = "desc"


@dataclass
class QueryFilter:
    """Query filter specification."""
    field: str
    operator: str
    value: Any
    
    def __str__(self):
        return f"{self.field} {self.operator} {self.value}"


@dataclass
class QueryOptions:
    """Query options for pagination, filtering, and ordering."""
    limit: Optional[int] = None
    offset: Optional[int] = None
    filters: List[QueryFilter] = None
    order_by: Optional[str] = None
    order: QueryOrder = QueryOrder.ASC
    
    def __post_init__(self):
        if self.filters is None:
            self.filters = []


class Repository(ABC, Generic[T]):
    """Abstract repository base class."""
    
    @abstractmethod
    async def get_by_id(self, entity_id: str) -> Optional[T]:
        """Get entity by ID."""
        pass
    
    @abstractmethod
    async def get_all(self, options: QueryOptions = None) -> List[T]:
        """Get all entities with optional filtering and pagination."""
        pass
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create new entity."""
        pass
    
    @abstractmethod
    async def update(self, entity: T) -> T:
        """Update existing entity."""
        pass
    
    @abstractmethod
    async def delete(self, entity_id: str) -> bool:
        """Delete entity by ID."""
        pass
    
    @abstractmethod
    async def exists(self, entity_id: str) -> bool:
        """Check if entity exists."""
        pass


class AccountRepository(Repository):
    """Repository for account data operations."""
    
    def __init__(self):
        # This will be injected via service locator in a real implementation
        self._db_session = None
    
    async def get_by_id(self, account_id: str) -> Optional[dict]:
        """Get account by ID."""
        # This would query the actual database
        # For now, return a mock structure
        return {
            'id': account_id,
            'username': '',
            'password': '',
            'channel': '',
            'config': {},
            'daily_result': [],
            'single_result': {}
        }
    
    async def get_all(self, options: QueryOptions = None) -> List[dict]:
        """Get all accounts with filtering."""
        # Implementation would query database with filters
        return []
    
    async def create(self, account: dict) -> dict:
        """Create new account."""
        # Implementation would insert into database
        return account
    
    async def update(self, account: dict) -> dict:
        """Update existing account."""
        # Implementation would update database record
        return account
    
    async def delete(self, account_id: str) -> bool:
        """Delete account by ID."""
        # Implementation would delete from database
        return True
    
    async def exists(self, account_id: str) -> bool:
        """Check if account exists."""
        # Implementation would check database
        return False
    
    async def get_by_user(self, user_id: str) -> List[dict]:
        """Get all accounts for a user."""
        # Custom query for accounts by user
        return []
    
    async def get_by_channel(self, channel: str) -> List[dict]:
        """Get all accounts for a specific channel."""
        # Custom query for accounts by channel
        return []


class UserRepository(Repository):
    """Repository for user data operations."""
    
    def __init__(self):
        self._db_session = None
    
    async def get_by_id(self, user_id: str) -> Optional[dict]:
        """Get user by ID."""
        return {
            'id': user_id,
            'password': '',
            'default_account': '',
            'clan': False,
            'admin': False,
            'disabled': False
        }
    
    async def get_all(self, options: QueryOptions = None) -> List[dict]:
        """Get all users."""
        return []
    
    async def create(self, user: dict) -> dict:
        """Create new user."""
        return user
    
    async def update(self, user: dict) -> dict:
        """Update existing user."""
        return user
    
    async def delete(self, user_id: str) -> bool:
        """Delete user by ID."""
        return True
    
    async def exists(self, user_id: str) -> bool:
        """Check if user exists."""
        return False
    
    async def authenticate(self, user_id: str, password: str) -> bool:
        """Authenticate user credentials."""
        # Implementation would verify password hash
        return False


class ResultRepository(Repository):
    """Repository for task and module results."""
    
    def __init__(self):
        self._db_session = None
    
    async def get_by_id(self, result_id: str) -> Optional[dict]:
        """Get result by ID."""
        return None
    
    async def get_all(self, options: QueryOptions = None) -> List[dict]:
        """Get all results."""
        return []
    
    async def create(self, result: dict) -> dict:
        """Create new result."""
        return result
    
    async def update(self, result: dict) -> dict:
        """Update existing result."""
        return result
    
    async def delete(self, result_id: str) -> bool:
        """Delete result by ID."""
        return True
    
    async def exists(self, result_id: str) -> bool:
        """Check if result exists."""
        return False
    
    async def get_by_account(self, account_id: str, result_type: str = None) -> List[dict]:
        """Get results for an account."""
        return []
    
    async def get_recent(self, account_id: str, limit: int = 10) -> List[dict]:
        """Get recent results for an account."""
        return []


class RepositoryFactory:
    """Factory for creating repository instances."""
    
    _repositories = {}
    
    @classmethod
    def get_account_repository(cls) -> AccountRepository:
        """Get account repository instance."""
        if 'account' not in cls._repositories:
            cls._repositories['account'] = AccountRepository()
        return cls._repositories['account']
    
    @classmethod
    def get_user_repository(cls) -> UserRepository:
        """Get user repository instance."""
        if 'user' not in cls._repositories:
            cls._repositories['user'] = UserRepository()
        return cls._repositories['user']
    
    @classmethod
    def get_result_repository(cls) -> ResultRepository:
        """Get result repository instance."""
        if 'result' not in cls._repositories:
            cls._repositories['result'] = ResultRepository()
        return cls._repositories['result']
    
    @classmethod
    def clear(cls):
        """Clear all repository instances (for testing)."""
        cls._repositories.clear()


# Database session management
class UnitOfWork:
    """Unit of work pattern for transaction management."""
    
    def __init__(self):
        self._transaction = None
        self._repositories = {}
    
    async def __aenter__(self):
        """Start transaction."""
        # In real implementation, start database transaction
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """End transaction."""
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
    
    async def commit(self):
        """Commit transaction."""
        # In real implementation, commit database transaction
        pass
    
    async def rollback(self):
        """Rollback transaction."""
        # In real implementation, rollback database transaction
        pass
    
    def get_repository(self, repository_type: type) -> Repository:
        """Get repository instance within this unit of work."""
        repo_name = repository_type.__name__
        if repo_name not in self._repositories:
            self._repositories[repo_name] = repository_type()
        return self._repositories[repo_name]