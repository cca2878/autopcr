"""
Refactored account management system using new architecture patterns.

This module demonstrates how the account management system would be
improved using dependency injection, repository pattern, and service locator.
"""
import hashlib
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from ..core.service_locator import ServiceLocator, LoggingService
from ..db.repository import RepositoryFactory, UnitOfWork
from ..config import config


class AccountException(Exception):
    """Account-related exceptions."""
    pass


class AccountService(ABC):
    """Abstract account service interface."""
    
    @abstractmethod
    async def get_account(self, user_id: str, account_name: str) -> Optional[dict]:
        """Get account data."""
        pass
    
    @abstractmethod
    async def create_account(self, user_id: str, account_name: str, account_data: dict) -> dict:
        """Create new account."""
        pass
    
    @abstractmethod
    async def update_account(self, user_id: str, account_name: str, account_data: dict) -> dict:
        """Update account data."""
        pass
    
    @abstractmethod
    async def delete_account(self, user_id: str, account_name: str) -> bool:
        """Delete account."""
        pass
    
    @abstractmethod
    async def list_accounts(self, user_id: str) -> List[dict]:
        """List all accounts for a user."""
        pass


class DefaultAccountService(AccountService):
    """Default implementation of account service."""
    
    def __init__(self):
        self.logger = ServiceLocator.get(LoggingService)
        self.repository_factory = RepositoryFactory()
        self._locks: Dict[str, asyncio.Lock] = {}
    
    def _get_lock(self, key: str) -> asyncio.Lock:
        """Get or create a lock for the given key."""
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]
    
    async def get_account(self, user_id: str, account_name: str) -> Optional[dict]:
        """Get account data with proper locking."""
        lock_key = f"{user_id}_{account_name}"
        
        async with self._get_lock(lock_key):
            try:
                async with UnitOfWork() as uow:
                    account_repo = uow.get_repository(type(self.repository_factory.get_account_repository()))
                    account_id = self._generate_account_id(user_id, account_name)
                    return await account_repo.get_by_id(account_id)
                    
            except Exception as e:
                self.logger.error(f"Failed to get account {account_name} for user {user_id}: {e}")
                return None
    
    async def create_account(self, user_id: str, account_name: str, account_data: dict) -> dict:
        """Create new account with validation."""
        if not account_name.strip():
            raise AccountException("账号别名不能为空")
        
        lock_key = f"{user_id}_{account_name}"
        
        async with self._get_lock(lock_key):
            try:
                async with UnitOfWork() as uow:
                    account_repo = uow.get_repository(type(self.repository_factory.get_account_repository()))
                    account_id = self._generate_account_id(user_id, account_name)
                    
                    # Check if account already exists
                    if await account_repo.exists(account_id):
                        raise AccountException("账号已存在")
                    
                    # Create account data
                    new_account = {
                        'id': account_id,
                        'user_id': user_id,
                        'name': account_name,
                        'username': account_data.get('username', ''),
                        'password': account_data.get('password', ''),
                        'channel': account_data.get('channel', config.app.bsdk),
                        'config': account_data.get('config', {}),
                        'daily_result': [],
                        'single_result': {},
                        'created_at': self._get_current_time()
                    }
                    
                    result = await account_repo.create(new_account)
                    await uow.commit()
                    
                    self.logger.info(f"Created account {account_name} for user {user_id}")
                    return result
                    
            except Exception as e:
                self.logger.error(f"Failed to create account {account_name} for user {user_id}: {e}")
                raise AccountException(f"创建账号失败: {e}")
    
    async def update_account(self, user_id: str, account_name: str, account_data: dict) -> dict:
        """Update account data."""
        lock_key = f"{user_id}_{account_name}"
        
        async with self._get_lock(lock_key):
            try:
                async with UnitOfWork() as uow:
                    account_repo = uow.get_repository(type(self.repository_factory.get_account_repository()))
                    account_id = self._generate_account_id(user_id, account_name)
                    
                    # Get existing account
                    existing_account = await account_repo.get_by_id(account_id)
                    if not existing_account:
                        raise AccountException("账号不存在")
                    
                    # Update fields
                    existing_account.update(account_data)
                    existing_account['updated_at'] = self._get_current_time()
                    
                    result = await account_repo.update(existing_account)
                    await uow.commit()
                    
                    self.logger.info(f"Updated account {account_name} for user {user_id}")
                    return result
                    
            except Exception as e:
                self.logger.error(f"Failed to update account {account_name} for user {user_id}: {e}")
                raise AccountException(f"更新账号失败: {e}")
    
    async def delete_account(self, user_id: str, account_name: str) -> bool:
        """Delete account."""
        lock_key = f"{user_id}_{account_name}"
        
        async with self._get_lock(lock_key):
            try:
                async with UnitOfWork() as uow:
                    account_repo = uow.get_repository(type(self.repository_factory.get_account_repository()))
                    account_id = self._generate_account_id(user_id, account_name)
                    
                    result = await account_repo.delete(account_id)
                    await uow.commit()
                    
                    self.logger.info(f"Deleted account {account_name} for user {user_id}")
                    return result
                    
            except Exception as e:
                self.logger.error(f"Failed to delete account {account_name} for user {user_id}: {e}")
                raise AccountException(f"删除账号失败: {e}")
    
    async def list_accounts(self, user_id: str) -> List[dict]:
        """List all accounts for a user."""
        try:
            async with UnitOfWork() as uow:
                account_repo = uow.get_repository(type(self.repository_factory.get_account_repository()))
                return await account_repo.get_by_user(user_id)
                
        except Exception as e:
            self.logger.error(f"Failed to list accounts for user {user_id}: {e}")
            return []
    
    def _generate_account_id(self, user_id: str, account_name: str) -> str:
        """Generate unique account ID."""
        combined = f"{user_id}_{account_name}"
        return hashlib.md5(combined.encode('utf-8')).hexdigest()
    
    def _get_current_time(self) -> str:
        """Get current timestamp."""
        import datetime
        return datetime.datetime.now().isoformat()


class RefactoredAccountManager:
    """
    Refactored account manager using service pattern.
    
    This demonstrates how the original AccountManager class would be
    simplified using the new architecture.
    """
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.logger = ServiceLocator.get(LoggingService)
        self.account_service = DefaultAccountService()
        self.repository_factory = RepositoryFactory()
    
    async def create_account(self, account_name: str, account_data: dict = None) -> dict:
        """Create a new account."""
        account_data = account_data or {}
        return await self.account_service.create_account(self.user_id, account_name, account_data)
    
    async def get_account(self, account_name: str) -> Optional[dict]:
        """Get account by name."""
        return await self.account_service.get_account(self.user_id, account_name)
    
    async def update_account(self, account_name: str, account_data: dict) -> dict:
        """Update account data."""
        return await self.account_service.update_account(self.user_id, account_name, account_data)
    
    async def delete_account(self, account_name: str) -> bool:
        """Delete account."""
        return await self.account_service.delete_account(self.user_id, account_name)
    
    async def list_accounts(self) -> List[dict]:
        """List all user accounts."""
        return await self.account_service.list_accounts(self.user_id)
    
    async def get_default_account(self) -> Optional[str]:
        """Get user's default account name."""
        try:
            async with UnitOfWork() as uow:
                user_repo = uow.get_repository(type(self.repository_factory.get_user_repository()))
                user = await user_repo.get_by_id(self.user_id)
                return user.get('default_account') if user else None
                
        except Exception as e:
            self.logger.error(f"Failed to get default account for user {self.user_id}: {e}")
            return None
    
    async def set_default_account(self, account_name: str):
        """Set user's default account."""
        try:
            async with UnitOfWork() as uow:
                user_repo = uow.get_repository(type(self.repository_factory.get_user_repository()))
                user = await user_repo.get_by_id(self.user_id)
                
                if not user:
                    raise AccountException("用户不存在")
                
                # Verify account exists
                account = await self.account_service.get_account(self.user_id, account_name)
                if not account:
                    raise AccountException("指定的账号不存在")
                
                user['default_account'] = account_name
                await user_repo.update(user)
                await uow.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to set default account for user {self.user_id}: {e}")
            raise AccountException(f"设置默认账号失败: {e}")
    
    async def generate_info(self) -> dict:
        """Generate account information summary."""
        try:
            accounts = await self.list_accounts()
            default_account = await self.get_default_account()
            
            return {
                'user_id': self.user_id,
                'account_count': len(accounts),
                'accounts': [acc.get('name', '') for acc in accounts],
                'default_account': default_account,
                'last_updated': self._get_current_time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate info for user {self.user_id}: {e}")
            return {
                'user_id': self.user_id,
                'error': str(e)
            }
    
    def _get_current_time(self) -> str:
        """Get current timestamp."""
        import datetime
        return datetime.datetime.now().isoformat()


class AccountManagerFactory:
    """Factory for creating account manager instances."""
    
    @staticmethod
    def create(user_id: str) -> RefactoredAccountManager:
        """Create account manager for a user."""
        return RefactoredAccountManager(user_id)
    
    @staticmethod
    def create_with_auth(user_id: str, password: str) -> RefactoredAccountManager:
        """Create account manager with authentication."""
        # In a real implementation, this would verify credentials
        # For now, just create the manager
        return RefactoredAccountManager(user_id)


# Register the account service with the service locator
ServiceLocator.register_factory(AccountService, DefaultAccountService)