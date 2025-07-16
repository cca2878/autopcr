"""
Authentication service for autopcr HTTP server.

This module provides authentication and authorization functionality,
separated from the main HTTP server to reduce coupling.
"""
from typing import Optional
from quart_auth import AuthUser, current_user, login_user, logout_user
from functools import wraps

from ..module.accountmgr import AccountManager, instance as usermgr
from ..module.accountmgr import UserDisabledException, PermissionLimitedException
from ..config import config


class AuthService:
    """Authentication and authorization service."""
    
    def __init__(self):
        self.usermgr = usermgr
    
    async def authenticate_user(self, username: str, password: str) -> Optional[AuthUser]:
        """
        Authenticate user credentials.
        
        Args:
            username: User identifier
            password: User password
            
        Returns:
            AuthUser if authentication successful, None otherwise
        """
        try:
            async with self.usermgr.load(username, readonly=True) as mgr:
                if mgr.verify_password(password):
                    return AuthUser(username)
        except Exception:
            pass
        return None
    
    async def login(self, username: str, password: str) -> bool:
        """
        Login user with credentials.
        
        Args:
            username: User identifier
            password: User password
            
        Returns:
            True if login successful, False otherwise
        """
        user = await self.authenticate_user(username, password)
        if user:
            login_user(user, remember=True)
            return True
        return False
    
    async def logout(self):
        """Logout current user."""
        logout_user()
    
    async def is_authenticated(self) -> bool:
        """Check if current user is authenticated."""
        return await current_user.is_authenticated
    
    async def get_current_user_id(self) -> Optional[str]:
        """Get current authenticated user ID."""
        if await self.is_authenticated():
            return current_user.auth_id
        return None
    
    async def check_user_permissions(self) -> bool:
        """
        Check if current user has valid permissions.
        
        Returns:
            True if user has valid permissions
            
        Raises:
            UserDisabledException: If user is disabled
            PermissionLimitedException: If user lacks permissions
        """
        if not await self.is_authenticated():
            return False
        
        user_id = current_user.auth_id
        try:
            async with self.usermgr.load(user_id, readonly=True) as mgr:
                if mgr.secret.disabled:
                    raise UserDisabledException("User account is disabled")
                return True
        except Exception as e:
            if isinstance(e, (UserDisabledException, PermissionLimitedException)):
                raise
            return False
    
    async def is_admin(self) -> bool:
        """Check if current user is an admin."""
        if not await self.is_authenticated():
            return False
        
        user_id = current_user.auth_id
        
        # Check if user is configured as superuser
        if config.server.superuser and user_id == config.server.superuser:
            return True
        
        try:
            async with self.usermgr.load(user_id, readonly=True) as mgr:
                return mgr.secret.admin
        except Exception:
            return False
    
    def require_auth(self, require_admin: bool = False):
        """
        Decorator to require authentication for endpoints.
        
        Args:
            require_admin: Whether admin privileges are required
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not await self.is_authenticated():
                    from quart_auth import Unauthorized
                    raise Unauthorized()
                
                await self.check_user_permissions()
                
                if require_admin and not await self.is_admin():
                    raise PermissionLimitedException("Admin privileges required")
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def with_account_manager(self, readonly: bool = False):
        """
        Decorator to inject AccountManager for current user.
        
        Args:
            readonly: Whether to open in readonly mode
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                user_id = await self.get_current_user_id()
                if not user_id:
                    from quart_auth import Unauthorized
                    raise Unauthorized()
                
                async with self.usermgr.load(user_id, readonly) as mgr:
                    return await func(accountmgr=mgr, *args, **kwargs)
            return wrapper
        return decorator
    
    def with_account(self, readonly: bool = False):
        """
        Decorator to inject Account for current user and specified account name.
        
        Args:
            readonly: Whether to open in readonly mode
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(acc: str, *args, **kwargs):
                if not acc:
                    return "Please specify an account", 400
                
                user_id = await self.get_current_user_id()
                if not user_id:
                    from quart_auth import Unauthorized
                    raise Unauthorized()
                
                async with self.usermgr.load(user_id, readonly) as accountmgr:
                    async with accountmgr.load(acc, readonly) as account:
                        return await func(account, *args, **kwargs)
            return wrapper
        return decorator


# Global authentication service instance
auth_service = AuthService()