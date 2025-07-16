"""
Route management for autopcr HTTP server.

This module organizes HTTP routes into logical groups,
reducing coupling in the main HttpServer class.
"""
from quart import Blueprint
from typing import Callable, Any
from functools import wraps

from .auth_service import auth_service
from ..config import config


class RouteManager:
    """Manages HTTP routes and their organization."""
    
    def __init__(self):
        # Create blueprints for different route groups
        self.web = Blueprint('web', __name__)
        self.api_limit = Blueprint('api_limit', __name__, url_prefix="/")
        self.api = Blueprint('api', __name__, url_prefix="/api")
        self.app = Blueprint('app', __name__, url_prefix="/daily")
        
        # Store route handlers for organization
        self.auth_routes = {}
        self.api_routes = {}
        self.daily_routes = {}
        self.admin_routes = {}
    
    def register_blueprints(self, parent_blueprint: Blueprint):
        """Register all route blueprints with a parent blueprint."""
        parent_blueprint.register_blueprint(self.web)
        parent_blueprint.register_blueprint(self.api)
        self.api.register_blueprint(self.api_limit)
    
    def auth_route(self, path: str, methods: list = None, require_admin: bool = False):
        """Decorator for authentication-required routes."""
        if methods is None:
            methods = ['GET']
        
        def decorator(func: Callable):
            @wraps(func)
            @auth_service.require_auth(require_admin=require_admin)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)
            
            # Register route
            route_name = f"{func.__name__}_{path.replace('/', '_')}"
            self.auth_routes[route_name] = {
                'path': path,
                'methods': methods,
                'handler': wrapper,
                'require_admin': require_admin
            }
            
            # Add to appropriate blueprint
            if path.startswith('/api'):
                self.api.route(path, methods=methods)(wrapper)
            elif path.startswith('/daily'):
                self.app.route(path, methods=methods)(wrapper)
            else:
                self.web.route(path, methods=methods)(wrapper)
            
            return wrapper
        return decorator
    
    def public_route(self, path: str, methods: list = None, blueprint_name: str = 'web'):
        """Decorator for public routes that don't require authentication."""
        if methods is None:
            methods = ['GET']
        
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)
            
            # Get appropriate blueprint
            if blueprint_name == 'api':
                blueprint = self.api
            elif blueprint_name == 'app':
                blueprint = self.app
            else:
                blueprint = self.web
            
            blueprint.route(path, methods=methods)(wrapper)
            return wrapper
        return decorator
    
    def account_route(self, path: str, methods: list = None, readonly: bool = False):
        """Decorator for routes that need account management context."""
        if methods is None:
            methods = ['GET', 'POST']
        
        def decorator(func: Callable):
            @wraps(func)
            @auth_service.require_auth()
            @auth_service.with_account_manager(readonly=readonly)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)
            
            # Register with appropriate blueprint
            if path.startswith('/api'):
                self.api.route(path, methods=methods)(wrapper)
            elif path.startswith('/daily'):
                self.app.route(path, methods=methods)(wrapper)
            else:
                self.web.route(path, methods=methods)(wrapper)
            
            return wrapper
        return decorator
    
    def specific_account_route(self, path: str, methods: list = None, readonly: bool = False):
        """Decorator for routes that operate on a specific account."""
        if methods is None:
            methods = ['GET', 'POST']
        
        def decorator(func: Callable):
            @wraps(func)
            @auth_service.require_auth()
            @auth_service.with_account(readonly=readonly)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)
            
            # Register with appropriate blueprint
            if path.startswith('/api'):
                self.api.route(path, methods=methods)(wrapper)
            elif path.startswith('/daily'):
                self.app.route(path, methods=methods)(wrapper)
            else:
                self.web.route(path, methods=methods)(wrapper)
            
            return wrapper
        return decorator
    
    def rate_limited_route(self, path: str, rate_limit: str, methods: list = None):
        """Decorator for rate-limited routes."""
        if methods is None:
            methods = ['GET', 'POST']
        
        def decorator(func: Callable):
            from quart_rate_limiter import rate_limit as rl_decorator
            
            @wraps(func)
            @rl_decorator(rate_limit, per_method=True)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)
            
            self.api_limit.route(path, methods=methods)(wrapper)
            return wrapper
        return decorator
    
    def get_route_info(self) -> dict:
        """Get information about registered routes."""
        return {
            'auth_routes': self.auth_routes,
            'api_routes': self.api_routes,
            'daily_routes': self.daily_routes,
            'admin_routes': self.admin_routes
        }


# Global route manager instance
route_manager = RouteManager()