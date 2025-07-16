# coding: utf-8
"""
Improved HTTP server with dependency injection and better separation of concerns
Demonstrates loose coupling and cleaner architecture
"""

import os
from typing import Optional, Callable, Any
import secrets
from abc import ABC, abstractmethod

from quart import Blueprint, Quart
from quart_auth import QuartAuth
from quart_rate_limiter import RateLimiter
from quart_compress import Compress

from ..config import get_http_server_config, HttpServerConfig


class HttpServerInterface(ABC):
    """Interface for HTTP server - enables testing and different implementations"""
    
    @abstractmethod
    async def start(self) -> None:
        """Start the HTTP server"""
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """Stop the HTTP server"""
        pass
    
    @abstractmethod
    def register_blueprint(self, blueprint: Blueprint) -> None:
        """Register a blueprint with the server"""
        pass


class ImprovedHttpServer(HttpServerInterface):
    """
    Improved HTTP server with better architecture:
    - Uses dependency injection for configuration
    - Separates concerns with clear interfaces
    - Reduces coupling to external modules
    """
    
    def __init__(self, 
                 config: Optional[HttpServerConfig] = None,
                 auth_factory: Optional[Callable] = None,
                 rate_limiter_factory: Optional[Callable] = None):
        """
        Initialize server with dependency injection
        
        Args:
            config: Server configuration (defaults to global config)
            auth_factory: Factory function for authentication setup
            rate_limiter_factory: Factory function for rate limiter setup
        """
        self._config = config or get_http_server_config()
        self._auth_factory = auth_factory or self._default_auth_factory
        self._rate_limiter_factory = rate_limiter_factory or self._default_rate_limiter_factory
        
        # Initialize Quart app
        self._app = Quart(__name__)
        self._setup_app()
        
        # Extension instances
        self._auth = None
        self._rate_limiter = None
        self._compress = None
        
    def _setup_app(self) -> None:
        """Setup basic app configuration"""
        self._app.config.update({
            'SECRET_KEY': self._config.secret_key or secrets.token_urlsafe(16),
            'DEBUG': self._config.debug,
            'HOST': self._config.host,
            'PORT': self._config.port
        })
        
    def _default_auth_factory(self, app: Quart) -> QuartAuth:
        """Default authentication setup"""
        return QuartAuth(app, cookie_secure=False)
    
    def _default_rate_limiter_factory(self, app: Quart) -> RateLimiter:
        """Default rate limiter setup"""
        return RateLimiter(app)
    
    def _setup_extensions(self) -> None:
        """Setup Quart extensions with dependency injection"""
        if not self._auth:
            self._auth = self._auth_factory(self._app)
        
        if not self._rate_limiter:
            self._rate_limiter = self._rate_limiter_factory(self._app)
            
        if not self._compress:
            self._compress = Compress(self._app)
    
    def register_blueprint(self, blueprint: Blueprint) -> None:
        """Register a blueprint with the server"""
        self._app.register_blueprint(blueprint)
    
    async def start(self) -> None:
        """Start the HTTP server"""
        self._setup_extensions()
        
        # In real implementation, would start server
        # For now, just ensure setup is complete
        print(f"HTTP Server configured to start on {self._config.host}:{self._config.port}")
    
    async def stop(self) -> None:
        """Stop the HTTP server"""
        # Cleanup logic would go here
        pass
    
    @property
    def app(self) -> Quart:
        """Get the underlying Quart app (for compatibility)"""
        return self._app
    
    @property
    def config(self) -> HttpServerConfig:
        """Get server configuration"""
        return self._config


class HttpServerFactory:
    """Factory for creating HTTP server instances"""
    
    @staticmethod
    def create_server(server_type: str = "standard", **kwargs) -> HttpServerInterface:
        """
        Create HTTP server instance
        
        Args:
            server_type: Type of server to create
            **kwargs: Additional arguments for server creation
            
        Returns:
            HTTP server instance
        """
        if server_type == "standard":
            return ImprovedHttpServer(**kwargs)
        elif server_type == "test":
            # Could return a test server implementation
            config = HttpServerConfig(debug=True, port=0)
            return ImprovedHttpServer(config=config, **kwargs)
        else:
            raise ValueError(f"Unknown server type: {server_type}")


# Backwards compatibility adapter for existing code
class LegacyHttpServerAdapter:
    """Adapter to maintain compatibility with existing HttpServer interface"""
    
    def __init__(self, host='0.0.0.0', port=2, qq_only=False):
        """Initialize with legacy parameters"""
        config = HttpServerConfig(host=host, port=port)
        self._server = ImprovedHttpServer(config=config)
        self._qq_only = qq_only
        
        # Legacy blueprint setup
        self.web = Blueprint('web', __name__)
        self.api = Blueprint('api', __name__, url_prefix="/api")
        self.app = Blueprint('app', __name__, url_prefix="/daily")
        
        # Register blueprints
        self._server.register_blueprint(self.web)
        self._server.register_blueprint(self.api)
        self._server.register_blueprint(self.app)
    
    @property
    def quart(self) -> Quart:
        """Get Quart app for backwards compatibility"""
        return self._server.app


__all__ = [
    'HttpServerInterface', 'ImprovedHttpServer', 'HttpServerFactory', 
    'LegacyHttpServerAdapter'
]