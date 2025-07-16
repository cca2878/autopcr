"""
Service factory pattern for dependency injection.

This module provides a centralized way to manage services and their dependencies,
reducing coupling throughout the application.
"""
from typing import Dict, Any, Optional, TypeVar, Type, Callable
from abc import ABC, abstractmethod

T = TypeVar('T')


class ServiceRegistry:
    """Registry for managing service instances and their dependencies."""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._singletons: Dict[str, Any] = {}
    
    def register_singleton(self, interface: Type[T], instance: T) -> None:
        """Register a singleton service instance."""
        service_name = interface.__name__
        self._singletons[service_name] = instance
    
    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory function for creating service instances."""
        service_name = interface.__name__
        self._factories[service_name] = factory
    
    def get(self, interface: Type[T]) -> T:
        """Get a service instance."""
        service_name = interface.__name__
        
        # Check if singleton exists
        if service_name in self._singletons:
            return self._singletons[service_name]
        
        # Check if factory exists
        if service_name in self._factories:
            instance = self._factories[service_name]()
            return instance
        
        # Check if class can be instantiated directly
        try:
            instance = interface()
            return instance
        except Exception:
            raise ValueError(f"No service registered for {interface.__name__}")
    
    def clear(self) -> None:
        """Clear all registered services."""
        self._services.clear()
        self._factories.clear()
        self._singletons.clear()


class ServiceLocator:
    """Service locator for accessing services throughout the application."""
    
    _registry = ServiceRegistry()
    
    @classmethod
    def get(cls, interface: Type[T]) -> T:
        """Get a service instance."""
        return cls._registry.get(interface)
    
    @classmethod
    def register_singleton(cls, interface: Type[T], instance: T) -> None:
        """Register a singleton service."""
        cls._registry.register_singleton(interface, instance)
    
    @classmethod
    def register_factory(cls, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory for a service."""
        cls._registry.register_factory(interface, factory)
    
    @classmethod
    def clear(cls) -> None:
        """Clear all services (mainly for testing)."""
        cls._registry.clear()


class DatabaseService(ABC):
    """Abstract database service interface."""
    
    @abstractmethod
    async def get_connection(self):
        """Get database connection."""
        pass
    
    @abstractmethod
    async def execute_query(self, query: str, params: dict = None):
        """Execute a database query."""
        pass


class ConfigService(ABC):
    """Abstract configuration service interface."""
    
    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        pass


class LoggingService(ABC):
    """Abstract logging service interface."""
    
    @abstractmethod
    def info(self, message: str) -> None:
        """Log info message."""
        pass
    
    @abstractmethod
    def error(self, message: str) -> None:
        """Log error message."""
        pass
    
    @abstractmethod
    def debug(self, message: str) -> None:
        """Log debug message."""
        pass


# Example implementations

class DefaultConfigService(ConfigService):
    """Default configuration service implementation."""
    
    def __init__(self):
        from ..config import config
        self._config = config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        parts = key.split('.')
        value = self._config
        
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value - not implemented for immutable config."""
        raise NotImplementedError("Configuration is read-only")


class DefaultLoggingService(LoggingService):
    """Default logging service implementation."""
    
    def __init__(self):
        try:
            from ..util.logger import instance as logger
            self._logger = logger
        except ImportError:
            # Fallback to basic logging
            import logging
            self._logger = logging.getLogger(__name__)
    
    def info(self, message: str) -> None:
        """Log info message."""
        if hasattr(self._logger, 'info'):
            self._logger.info(message)
        else:
            print(f"INFO: {message}")
    
    def error(self, message: str) -> None:
        """Log error message."""
        if hasattr(self._logger, 'error'):
            self._logger.error(message)
        else:
            print(f"ERROR: {message}")
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        if hasattr(self._logger, 'debug'):
            self._logger.debug(message)
        else:
            print(f"DEBUG: {message}")


# Register default services
ServiceLocator.register_factory(ConfigService, DefaultConfigService)
ServiceLocator.register_factory(LoggingService, DefaultLoggingService)