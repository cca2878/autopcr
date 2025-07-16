# coding: utf-8
"""
Configuration management module
Centralizes configuration and reduces coupling between modules
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class DatabaseConfig:
    """Database configuration with defaults"""
    connection_string: str = "sqlite:///cache/autopcr.db"
    pool_size: int = 5
    echo_sql: bool = False
    migration_path: str = "alembic"
    
@dataclass  
class HttpServerConfig:
    """HTTP server configuration"""
    host: str = "0.0.0.0"
    port: int = 2
    debug: bool = False
    secret_key: Optional[str] = None
    rate_limit: int = 100
    
@dataclass
class ModuleConfig:
    """Module execution configuration"""
    max_retries: int = 3
    timeout_seconds: int = 300
    parallel_execution: bool = False
    log_level: str = "INFO"

@dataclass
class AppConfig:
    """Main application configuration"""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    http_server: HttpServerConfig = field(default_factory=HttpServerConfig)
    modules: ModuleConfig = field(default_factory=ModuleConfig)
    
    # Path configurations (centralized)
    root_dir: str = field(default_factory=lambda: os.path.join(os.path.dirname(__file__), '../..'))
    cache_dir: str = field(default="./cache/")
    result_dir: str = field(default="./result/")
    data_dir: str = field(default="./data/")
    
    def __post_init__(self):
        """Resolve relative paths to absolute"""
        base_path = Path(self.root_dir)
        self.cache_dir = str(base_path / self.cache_dir)
        self.result_dir = str(base_path / self.result_dir)
        self.data_dir = str(base_path / self.data_dir)


class ConfigurationManager:
    """Centralized configuration management"""
    
    _instance: Optional['ConfigurationManager'] = None
    _config: Optional[AppConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self._config = self._load_config()
    
    def _load_config(self) -> AppConfig:
        """Load configuration from environment and defaults"""
        config = AppConfig()
        
        # Override with environment variables if present
        if os.getenv('DATABASE_URL'):
            config.database.connection_string = os.getenv('DATABASE_URL')
            
        if os.getenv('HTTP_PORT'):
            config.http_server.port = int(os.getenv('HTTP_PORT'))
            
        if os.getenv('HTTP_HOST'):
            config.http_server.host = os.getenv('HTTP_HOST')
            
        if os.getenv('DEBUG'):
            config.http_server.debug = os.getenv('DEBUG').lower() == 'true'
            
        if os.getenv('SECRET_KEY'):
            config.http_server.secret_key = os.getenv('SECRET_KEY')
            
        return config
    
    @property 
    def config(self) -> AppConfig:
        """Get current configuration"""
        return self._config
    
    def update_config(self, **kwargs):
        """Update configuration values"""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
    
    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration"""
        return self._config.database
    
    def get_http_server_config(self) -> HttpServerConfig:
        """Get HTTP server configuration"""
        return self._config.http_server
    
    def get_module_config(self) -> ModuleConfig:
        """Get module configuration"""
        return self._config.modules


# Global configuration instance
config_manager = ConfigurationManager()

def get_config() -> AppConfig:
    """Get application configuration"""
    return config_manager.config

def get_database_config() -> DatabaseConfig:
    """Get database configuration"""
    return config_manager.get_database_config()

def get_http_server_config() -> HttpServerConfig:
    """Get HTTP server configuration"""  
    return config_manager.get_http_server_config()

def get_module_config() -> ModuleConfig:
    """Get module configuration"""
    return config_manager.get_module_config()

__all__ = [
    'AppConfig', 'DatabaseConfig', 'HttpServerConfig', 'ModuleConfig',
    'ConfigurationManager', 'get_config', 'get_database_config', 
    'get_http_server_config', 'get_module_config', 'config_manager'
]