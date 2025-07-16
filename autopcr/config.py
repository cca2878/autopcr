"""
Centralized configuration management for autopcr.

This module provides a single source of truth for all configuration values,
supporting both environment variables and default values.
"""
import os
from typing import Optional, Union
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ServerConfig:
    """HTTP server configuration."""
    host: str = '0.0.0.0'
    port: int = 13200
    debug_log: bool = False
    allow_register: bool = True
    superuser: Optional[str] = None


@dataclass
class PathConfig:
    """File system paths configuration."""
    root_dir: str
    cache_dir: str
    result_dir: str
    data_dir: str
    config_path: str
    old_config_path: str
    
    @classmethod
    def create_default(cls) -> 'PathConfig':
        """Create default path configuration."""
        root_dir = os.path.join(os.path.dirname(__file__), '..')
        return cls(
            root_dir=root_dir,
            cache_dir=os.path.join(root_dir, './cache/'),
            result_dir=os.path.join(root_dir, './result/'),
            data_dir=os.path.join(root_dir, './data/'),
            config_path=os.path.join(root_dir, './cache/http_server/'),
            old_config_path=os.path.join(root_dir, 'autopcr/http_server/config')
        )


@dataclass
class AppConfig:
    """Application configuration."""
    version: str = "1.4.0"
    auth_key: str = ""
    clan_battle_forbid_path: str = ""
    bsdk: str = "1"  # Default SDK value
    
    # Game-specific headers
    default_headers: dict = None
    ios_headers: dict = None
    
    def __post_init__(self):
        if self.default_headers is None:
            self.default_headers = {
                'Accept-Encoding': 'gzip',
                'User-Agent': 'Dalvik/2.1.0 (Linux, U, Android 5.1.1, PCRT00 Build/LMY48Z)',
                'X-Unity-Version': '2021.3.20f1c1',
                'APP-VER': "7.7.1",
                'BATTLE-LOGIC-VERSION': '4',
                'BUNDLE-VER': '',
                'DEVICE': '2',
                'DEVICE-ID': '7b1703a5d9b394e24051d7a5d4818f17',
                'DEVICE-NAME': 'OPPO PCRT00',
                'EXCEL-VER': '1.0.0',
                'GRAPHICS-DEVICE-NAME': 'Adreno (TM) 640',
                'IP-ADDRESS': '10.0.2.15',
                'KEYCHAIN': '',
                'LOCALE': 'CN',
                'PLATFORM-OS-VERSION': 'Android OS 5.1.1 / API-22 (LMY48Z/rel.se.infra.20200612.100533)',
                'REGION-CODE': '',
                'RES-KEY': 'ab00a0a6dd915a052a2ef7fd649083e5',
                'RES-VER': '10002200',
                'SHORT-UDID': '0'
            }
        
        if self.ios_headers is None:
            self.ios_headers = {
                'Accept-Encoding': 'gzip',
                'User-Agent': 'priconne/24 CFNetwork/1492.0.1 Darwin/23.3.0',
                'X-Unity-Version': '2021.3.20f1c1',
                'APP-VER': "7.7.1",
                'BATTLE-LOGIC-VERSION': '4',
                'BUNDLE-VER': '',
                'DEVICE': '1',
                'DEVICE-ID': 'CB03A1AC-B27D-5E96-9422-CBF0F4D333D7',
                'DEVICE-NAME': 'iPad13,8',
                'EXCEL-VER': '1.0.0',
                'GRAPHICS-DEVICE-NAME': 'Apple M1',
                'IP-ADDRESS': '172.26.62.98',
                'KEYCHAIN': '',
                'LOCALE': 'CN',
                'PLATFORM-OS-VERSION': 'iOS 17.3',
                'REGION-CODE': '',
                'RES-KEY': 'ab00a0a6dd915a052a2ef7fd649083e5',
                'RES-VER': '10002200',
                'SHORT-UDID': '0'
            }


class ConfigManager:
    """Centralized configuration manager."""
    
    def __init__(self):
        self._server_config = None
        self._path_config = None
        self._app_config = None
    
    @property
    def server(self) -> ServerConfig:
        """Get server configuration."""
        if self._server_config is None:
            self._server_config = ServerConfig(
                host=self._get_env('AUTOPCR_SERVER_HOST', '0.0.0.0'),
                port=int(self._get_env('AUTOPCR_SERVER_PORT', '13200')),
                debug_log=self._get_bool_env('AUTOPCR_SERVER_DEBUG_LOG', False),
                allow_register=self._get_bool_env('AUTOPCR_SERVER_ALLOW_REGISTER', True),
                superuser=self._get_env('AUTOPCR_SERVER_SUPERUSER', None)
            )
        return self._server_config
    
    @property
    def paths(self) -> PathConfig:
        """Get path configuration."""
        if self._path_config is None:
            self._path_config = PathConfig.create_default()
        return self._path_config
    
    @property
    def app(self) -> AppConfig:
        """Get application configuration."""
        if self._app_config is None:
            self._app_config = AppConfig(
                version=self._get_env('AUTOPCR_APP_VERSION', '1.4.0'),
                auth_key=self._get_env('AUTOPCR_AUTH_KEY', ''),
                clan_battle_forbid_path=self._get_env('AUTOPCR_CLAN_BATTLE_FORBID_PATH', ''),
                bsdk=self._get_env('AUTOPCR_BSDK', '1')
            )
        return self._app_config
    
    def _get_env(self, key: str, default: str = None) -> Optional[str]:
        """Get environment variable with default value."""
        return os.environ.get(key, default)
    
    def _get_bool_env(self, key: str, default: bool = False) -> bool:
        """Get boolean environment variable with default value."""
        value = os.environ.get(key, '').lower()
        if value in ('true', '1', 'yes', 'on'):
            return True
        elif value in ('false', '0', 'no', 'off'):
            return False
        return default
    
    def refresh_headers(self, version: str = None):
        """Refresh app version in headers."""
        if version is not None:
            # Update version file
            version_path = os.path.join(self.paths.cache_dir, 'version.txt')
            os.makedirs(os.path.dirname(version_path), exist_ok=True)
            with open(version_path, 'w', encoding='utf-8') as f:
                f.write(version)
            self.app.version = version
        else:
            # Load version from file
            try:
                version_path = os.path.join(self.paths.cache_dir, 'version.txt')
                with open(version_path, 'r', encoding='utf-8') as f:
                    self.app.version = f.read().strip()
            except FileNotFoundError:
                self.refresh_headers('6.2.0')
                return
        
        # Update headers
        self.app.default_headers['APP-VER'] = self.app.version
        self.app.ios_headers['APP-VER'] = self.app.version


# Global configuration instance
config = ConfigManager()

# Backward compatibility - expose old constants
ROOT_DIR = config.paths.root_dir
CACHE_DIR = config.paths.cache_dir
RESULT_DIR = config.paths.result_dir
DATA_DIR = config.paths.data_dir
CONFIG_PATH = config.paths.config_path
OLD_CONFIG_PATH = config.paths.old_config_path
AUTH_KEY = config.app.auth_key
DEFAULT_HEADERS = config.app.default_headers
IOS_HEADERS = config.app.ios_headers
refresh_headers = config.refresh_headers

# Initialize headers
config.refresh_headers()