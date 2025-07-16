"""
Refactored HTTP server using new service architecture.

This version demonstrates how the HttpServer class would look
after applying the optimization patterns.
"""
import os
import secrets
from typing import Callable, Coroutine, Any

# Note: These imports would normally work when dependencies are installed
try:
    import quart
    from quart import request, Blueprint, send_file, send_from_directory
    from quart_auth import QuartAuth, Unauthorized, login_required
    from quart_compress import Compress
    from quart_rate_limiter import RateLimiter, RateLimitExceeded
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    # Mock classes for demonstration when dependencies are missing
    class Blueprint:
        def __init__(self, *args, **kwargs): pass
        def route(self, *args, **kwargs): return lambda f: f
        def register_blueprint(self, *args): pass
        def errorhandler(self, *args): return lambda f: f
    
    class QuartAuth:
        def __init__(self, *args, **kwargs): pass
    
    class RateLimiter:
        def __init__(self, *args, **kwargs): pass
    
    class Compress:
        def __init__(self, *args, **kwargs): pass
    
    class Unauthorized(Exception): pass
    class RateLimitExceeded(Exception): pass
    
    def login_required(f): return f
    
    DEPENDENCIES_AVAILABLE = False

from ..config import config
from ..core.service_locator import ServiceLocator, ConfigService, LoggingService
from ..db.repository import RepositoryFactory
from .auth_service import auth_service
from .route_manager import route_manager


class RefactoredHttpServer:
    """
    Refactored HTTP server using service architecture.
    
    This demonstrates how the original HttpServer class would be
    simplified using the new patterns.
    """
    
    def __init__(self, host: str = None, port: int = None, qq_only: bool = False):
        # Use configuration service instead of hardcoded values
        self.config_service = ServiceLocator.get(ConfigService)
        self.logger = ServiceLocator.get(LoggingService)
        
        # Get configuration values
        self.host = host or self.config_service.get('server.host', '0.0.0.0')
        self.port = port or self.config_service.get('server.port', 13200)
        self.qq_only = qq_only
        
        # Initialize Flask/Quart app with dependency injection
        self.app = self._create_app()
        
        # Use route manager for organizing routes
        self.route_manager = route_manager
        
        # Initialize services
        self.auth_service = auth_service
        self.repository_factory = RepositoryFactory()
        
        # Setup server
        self._setup_blueprints()
        self._configure_middleware()
        self._register_routes()
        
        self.logger.info(f"HTTP Server initialized on {self.host}:{self.port}")
    
    def _create_app(self):
        """Create and configure the main application."""
        if not DEPENDENCIES_AVAILABLE:
            # Return mock object when dependencies are missing
            return type('MockApp', (), {
                'register_blueprint': lambda self, bp: None,
                'secret_key': None
            })()
        
        app = quart.Quart(__name__)
        QuartAuth(app, cookie_secure=False)
        RateLimiter(app)
        Compress(app)
        app.secret_key = self._get_or_create_secret()
        return app
    
    def _get_or_create_secret(self) -> str:
        """Get or create server secret key."""
        cache_dir = self.config_service.get('paths.cache_dir')
        secret_path = os.path.join(cache_dir, 'http_server', 'server_secret')
        
        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        
        if not os.path.exists(secret_path):
            with open(secret_path, 'w') as f:
                f.write(secrets.token_urlsafe(256))
        
        with open(secret_path, 'r') as f:
            return f.read().strip()
    
    def _setup_blueprints(self):
        """Setup application blueprints."""
        # Get static paths from configuration
        static_path = self._get_static_path()
        
        # Create main blueprint
        self.main_blueprint = Blueprint('main', __name__, url_prefix="/daily")
        
        # Register with route manager
        self.route_manager.register_blueprints(self.main_blueprint)
        
        # Register with app
        self.app.register_blueprint(self.main_blueprint)
    
    def _get_static_path(self) -> str:
        """Get static files path from configuration."""
        path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(path, 'ClientAppVue')
    
    def _configure_middleware(self):
        """Configure middleware and error handlers."""
        if not DEPENDENCIES_AVAILABLE:
            return
        
        # Global error handlers using route manager
        @self.route_manager.api.errorhandler(RateLimitExceeded)
        async def handle_rate_limit_exceeded_error(error):
            self.logger.info(f"Rate limit exceeded: {error}")
            return "您冲得太快了，休息一下吧", 429
        
        @self.route_manager.api.errorhandler(Unauthorized)
        async def redirect_to_login(*_):
            self.logger.info("Unauthorized access attempt")
            return "未登录，请登录", 401
    
    def _register_routes(self):
        """Register all application routes using the route manager."""
        self._register_account_routes()
        self._register_task_routes()
        self._register_auth_routes()
        self._register_admin_routes()
    
    def _register_account_routes(self):
        """Register account management routes."""
        
        @self.route_manager.account_route('/api/account', ['GET'], readonly=True)
        async def get_account_info(accountmgr):
            """Get account information."""
            try:
                info = await accountmgr.generate_info()
                return info, 200
            except Exception as e:
                self.logger.error(f"Failed to get account info: {e}")
                return "服务器发生错误", 500
        
        @self.route_manager.account_route('/api/account', ['PUT'])
        async def update_account_info(accountmgr):
            """Update account information."""
            try:
                data = await request.get_json() if DEPENDENCIES_AVAILABLE else {}
                default_account = data.get('default_account', '')
                if default_account:
                    accountmgr.set_default_account(default_account)
                return "保存成功", 200
            except Exception as e:
                self.logger.error(f"Failed to update account: {e}")
                return "服务器发生错误", 500
        
        @self.route_manager.account_route('/api/account', ['POST'])
        async def create_account(accountmgr):
            """Create new account."""
            try:
                data = await request.get_json() if DEPENDENCIES_AVAILABLE else {}
                alias = data.get("alias", "").strip()
                if not alias:
                    return "账号别名不能为空", 400
                
                accountmgr.create_account(alias)
                return "创建账号成功", 200
            except Exception as e:
                self.logger.error(f"Failed to create account: {e}")
                return str(e), 400
    
    def _register_task_routes(self):
        """Register task execution routes."""
        
        @self.route_manager.specific_account_route('/api/daily/<acc>', ['POST'])
        async def run_daily_task(account, acc: str):
            """Run daily tasks for specific account."""
            try:
                # Use the new module management system
                from ..module.simple_module_mgr import TaskExecutor, ExecutionContext
                
                executor = TaskExecutor(self.route_manager.module_registry)
                context = ExecutionContext({
                    'account': account,
                    'account_name': acc
                })
                
                # Define default daily modules
                daily_modules = ['daily', 'shop', 'gacha']  # Example modules
                
                result = await executor.execute_task(
                    task_name="daily_task",
                    modules=daily_modules,
                    context=context
                )
                
                if result.is_success:
                    return {"status": "success", "message": "日常任务完成"}, 200
                else:
                    failed = result.failed_modules
                    return {
                        "status": "partial_failure", 
                        "message": f"部分任务失败: {', '.join(failed)}"
                    }, 207
                    
            except Exception as e:
                self.logger.error(f"Daily task failed for {acc}: {e}")
                return {"status": "error", "message": "任务执行失败"}, 500
    
    def _register_auth_routes(self):
        """Register authentication routes."""
        
        @self.route_manager.public_route('/api/login', ['POST'])
        async def login():
            """User login endpoint."""
            try:
                data = await request.get_json() if DEPENDENCIES_AVAILABLE else {}
                username = data.get('username', '')
                password = data.get('password', '')
                
                if await self.auth_service.login(username, password):
                    return {"status": "success", "message": "登录成功"}, 200
                else:
                    return {"status": "error", "message": "用户名或密码错误"}, 401
                    
            except Exception as e:
                self.logger.error(f"Login failed: {e}")
                return {"status": "error", "message": "登录失败"}, 500
        
        @self.route_manager.auth_route('/api/logout', ['POST'])
        async def logout():
            """User logout endpoint."""
            try:
                await self.auth_service.logout()
                return {"status": "success", "message": "退出成功"}, 200
            except Exception as e:
                self.logger.error(f"Logout failed: {e}")
                return {"status": "error", "message": "退出失败"}, 500
    
    def _register_admin_routes(self):
        """Register admin-only routes."""
        
        @self.route_manager.auth_route('/api/admin/users', ['GET'], require_admin=True)
        async def get_all_users():
            """Get all users (admin only)."""
            try:
                user_repo = self.repository_factory.get_user_repository()
                users = await user_repo.get_all()
                return {"users": users}, 200
            except Exception as e:
                self.logger.error(f"Failed to get users: {e}")
                return {"status": "error", "message": "获取用户列表失败"}, 500
    
    async def run(self):
        """Run the HTTP server."""
        if not DEPENDENCIES_AVAILABLE:
            self.logger.info("Dependencies not available, server cannot run")
            return
        
        self.logger.info(f"Starting HTTP server on {self.host}:{self.port}")
        await self.app.run_task(host=self.host, port=self.port)
    
    def get_route_info(self) -> dict:
        """Get information about registered routes."""
        return {
            "total_routes": len(self.route_manager.get_route_info()),
            "server_config": {
                "host": self.host,
                "port": self.port,
                "qq_only": self.qq_only
            },
            "services": {
                "auth_service": "configured",
                "config_service": "configured", 
                "repository_factory": "configured"
            }
        }


# Factory function for creating server instances
def create_http_server(host: str = None, port: int = None, qq_only: bool = False) -> RefactoredHttpServer:
    """Create a new HTTP server instance with dependency injection."""
    return RefactoredHttpServer(host, port, qq_only)