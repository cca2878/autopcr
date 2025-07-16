"""
Simplified module management system.

This module provides a cleaner, less coupled approach to module management
by using composition over inheritance and reducing abstract class complexity.
"""
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from abc import ABC, abstractmethod


class ModuleStatus(Enum):
    """Module execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ModulePriority(Enum):
    """Module execution priority."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ModuleConfig:
    """Configuration for a module."""
    enabled: bool = True
    priority: ModulePriority = ModulePriority.NORMAL
    timeout: int = 300
    retry_count: int = 3
    retry_delay: int = 5
    dependencies: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """Result of module execution."""
    module_name: str
    status: ModuleStatus
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        """Check if module executed successfully."""
        return self.status == ModuleStatus.SUCCESS
    
    @property
    def is_failed(self) -> bool:
        """Check if module failed."""
        return self.status == ModuleStatus.FAILED


@dataclass
class TaskResult:
    """Result of task execution containing multiple modules."""
    task_name: str
    modules: Dict[str, ModuleResult] = field(default_factory=dict)
    execution_order: List[str] = field(default_factory=list)
    total_time: float = 0.0
    
    def add_module_result(self, result: ModuleResult):
        """Add a module result to the task."""
        self.modules[result.module_name] = result
        if result.module_name not in self.execution_order:
            self.execution_order.append(result.module_name)
    
    @property
    def is_success(self) -> bool:
        """Check if all modules succeeded."""
        return all(result.is_success for result in self.modules.values())
    
    @property
    def failed_modules(self) -> List[str]:
        """Get list of failed module names."""
        return [name for name, result in self.modules.items() if result.is_failed]


class Module(ABC):
    """Base class for all modules."""
    
    def __init__(self, name: str, config: ModuleConfig = None):
        self.name = name
        self.config = config or ModuleConfig()
    
    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> ModuleResult:
        """Execute the module with given context."""
        pass
    
    async def pre_execute(self, context: Dict[str, Any]) -> bool:
        """Pre-execution hook. Return False to skip execution."""
        return True
    
    async def post_execute(self, result: ModuleResult, context: Dict[str, Any]):
        """Post-execution hook."""
        pass
    
    def get_dependencies(self) -> List[str]:
        """Get list of module dependencies."""
        return self.config.dependencies


class ModuleRegistry:
    """Registry for managing available modules."""
    
    def __init__(self):
        self._modules: Dict[str, type] = {}
        self._instances: Dict[str, Module] = {}
    
    def register(self, module_class: type):
        """Register a module class."""
        if not issubclass(module_class, Module):
            raise ValueError("Module must inherit from Module base class")
        
        # Use class name as default module name
        module_name = getattr(module_class, 'module_name', module_class.__name__)
        self._modules[module_name] = module_class
    
    def get_module(self, name: str, config: ModuleConfig = None) -> Module:
        """Get a module instance."""
        if name not in self._modules:
            raise ValueError(f"Module '{name}' not registered")
        
        # Return cached instance or create new one
        cache_key = f"{name}_{id(config) if config else 'default'}"
        if cache_key not in self._instances:
            self._instances[cache_key] = self._modules[name](name, config)
        
        return self._instances[cache_key]
    
    def get_available_modules(self) -> List[str]:
        """Get list of available module names."""
        return list(self._modules.keys())
    
    def clear_cache(self):
        """Clear module instance cache."""
        self._instances.clear()


class ExecutionContext:
    """Context for module execution."""
    
    def __init__(self, initial_data: Dict[str, Any] = None):
        self.data = initial_data or {}
        self.shared_state = {}
        self.execution_log = []
    
    def set(self, key: str, value: Any):
        """Set context data."""
        self.data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get context data."""
        return self.data.get(key, default)
    
    def set_shared(self, key: str, value: Any):
        """Set shared state between modules."""
        self.shared_state[key] = value
    
    def get_shared(self, key: str, default: Any = None) -> Any:
        """Get shared state."""
        return self.shared_state.get(key, default)
    
    def log(self, message: str):
        """Add log entry."""
        self.execution_log.append(message)


class TaskExecutor:
    """Executes tasks containing multiple modules."""
    
    def __init__(self, registry: ModuleRegistry):
        self.registry = registry
    
    async def execute_task(self, 
                          task_name: str,
                          modules: List[str],
                          context: ExecutionContext,
                          configs: Dict[str, ModuleConfig] = None) -> TaskResult:
        """
        Execute a task containing multiple modules.
        
        Args:
            task_name: Name of the task
            modules: List of module names to execute
            context: Execution context
            configs: Module-specific configurations
            
        Returns:
            TaskResult containing execution results
        """
        configs = configs or {}
        result = TaskResult(task_name)
        
        # Resolve module execution order based on dependencies
        execution_order = self._resolve_dependencies(modules, configs)
        
        for module_name in execution_order:
            module_config = configs.get(module_name, ModuleConfig())
            
            if not module_config.enabled:
                module_result = ModuleResult(
                    module_name=module_name,
                    status=ModuleStatus.SKIPPED,
                    message="Module disabled in configuration"
                )
                result.add_module_result(module_result)
                continue
            
            try:
                module = self.registry.get_module(module_name, module_config)
                module_result = await self._execute_module(module, context)
                result.add_module_result(module_result)
                
                # Stop execution if a critical module fails
                if (module_result.is_failed and 
                    module_config.priority == ModulePriority.CRITICAL):
                    break
                    
            except Exception as e:
                module_result = ModuleResult(
                    module_name=module_name,
                    status=ModuleStatus.FAILED,
                    error=str(e),
                    message=f"Module execution failed: {e}"
                )
                result.add_module_result(module_result)
        
        return result
    
    async def _execute_module(self, module: Module, context: ExecutionContext) -> ModuleResult:
        """Execute a single module with error handling and timeouts."""
        import time
        
        start_time = time.time()
        
        try:
            # Pre-execution check
            if not await module.pre_execute(context.data):
                return ModuleResult(
                    module_name=module.name,
                    status=ModuleStatus.SKIPPED,
                    message="Pre-execution check failed"
                )
            
            # Execute with timeout
            result = await asyncio.wait_for(
                module.execute(context.data),
                timeout=module.config.timeout
            )
            
            result.execution_time = time.time() - start_time
            
            # Post-execution hook
            await module.post_execute(result, context.data)
            
            return result
            
        except asyncio.TimeoutError:
            return ModuleResult(
                module_name=module.name,
                status=ModuleStatus.FAILED,
                error="Timeout",
                message=f"Module timed out after {module.config.timeout} seconds",
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ModuleResult(
                module_name=module.name,
                status=ModuleStatus.FAILED,
                error=str(e),
                message=f"Module execution failed: {e}",
                execution_time=time.time() - start_time
            )
    
    def _resolve_dependencies(self, 
                             modules: List[str], 
                             configs: Dict[str, ModuleConfig]) -> List[str]:
        """Resolve module execution order based on dependencies."""
        resolved = []
        remaining = set(modules)
        
        while remaining:
            ready = []
            
            for module_name in remaining:
                config = configs.get(module_name, ModuleConfig())
                dependencies = config.dependencies
                
                # Check if all dependencies are resolved
                if all(dep in resolved for dep in dependencies):
                    ready.append(module_name)
            
            if not ready:
                # Circular dependency or missing dependency
                raise ValueError(f"Cannot resolve dependencies for modules: {remaining}")
            
            # Sort by priority (higher priority first)
            ready.sort(key=lambda x: configs.get(x, ModuleConfig()).priority.value, reverse=True)
            
            resolved.extend(ready)
            remaining -= set(ready)
        
        return resolved


# Global registry instance
module_registry = ModuleRegistry()