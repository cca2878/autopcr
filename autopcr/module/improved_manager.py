# coding: utf-8
"""
Module management interface - demonstrates dependency injection and loose coupling
Improves the existing module system architecture
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Protocol
from dataclasses import dataclass
from enum import Enum

from ..config import get_module_config, ModuleConfig


class ModuleResult(Enum):
    """Module execution result status"""
    SUCCESS = "success"
    FAILURE = "failure"
    SKIP = "skip"
    RETRY = "retry"


@dataclass
class ModuleExecutionContext:
    """Context for module execution with dependency injection"""
    config: ModuleConfig
    client: Any  # PCR client interface
    database_service: Any  # Database service interface
    logger: Any  # Logger interface
    execution_id: str
    dry_run: bool = False


class ModuleInterface(Protocol):
    """Protocol for all modules - enables duck typing and loose coupling"""
    
    async def execute(self, context: ModuleExecutionContext) -> ModuleResult:
        """Execute the module with given context"""
        ...
    
    def get_name(self) -> str:
        """Get module name"""
        ...
    
    def get_dependencies(self) -> List[str]:
        """Get list of module dependencies"""
        ...


class BaseModule(ABC):
    """Base class for modules with common functionality"""
    
    def __init__(self, name: str):
        self._name = name
        self._dependencies: List[str] = []
    
    def get_name(self) -> str:
        return self._name
    
    def get_dependencies(self) -> List[str]:
        return self._dependencies.copy()
    
    def add_dependency(self, dependency: str) -> None:
        """Add a dependency to this module"""
        if dependency not in self._dependencies:
            self._dependencies.append(dependency)
    
    @abstractmethod
    async def execute(self, context: ModuleExecutionContext) -> ModuleResult:
        """Execute the module logic"""
        pass
    
    async def pre_execute(self, context: ModuleExecutionContext) -> bool:
        """Pre-execution hook - return False to skip execution"""
        return True
    
    async def post_execute(self, context: ModuleExecutionContext, result: ModuleResult) -> None:
        """Post-execution hook for cleanup"""
        pass


class ModuleRegistry:
    """Registry for modules with dependency resolution"""
    
    def __init__(self):
        self._modules: Dict[str, ModuleInterface] = {}
        self._execution_order: Optional[List[str]] = None
    
    def register(self, module: ModuleInterface) -> None:
        """Register a module"""
        self._modules[module.get_name()] = module
        self._execution_order = None  # Reset cached order
    
    def unregister(self, name: str) -> None:
        """Unregister a module"""
        if name in self._modules:
            del self._modules[name]
            self._execution_order = None
    
    def get_module(self, name: str) -> Optional[ModuleInterface]:
        """Get module by name"""
        return self._modules.get(name)
    
    def get_all_modules(self) -> Dict[str, ModuleInterface]:
        """Get all registered modules"""
        return self._modules.copy()
    
    def resolve_execution_order(self) -> List[str]:
        """Resolve module execution order based on dependencies"""
        if self._execution_order is not None:
            return self._execution_order
        
        # Simple topological sort
        visited = set()
        temp_visited = set()
        order = []
        
        def visit(name: str):
            if name in temp_visited:
                raise ValueError(f"Circular dependency detected involving {name}")
            if name in visited:
                return
            
            temp_visited.add(name)
            module = self._modules.get(name)
            if module:
                for dep in module.get_dependencies():
                    if dep in self._modules:
                        visit(dep)
            visited.add(name)
            temp_visited.remove(name)
            order.append(name)
        
        for name in self._modules:
            if name not in visited:
                visit(name)
        
        self._execution_order = order
        return order


class ImprovedModuleManager:
    """
    Improved module manager with dependency injection and better error handling
    Demonstrates loose coupling and separation of concerns
    """
    
    def __init__(self, 
                 config: Optional[ModuleConfig] = None,
                 registry: Optional[ModuleRegistry] = None):
        self._config = config or get_module_config()
        self._registry = registry or ModuleRegistry()
        self._execution_stats: Dict[str, Dict[str, Any]] = {}
    
    def register_module(self, module: ModuleInterface) -> None:
        """Register a module for execution"""
        self._registry.register(module)
    
    async def execute_modules(self, 
                            context_factory: callable,
                            module_filter: Optional[List[str]] = None) -> Dict[str, ModuleResult]:
        """
        Execute modules with dependency injection
        
        Args:
            context_factory: Factory function to create execution context
            module_filter: Optional list of modules to execute (None = all)
            
        Returns:
            Dictionary of module name -> execution result
        """
        results: Dict[str, ModuleResult] = {}
        
        # Get execution order
        try:
            execution_order = self._registry.resolve_execution_order()
        except ValueError as e:
            # Handle circular dependency
            raise RuntimeError(f"Cannot execute modules: {e}")
        
        # Filter modules if specified
        if module_filter:
            execution_order = [name for name in execution_order if name in module_filter]
        
        # Execute modules in dependency order
        for module_name in execution_order:
            module = self._registry.get_module(module_name)
            if not module:
                continue
            
            try:
                # Create execution context
                context = context_factory()
                
                # Pre-execution check
                if hasattr(module, 'pre_execute'):
                    should_execute = await module.pre_execute(context)
                    if not should_execute:
                        results[module_name] = ModuleResult.SKIP
                        continue
                
                # Execute with retry logic
                result = await self._execute_with_retry(module, context)
                results[module_name] = result
                
                # Post-execution hook
                if hasattr(module, 'post_execute'):
                    await module.post_execute(context, result)
                    
            except Exception as e:
                # Log error and continue with next module
                results[module_name] = ModuleResult.FAILURE
                if hasattr(context, 'logger'):
                    context.logger.error(f"Module {module_name} failed: {e}")
        
        return results
    
    async def _execute_with_retry(self, 
                                module: ModuleInterface, 
                                context: ModuleExecutionContext) -> ModuleResult:
        """Execute module with retry logic"""
        last_exception = None
        
        for attempt in range(self._config.max_retries + 1):
            try:
                return await module.execute(context)
            except Exception as e:
                last_exception = e
                if attempt < self._config.max_retries:
                    # Wait before retry (could use exponential backoff)
                    import asyncio
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                else:
                    break
        
        # All retries failed
        return ModuleResult.FAILURE
    
    def get_execution_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get execution statistics"""
        return self._execution_stats.copy()


# Example improved module implementation
class DailyQuestModule(BaseModule):
    """Example of improved module using dependency injection"""
    
    def __init__(self):
        super().__init__("daily_quest")
        self.add_dependency("login")  # Depends on login module
    
    async def execute(self, context: ModuleExecutionContext) -> ModuleResult:
        """Execute daily quest logic with injected dependencies"""
        try:
            # Use injected client instead of global state
            client = context.client
            db_service = context.database_service
            
            # Example logic with proper error handling
            if context.dry_run:
                context.logger.info("Dry run: Would execute daily quests")
                return ModuleResult.SUCCESS
            
            # Use database service instead of direct model access
            quest_data = db_service.get_quest_data(quest_id=1001)
            if not quest_data:
                return ModuleResult.SKIP
            
            # Execute quest logic...
            context.logger.info("Daily quests completed successfully")
            return ModuleResult.SUCCESS
            
        except Exception as e:
            context.logger.error(f"Daily quest execution failed: {e}")
            return ModuleResult.FAILURE


__all__ = [
    'ModuleInterface', 'BaseModule', 'ModuleRegistry', 'ImprovedModuleManager',
    'ModuleResult', 'ModuleExecutionContext', 'DailyQuestModule'
]