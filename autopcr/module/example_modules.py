"""
Example modules demonstrating the new simplified module management system.

These examples show how the complex inheritance-based module system
can be replaced with simpler, more maintainable patterns.
"""
from typing import Dict, Any
import asyncio

from ..module.simple_module_mgr import (
    Module, ModuleResult, ModuleStatus, ModuleConfig, ModulePriority,
    module_registry, TaskExecutor, ExecutionContext
)


class DailyLoginModule(Module):
    """Example daily login module using new system."""
    
    module_name = "daily_login"
    
    async def execute(self, context: Dict[str, Any]) -> ModuleResult:
        """Execute daily login task."""
        try:
            # Simulate login logic
            account = context.get('account')
            if not account:
                return ModuleResult(
                    module_name=self.name,
                    status=ModuleStatus.FAILED,
                    message="No account provided",
                    error="Missing account context"
                )
            
            # Simulate API call
            await asyncio.sleep(0.1)  # Simulate network delay
            
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SUCCESS,
                message="Daily login completed",
                data={
                    'login_reward': 'coins_100',
                    'consecutive_days': 5
                }
            )
            
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.FAILED,
                message="Daily login failed",
                error=str(e)
            )
    
    async def pre_execute(self, context: Dict[str, Any]) -> bool:
        """Check if login is needed."""
        # Check if already logged in today
        last_login = context.get('last_login')
        if last_login:
            # Logic to check if login is needed
            pass
        return True


class ShopModule(Module):
    """Example shop module using new system."""
    
    module_name = "shop"
    
    async def execute(self, context: Dict[str, Any]) -> ModuleResult:
        """Execute shop tasks."""
        try:
            account = context.get('account')
            if not account:
                return ModuleResult(
                    module_name=self.name,
                    status=ModuleStatus.FAILED,
                    message="No account provided"
                )
            
            # Simulate shop operations
            await asyncio.sleep(0.2)
            
            purchases = []
            budget = context.get('shop_budget', 1000)
            
            # Simulate purchasing logic
            if budget >= 100:
                purchases.append({'item': 'health_potion', 'cost': 100})
            
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SUCCESS,
                message=f"Shop tasks completed, {len(purchases)} purchases made",
                data={
                    'purchases': purchases,
                    'remaining_budget': budget - sum(p['cost'] for p in purchases)
                }
            )
            
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.FAILED,
                message="Shop tasks failed",
                error=str(e)
            )


class CriticalUpdateModule(Module):
    """Example of a critical module that stops execution on failure."""
    
    module_name = "critical_update"
    
    def __init__(self, name: str, config: ModuleConfig = None):
        # Set high priority for critical module
        if config is None:
            config = ModuleConfig(
                priority=ModulePriority.CRITICAL,
                timeout=60,
                retry_count=3
            )
        super().__init__(name, config)
    
    async def execute(self, context: Dict[str, Any]) -> ModuleResult:
        """Execute critical update."""
        try:
            # Simulate critical operation
            await asyncio.sleep(0.3)
            
            # Simulate potential failure
            failure_chance = context.get('simulate_failure', False)
            if failure_chance:
                raise Exception("Critical operation failed")
            
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SUCCESS,
                message="Critical update completed successfully",
                data={'update_version': '1.2.3'}
            )
            
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.FAILED,
                message="Critical update failed",
                error=str(e)
            )


class DependentModule(Module):
    """Example module that depends on other modules."""
    
    module_name = "dependent_task"
    
    def __init__(self, name: str, config: ModuleConfig = None):
        if config is None:
            config = ModuleConfig(
                dependencies=["daily_login", "shop"],  # Depends on login and shop
                priority=ModulePriority.NORMAL
            )
        super().__init__(name, config)
    
    async def execute(self, context: Dict[str, Any]) -> ModuleResult:
        """Execute task that depends on other modules."""
        try:
            # Check if dependencies completed successfully
            execution_log = context.get('execution_log', [])
            
            login_success = any('daily_login' in log and 'success' in log.lower() 
                              for log in execution_log)
            shop_success = any('shop' in log and 'success' in log.lower() 
                             for log in execution_log)
            
            if not login_success:
                return ModuleResult(
                    module_name=self.name,
                    status=ModuleStatus.FAILED,
                    message="Cannot proceed without successful login"
                )
            
            if not shop_success:
                return ModuleResult(
                    module_name=self.name,
                    status=ModuleStatus.SKIPPED,
                    message="Skipping task due to shop failure"
                )
            
            # Perform dependent task
            await asyncio.sleep(0.1)
            
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SUCCESS,
                message="Dependent task completed",
                data={'dependent_result': 'processed_data'}
            )
            
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.FAILED,
                message="Dependent task failed",
                error=str(e)
            )


# Example usage function
async def run_example_task():
    """Demonstrate how to use the new module system."""
    
    # Register modules
    module_registry.register(DailyLoginModule)
    module_registry.register(ShopModule)
    module_registry.register(CriticalUpdateModule)
    module_registry.register(DependentModule)
    
    # Create task executor
    executor = TaskExecutor(module_registry)
    
    # Create execution context
    context = ExecutionContext({
        'account': {'id': 'test_account', 'name': 'Test User'},
        'shop_budget': 500,
        'simulate_failure': False  # Set to True to test failure handling
    })
    
    # Define modules to execute
    modules_to_run = [
        "daily_login",
        "shop", 
        "dependent_task",
        "critical_update"
    ]
    
    # Configure modules
    module_configs = {
        "daily_login": ModuleConfig(
            priority=ModulePriority.HIGH,
            timeout=30
        ),
        "shop": ModuleConfig(
            priority=ModulePriority.NORMAL,
            timeout=60
        ),
        "dependent_task": ModuleConfig(
            dependencies=["daily_login", "shop"]
        ),
        "critical_update": ModuleConfig(
            priority=ModulePriority.CRITICAL,
            timeout=120
        )
    }
    
    # Execute task
    result = await executor.execute_task(
        task_name="daily_routine",
        modules=modules_to_run,
        context=context,
        configs=module_configs
    )
    
    return result


# Function to demonstrate the improvements
def demonstrate_improvements():
    """Show the improvements over the old system."""
    
    print("=== New Module System Improvements ===")
    print()
    
    print("1. Simplified Module Definition:")
    print("   - No complex inheritance hierarchy")
    print("   - Clear execute() method contract") 
    print("   - Built-in error handling")
    print()
    
    print("2. Dependency Management:")
    print("   - Automatic dependency resolution")
    print("   - Clear dependency declaration")
    print("   - Circular dependency detection")
    print()
    
    print("3. Priority System:")
    print("   - Modules execute by priority")
    print("   - Critical modules can halt execution")
    print("   - Flexible scheduling")
    print()
    
    print("4. Better Error Handling:")
    print("   - Structured result objects")
    print("   - Execution time tracking")
    print("   - Detailed error reporting")
    print()
    
    print("5. Configuration Management:")
    print("   - Per-module configuration")
    print("   - Timeout and retry settings")
    print("   - Runtime parameter passing")
    print()
    
    available_modules = module_registry.get_available_modules()
    print(f"Available modules: {available_modules}")


if __name__ == "__main__":
    # This would run the example if executed directly
    demonstrate_improvements()
    
    # Async example would need to be run in an event loop
    # result = asyncio.run(run_example_task())
    # print(f"Task result: {result}")