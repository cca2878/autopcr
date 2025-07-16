# Model module interface - controls what gets exported to avoid namespace pollution
# This helps break tight coupling between modules

# Core model classes needed by external modules
from .modelbase import Request, ResponseBase
from .error import ApiException, NetworkException

# Only expose the most commonly used enums to reduce coupling
from .enums import (
    eInventoryType, ePromotionLevel, ePartyType, eClanRole, 
    eMissionStatusType, eGachaType, eSystemId
)

# Essential data structures - limit to prevent over-coupling
from .common import (
    StatusParam, UnitParam, InventoryInfo, UnitData, 
    ArenaInfo, ClanInfo, QuestResult
)

# Note: Request and Response classes are imported dynamically 
# in models.py to break circular dependencies

__all__ = [
    # Base classes
    'Request', 'ResponseBase',
    # Exceptions
    'ApiException', 'NetworkException', 
    # Core enums
    'eInventoryType', 'ePromotionLevel', 'ePartyType', 'eClanRole',
    'eMissionStatusType', 'eGachaType', 'eSystemId',
    # Data structures  
    'StatusParam', 'UnitParam', 'InventoryInfo', 'UnitData',
    'ArenaInfo', 'ClanInfo', 'QuestResult'
]