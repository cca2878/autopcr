# coding: utf-8
"""
Database service layer - provides high-level interface to reduce coupling
Demonstrates dependency injection and factory patterns for better architecture
"""

from typing import Dict, Any, Optional, List, Type
from sqlalchemy.orm import Session
from abc import ABC, abstractmethod

class DatabaseServiceInterface(ABC):
    """Interface for database operations - enables dependency injection"""
    
    @abstractmethod
    def get_unit_data(self, unit_id: int) -> Optional[Dict[str, Any]]:
        """Get unit data by ID"""
        pass
    
    @abstractmethod 
    def get_quest_data(self, quest_id: int) -> Optional[Dict[str, Any]]:
        """Get quest data by ID"""
        pass
    
    @abstractmethod
    def get_equipment_data(self, equipment_id: int) -> Optional[Dict[str, Any]]:
        """Get equipment data by ID"""
        pass


class ModelFactory:
    """Factory pattern for creating model instances - reduces coupling"""
    
    _model_registry: Dict[str, Type] = {}
    
    @classmethod
    def register_model(cls, name: str, model_class: Type):
        """Register a model class with the factory"""
        cls._model_registry[name] = model_class
    
    @classmethod
    def create_model(cls, name: str, **kwargs):
        """Create model instance using factory pattern"""
        if name not in cls._model_registry:
            raise ValueError(f"Model '{name}' not registered")
        return cls._model_registry[name](**kwargs)
    
    @classmethod
    def get_registered_models(cls) -> List[str]:
        """Get list of registered model names"""
        return list(cls._model_registry.keys())


class DatabaseService(DatabaseServiceInterface):
    """Concrete implementation of database service"""
    
    def __init__(self, session_factory, model_factory: ModelFactory = None):
        self._session_factory = session_factory
        self._model_factory = model_factory or ModelFactory()
    
    def get_unit_data(self, unit_id: int) -> Optional[Dict[str, Any]]:
        """Get unit data with reduced coupling to specific model classes"""
        try:
            # Using lazy imports to reduce coupling
            from .models import UnitDatum
            
            with self._session_factory() as session:
                unit = session.query(UnitDatum).filter(UnitDatum.unit_id == unit_id).first()
                if unit:
                    return {
                        'unit_id': unit.unit_id,
                        'unit_name': unit.unit_name,
                        'kana': unit.kana,
                        'prefab_id': unit.prefab_id
                    }
                return None
        except ImportError:
            # Fallback if models not available
            return None
    
    def get_quest_data(self, quest_id: int) -> Optional[Dict[str, Any]]:
        """Get quest data with error handling"""
        try:
            from .models import QuestDatum
            
            with self._session_factory() as session:
                quest = session.query(QuestDatum).filter(QuestDatum.quest_id == quest_id).first()
                if quest:
                    return {
                        'quest_id': quest.quest_id,
                        'quest_name': quest.quest_name,
                        'area_id': quest.area_id
                    }
                return None
        except (ImportError, AttributeError):
            return None
    
    def get_equipment_data(self, equipment_id: int) -> Optional[Dict[str, Any]]:
        """Get equipment data with error handling"""
        try:
            from .models import EquipmentDatum
            
            with self._session_factory() as session:
                equipment = session.query(EquipmentDatum).filter(
                    EquipmentDatum.equipment_id == equipment_id
                ).first()
                if equipment:
                    return {
                        'equipment_id': equipment.equipment_id,
                        'equipment_name': equipment.equipment_name,
                        'description': equipment.description
                    }
                return None
        except (ImportError, AttributeError):
            return None


# Singleton instance for global access (can be replaced with DI container)
_service_instance: Optional[DatabaseService] = None

def get_database_service() -> DatabaseService:
    """Get database service instance (simple service locator pattern)"""
    global _service_instance
    if _service_instance is None:
        # In real implementation, would use proper DI container
        raise RuntimeError("Database service not initialized. Call set_database_service() first.")
    return _service_instance

def set_database_service(service: DatabaseService):
    """Set the database service instance"""
    global _service_instance
    _service_instance = service

__all__ = [
    'DatabaseServiceInterface', 'DatabaseService', 'ModelFactory',
    'get_database_service', 'set_database_service'
]