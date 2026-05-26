"""
Component registration mechanism.

Provides a metaclass and a factory for automatic component registration and creation.
"""
import logging
from abc import ABCMeta
from typing import Any, Dict, List, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ComponentRegistryMeta(ABCMeta):
    """
    A metaclass for component registration.

    It automatically registers non-abstract subclasses into a registry.
    Each registry class (e.g., DataSourceRegistry) maintains its own component registry,
    and all components inheriting from it share the same registry.
    """
    
    def __new__(mcs, name: str, bases: tuple, namespace: dict, **kwargs: Any):
        cls = super().__new__(mcs, name, bases, namespace, **kwargs)
        
        if not hasattr(cls, '_registry') or cls._registry is None:
            cls._registry = {}
        
        is_registry_base = namespace.get('_is_registry_base', False)
        
        if is_registry_base:
            logger.debug(
                "Registry base class defined: %s with registry id %s",
                name,
                id(cls._registry)
            )
            return cls
        
        if hasattr(cls, "__abstractmethods__") and len(getattr(cls, "__abstractmethods__")) > 0:
            logger.debug("Skipping abstract class: %s", name)
            return cls
        
        registry_cls = cls._find_registry_base()
        
        if registry_cls is not None and registry_cls is not cls:
            component_type = namespace.get("COMPONENT_NAME", name.lower())
            registry_cls._registry[component_type] = cls
            logger.debug(
                "Registered %s as component '%s' in registry %s (id: %s)",
                name,
                component_type,
                registry_cls.__name__,
                id(registry_cls._registry)
            )
        else:
            logger.debug(
                "Class %s has no registry base, skipping registration",
                name
            )
        
        return cls
    
    def _find_registry_base(cls) -> Optional[Type]:
        """Find the registry base class in the MRO."""
        for base in cls.__mro__[1:]:
            if hasattr(base, '_is_registry_base') and base._is_registry_base:
                return base
        return None

    def get_component(cls, name: str) -> Optional[Type]:
        """Get a component class by name from the registry."""
        return cls._registry.get(name)

    def list_components(cls) -> List[str]:
        """List all registered component names."""
        return list(cls._registry.keys())

    def is_registered(cls, name: str) -> bool:
        """Check if a component is registered."""
        return name in cls._registry


def create_registry_class(name: str) -> Type[ComponentRegistryMeta]:
    """
    Factory function to create a registry class.
    
    Each registry class has its own _registry dictionary that is shared
    among all components that inherit from it.
    
    Args:
        name: The name of the registry class
        
    Returns:
        A new registry class
    """
    return type(
        name,
        (object,),
        {
            '__metaclass__': ComponentRegistryMeta,
            '_registry': {},
            '_is_registry_base': True,
        }
    )


class DataSourceRegistry(metaclass=ComponentRegistryMeta):
    """Registry for data source components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class PreprocessorRegistry(metaclass=ComponentRegistryMeta):
    """Registry for preprocessor components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class DetectorRegistry(metaclass=ComponentRegistryMeta):
    """Registry for detector components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class ReporterRegistry(metaclass=ComponentRegistryMeta):
    """Registry for alert reporter components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class MetricExtractorRegistry(metaclass=ComponentRegistryMeta):
    """Registry for metric extractor components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class DataSinkRegistry(metaclass=ComponentRegistryMeta):
    """Registry for data sink components."""
    _registry: Dict[str, Type] = {}
    _is_registry_base = True


class ComponentFactory:
    """
    A generic factory for creating components from a registry.
    """
    
    def __init__(self, registry: Type[ComponentRegistryMeta]):
        self._registry = registry
        logger.debug(
            "ComponentFactory created for %s with registry id %s",
            registry.__name__,
            id(registry._registry)
        )

    def create(self, component_type: str, **kwargs: Any) -> Any:
        """
        Creates a component instance.

        Args:
            component_type: The type of the component to create.
            **kwargs: The arguments to pass to the component's constructor.

        Returns:
            A component instance.

        Raises:
            ValueError: If the component type is not registered.
        """
        component_cls = self._registry.get_component(component_type)
        if component_cls is None:
            available = ", ".join(self._registry.list_components())
            raise ValueError(
                f"Unknown component type: '{component_type}'. "
                f"Available types: [{available}]"
            )
        return component_cls(**kwargs)

    def list_available(self) -> List[str]:
        """List all available component types."""
        return self._registry.list_components()


__all__ = [
    "ComponentRegistryMeta",
    "ComponentFactory",
    "DataSourceRegistry",
    "PreprocessorRegistry",
    "DetectorRegistry",
    "ReporterRegistry",
    "MetricExtractorRegistry",
    "DataSinkRegistry",
    "create_registry_class",
]
