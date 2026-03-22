"""
Plugin Architecture for Mutators — OmniFuzz

Allows third-party mutators to be registered and discovered without
modifying the core codebase. Plugins can be:

  1. Python callables registered programmatically via @register_mutator
  2. Entry-point plugins discovered from installed packages
     (group: "omnifuzz.mutators")
  3. YAML-defined template mutators loaded from a directory

A plugin mutator must implement the MutatorProtocol:
    def mutate(self, text: str) -> str

Or be any callable: (str) -> str
"""
from __future__ import annotations

import importlib
import importlib.metadata
import logging
import os
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("omnifuzz.plugin")

MutatorFn = Callable[[str], str]

# Global registry: name → mutator callable
_REGISTRY: Dict[str, MutatorFn] = {}


# ---------------------------------------------------------------------------
# Registration API
# ---------------------------------------------------------------------------

def register_mutator(name: str, fn: Optional[MutatorFn] = None):
    """
    Register a mutator callable under a given name.

    Can be used as a decorator or called directly:

        @register_mutator("my_mutator")
        def my_mutator(text: str) -> str: ...

        # or
        register_mutator("my_mutator", my_fn)
    """
    if fn is not None:
        _REGISTRY[name] = fn
        logger.debug("Registered mutator: %s", name)
        return fn

    # Decorator mode
    def decorator(func: MutatorFn) -> MutatorFn:
        _REGISTRY[name] = func
        logger.debug("Registered mutator (decorator): %s", name)
        return func
    return decorator


def unregister_mutator(name: str) -> bool:
    """Remove a mutator from the registry. Returns True if it existed."""
    if name in _REGISTRY:
        del _REGISTRY[name]
        return True
    return False


def list_mutators() -> List[str]:
    """Return sorted list of all registered mutator names."""
    return sorted(_REGISTRY.keys())


def get_mutator(name: str) -> MutatorFn:
    """
    Retrieve a registered mutator by name.
    Raises KeyError if not found.
    """
    if name not in _REGISTRY:
        raise KeyError(f"Mutator '{name}' not found. Available: {list_mutators()}")
    return _REGISTRY[name]


def apply_mutator(name: str, text: str) -> str:
    """Apply a registered mutator to text by name."""
    return get_mutator(name)(text)


# ---------------------------------------------------------------------------
# Entry-point discovery
# ---------------------------------------------------------------------------

def load_entry_point_plugins(group: str = "omnifuzz.mutators") -> List[str]:
    """
    Discover and register mutators from installed packages.

    Packages advertise mutators via pyproject.toml entry points:
        [project.entry-points."omnifuzz.mutators"]
        my_mutator = "my_package.mutators:my_mutator_fn"

    Returns list of newly registered mutator names.
    """
    registered = []
    try:
        eps = importlib.metadata.entry_points(group=group)
    except Exception as exc:
        logger.warning("Entry point discovery failed: %s", exc)
        return registered

    for ep in eps:
        try:
            fn = ep.load()
            register_mutator(ep.name, fn)
            registered.append(ep.name)
            logger.info("Loaded entry-point mutator: %s from %s", ep.name, ep.value)
        except Exception as exc:
            logger.error("Failed to load entry point '%s': %s", ep.name, exc)

    return registered


# ---------------------------------------------------------------------------
# Module-path registration
# ---------------------------------------------------------------------------

def load_module_mutator(module_path: str, attr: str, name: Optional[str] = None) -> str:
    """
    Load a mutator from a dotted module path and attribute name.

    Example:
        load_module_mutator("mypackage.mutators", "CoolMutator")

    Args:
        module_path: Dotted import path, e.g. "mypackage.mutators"
        attr:        Attribute name on the module (class or function)
        name:        Registry name. Defaults to attr.

    Returns:
        The name under which the mutator was registered.
    """
    mod     = importlib.import_module(module_path)
    fn_or_cls = getattr(mod, attr)
    # Support classes with a .mutate() method
    if isinstance(fn_or_cls, type):
        instance = fn_or_cls()
        fn = instance.mutate
    else:
        fn = fn_or_cls
    reg_name = name or attr
    register_mutator(reg_name, fn)
    return reg_name


# ---------------------------------------------------------------------------
# Built-in mutators auto-registered on import
# ---------------------------------------------------------------------------

def _bootstrap_builtins() -> None:
    """Register the built-in OmniFuzz mutators under well-known names."""
    from omnifuzz.mutators import mutate_base64, mutate_flip, mutate_leetspeak
    from omnifuzz.cross_lingual_mutators import CrossLingualMutator

    _clm = CrossLingualMutator()

    builtins = {
        "base64":        mutate_base64,
        "flip":          mutate_flip,
        "leetspeak":     mutate_leetspeak,
        "cross_lingual": lambda text: _clm.generate_attack_chain(),
    }
    for name, fn in builtins.items():
        register_mutator(name, fn)
        logger.debug("Registered built-in mutator: %s", name)


_bootstrap_builtins()
