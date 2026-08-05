"""DigiScope's self-registering intelligence modules."""

from __future__ import annotations

import importlib
from typing import List

from .base import REGISTRY, ModuleSpec, ScanContext

_MODULE_NAMES = (
    "domain",
    "ip",
    "email",
    "username",
    "phone",
    "person",
    "company",
    "url",
    "hash",
    "crypto",
    "web",
)
_loaded = False


def load_modules() -> None:
    global _loaded
    if _loaded:
        return
    for name in _MODULE_NAMES:
        importlib.import_module(f"{__name__}.{name}")
    _loaded = True


def specs() -> List[ModuleSpec]:
    load_modules()
    return list(REGISTRY.values())


__all__ = ["REGISTRY", "ModuleSpec", "ScanContext", "load_modules", "specs"]
