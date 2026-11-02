"""Base class for tiered SOC agents."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(name)s] %(levelname)s: %(message)s")


class SOCAgent(ABC):
    """Abstract base class for autonomous SOC agents."""

    def __init__(self, name: str, tier: int, role: str) -> None:
        self.name = name
        self.tier = tier
        self.role = role
        self.logger = logging.getLogger(self.name)

    @abstractmethod
    def process(self, *args: Any, **kwargs: Any) -> Any:
        """Core analytical execution turn."""
        pass
