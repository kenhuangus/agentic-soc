"""Pre-configured synthetic attack scenarios for validation and testing."""

from .attack_chains import generate_false_positive_scenario, generate_apt_attack_chain

__all__ = [
    "generate_false_positive_scenario",
    "generate_apt_attack_chain",
]
