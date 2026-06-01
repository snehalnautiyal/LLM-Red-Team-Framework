"""
probes/__init__.py — Master list of all probes.

To add a new probe: create it in the right category file and add it here.
The engine never needs to change — it just iterates this list.
"""
from .injection import INJECTION_PROBES
from .jailbreak import JAILBREAK_PROBES
from .leakage import LEAKAGE_PROBES
from .data import DATA_PROBES

ALL_PROBES = INJECTION_PROBES + JAILBREAK_PROBES + LEAKAGE_PROBES + DATA_PROBES

CATEGORY_MAP = {
    "prompt_injection": INJECTION_PROBES,
    "jailbreak": JAILBREAK_PROBES,
    "system_prompt_leakage": LEAKAGE_PROBES,
    "data_leakage": DATA_PROBES,
}


def get_probes(categories: list[str] | None = None):
    """Return probes for the given categories, or all probes if None."""
    if not categories:
        return ALL_PROBES
    result = []
    for cat in categories:
        result.extend(CATEGORY_MAP.get(cat, []))
    return result
