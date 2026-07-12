"""ffx-magic-re: public repository safety guard and sync preview."""

__version__ = "0.1.0"

__all__ = [
    "GuardPolicy",
    "Violation",
    "ViolationKind",
    "default_policy",
    "scan_tree",
    "format_violations",
]

_LAZY_NAMES = frozenset(__all__)


def __getattr__(name: str):
    if name in _LAZY_NAMES:
        from ffx_magic_re import guard

        return getattr(guard, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_NAMES)