"""OpenGxP: an open-source, single-kernel suite for regulated life-science operations.

One GxP kernel (users, append-only hash-chained audit trail, 21 CFR Part 11
electronic signatures, versioned records, declarative workflows) is shared by
five thin modules: LIMS, QMS, DMS, MES (electronic batch records) and CSV.
"""
from .core import GxP, GxPError, RecordType, Transition
from .modules import install

__all__ = ["GxP", "GxPError", "RecordType", "Transition", "install", "open_system"]


def open_system(path=":memory:"):
    """Return a kernel with every module registered."""
    system = GxP(path)
    install(system)
    return system
