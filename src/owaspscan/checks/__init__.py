"""Importing the modules below registers every check."""
from . import cookies, disclosure, exposed_files, headers, transport  # noqa: F401
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
