"""Importing the modules below registers every check."""
from . import cookies, cors, disclosure, exposed_files, headers, tls, transport  # noqa: F401
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
