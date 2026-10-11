"""Importing the modules below registers every check."""
from . import (cookies, cors, disclosure, exposed_files, headers, open_redirect,  # noqa: F401
               reflection, sqli_errors, tls, transport)
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
