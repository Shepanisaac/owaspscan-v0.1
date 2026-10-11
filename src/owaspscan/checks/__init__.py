"""Importing the modules below registers every check."""
from . import (access_control, cookies, cors, csrf, disclosure, exposed_files, headers,  # noqa: F401
               open_redirect, reflection, session, sqli_errors, tls, transport)
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
