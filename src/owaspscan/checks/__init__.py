"""Importing the modules below registers every check."""
from . import (access_control, components, cookies, cors, csrf, disclosure,  # noqa: F401
               exposed_files, headers, http_methods, open_redirect, reflection, session,
               sqli_errors, sri, ssrf, tls, transport)
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
