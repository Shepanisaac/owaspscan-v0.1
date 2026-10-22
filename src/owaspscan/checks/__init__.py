"""Importing the modules below registers every check."""
from . import (access_control, cache_control, components, cookies, cors, crlf_injection,  # noqa: F401
               csrf, directory_listing, disclosure, exposed_files, headers, http_methods,
               open_redirect, path_traversal, reflection, session, sqli_blind, sqli_errors,
               sri, ssrf, tls, transport)
from .base import REGISTRY, Check, ScanContext, register

__all__ = ["REGISTRY", "Check", "ScanContext", "register"]
