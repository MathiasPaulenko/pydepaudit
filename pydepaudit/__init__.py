"""Audit Python dependencies for CVEs, licenses, staleness and maintainer health."""

__version__ = "0.1.0"

from pydepaudit.audit import audit_project

__all__ = ["__version__", "audit_project"]
