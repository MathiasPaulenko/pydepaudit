"""Audit Python dependencies for CVEs, licenses, staleness and maintainer health."""

__version__ = "1.0.0"

from pydepaudit.audit import audit_project

__all__ = ["__version__", "audit_project"]
