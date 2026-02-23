"""Inspection policy dataclass shared between security_engine and pattern modules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InspectionPolicy:
    """Pattern toggles used by the analyzer."""

    xss_enabled: bool = True
    sql_enabled: bool = True


DEFAULT_POLICY = InspectionPolicy()
