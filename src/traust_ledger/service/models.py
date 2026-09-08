"""REST-specific models — only used by FastAPI routes."""

from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str


class ErrorDetail(BaseModel):
    detail: str


class ResolveRequest(BaseModel):
    key: str
    decision: str  # "confirmed" | "rejected"
    note: str = ""
