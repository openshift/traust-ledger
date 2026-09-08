"""Env-auto-loading config — REST service and CLI entrypoints only.

Extends ``ServiceConfig`` (a plain BaseModel) with pydantic-settings so that
``LAAS_*`` env vars are picked up automatically.  This module is behind the
``[service]`` optional extra; library consumers and SDK callers use
``ServiceConfig`` directly and never import this.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict

from traust_ledger.config import ServiceConfig


class ServiceSettings(ServiceConfig, BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LAAS_")
