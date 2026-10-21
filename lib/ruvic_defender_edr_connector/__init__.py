"""Gestión de endpoints protegidos con Microsoft Defender for Endpoint: consultar alertas, listar dispositivos, aislar/liberar dispositivos y obtener vulnerabilidades"""

from .client import DefenderEdrClient
from .config import ENV_PREFIX, DefenderEdrConfig
from .exceptions import (
    DefenderEdrAuthError,
    DefenderEdrConnectorError,
    DefenderEdrDataError,
    DefenderEdrNetworkError,
)
from .logging_utils import setup_logging

__all__ = [
    "DefenderEdrAuthError",
    "DefenderEdrClient",
    "DefenderEdrConfig",
    "DefenderEdrConnectorError",
    "DefenderEdrDataError",
    "DefenderEdrNetworkError",
    "ENV_PREFIX",
    "setup_logging",
]

__version__ = "1.0.0"
