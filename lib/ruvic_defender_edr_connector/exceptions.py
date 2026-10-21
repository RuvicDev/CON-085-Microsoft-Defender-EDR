"""Excepciones propias del conector Microsoft Defender for Endpoint (EDR).

Separan los tres tipos de fallo que el usuario debe distinguir:
autenticación, red/servidor y datos. Nunca exponemos excepciones
crípticas del cliente HTTP subyacente.
"""


class DefenderEdrConnectorError(Exception):
    """Error base del conector."""


class DefenderEdrAuthError(DefenderEdrConnectorError):
    """Credenciales inválidas o permisos insuficientes."""


class DefenderEdrNetworkError(DefenderEdrConnectorError):
    """No se pudo alcanzar el servicio (red, timeout o error del servidor)."""


class DefenderEdrDataError(DefenderEdrConnectorError):
    """La operación es válida pero los datos o parámetros no lo son."""
