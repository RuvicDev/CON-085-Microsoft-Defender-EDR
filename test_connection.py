"""Prueba de conexión estándar del conector defender_edr.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_DEFENDER_EDR_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Obtiene un token y lista un dispositivo de Defender con las env vars RUVIC_DEFENDER_EDR_*."""
    try:
        from ruvic_defender_edr_connector import (
            DefenderEdrAuthError,
            DefenderEdrClient,
            DefenderEdrDataError,
            DefenderEdrNetworkError,
        )
    except ImportError:
        return (
            False,
            (
                "La librería ruvic-defender-edr-connector no está instalada. "
                "Instala con: pip install git+https://github.com/RuvicDev/"
                "CON-085-Microsoft-Defender-EDR.git#subdirectory=lib"
            ),
        )

    try:
        client = DefenderEdrClient()  # valida que existan las env vars
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except DefenderEdrAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except DefenderEdrNetworkError as exc:
        return False, f"Error de red: {exc}"
    except DefenderEdrDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # noqa: BLE001 - red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return True, "Conexión exitosa a Microsoft Defender for Endpoint"


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
