"""Cliente de Microsoft Defender for Endpoint (API de WindowsDefenderATP).

Capacidades:
- list_alerts():          consultar alertas.
- list_devices():         listar dispositivos (máquinas) incorporados.
- isolate_device():       aislar un dispositivo de la red.
- release_device():       liberar un dispositivo aislado.
- get_vulnerabilities():  obtener vulnerabilidades (de un dispositivo o de la organización).

Autenticación: OAuth2 client_credentials contra Microsoft Entra ID con el
scope https://api.securitycenter.microsoft.com/.default.

Las credenciales SIEMPRE provienen de variables de entorno RUVIC_DEFENDER_EDR_*
(ver config.DefenderEdrConfig.from_env). Prohibido hardcodearlas.
"""

from __future__ import annotations

import re
import time
from typing import Any

import requests

from .config import DefenderEdrConfig
from .exceptions import DefenderEdrAuthError, DefenderEdrDataError, DefenderEdrNetworkError
from .logging_utils import get_logger

_SCOPE = "https://api.securitycenter.microsoft.com/.default"
_SEVERITIES = {"Informational", "Low", "Medium", "High"}
_ALERT_STATUSES = {"New", "InProgress", "Resolved"}
_ISOLATION_TYPES = {"Full", "Selective"}
_DEVICE_ID_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _limit(value: Any, maximum: int = 1000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DefenderEdrDataError(f"limit debe ser un entero entre 1 y {maximum}.")
    return value


def _norm_choice(value: str | None, allowed: set[str], field: str) -> str | None:
    if value is None:
        return None
    lookup = {a.lower(): a for a in allowed}
    found = lookup.get(str(value).strip().lower())
    if not found:
        raise DefenderEdrDataError(f"{field} {value!r} inválido. Valores permitidos: {sorted(allowed)}")
    return found


def _device_id(value: Any) -> str:
    if not isinstance(value, str) or not _DEVICE_ID_RE.match(value.strip()):
        raise DefenderEdrDataError(
            "device_id debe ser el ID de máquina de Defender (40 caracteres hexadecimales); "
            "obténlo con list_devices()."
        )
    return value.strip()


class DefenderEdrClient:
    """Cliente de Microsoft Defender for Endpoint.

    Args:
        config: configuración. Si se omite, se lee de RUVIC_DEFENDER_EDR_*.

    Ejemplo:
        >>> client = DefenderEdrClient()
        >>> client.list_alerts(severity="High", limit=10)
        [{'id': 'da637...', 'title': 'Suspicious PowerShell', 'severity': 'High', ...}]
    """

    def __init__(self, config: DefenderEdrConfig | None = None) -> None:
        self.config = config or DefenderEdrConfig.from_env()
        self.api_url = (self.config.api_base_url or "https://api.securitycenter.microsoft.com").rstrip("/")
        self._logger = get_logger()
        self._session = requests.Session()
        self._token: str | None = None
        self._token_expiry = 0.0

    # ------------------------------------------------------------------ #
    # Conexión
    # ------------------------------------------------------------------ #

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        try:
            resp = self._session.post(url, data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": _SCOPE,
            }, timeout=self.config.connect_timeout)
        except requests.exceptions.RequestException as exc:
            raise DefenderEdrNetworkError(f"No se pudo alcanzar Microsoft Entra ID: {exc}") from exc
        if resp.status_code != 200:
            try:
                desc = resp.json().get("error_description", "")
            except ValueError:
                desc = resp.text
            raise DefenderEdrAuthError(
                "No se pudo obtener el token de Microsoft Entra ID: revisa Tenant ID, Client ID y "
                f"Client Secret (y que el secreto no haya vencido). Detalle: {desc.splitlines()[0][:200] if desc else resp.status_code}"
            )
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {"Authorization": f"Bearer {self._get_token()}", "Accept": "application/json"}
        try:
            resp = self._session.request(
                method, f"{self.api_url}{path}", headers=headers,
                timeout=self.config.connect_timeout, **kwargs,
            )
        except requests.exceptions.RequestException as exc:
            raise DefenderEdrNetworkError(f"No se pudo alcanzar la API de Defender: {exc}") from exc
        if resp.status_code == 401:
            raise DefenderEdrAuthError("Token rechazado por Defender: revisa la configuración de la aplicación.")
        if resp.status_code == 403:
            raise DefenderEdrAuthError(
                "Permiso insuficiente: la aplicación necesita permisos de 'WindowsDefenderATP' "
                "(Alert.Read.All, Machine.Read.All, Machine.Isolate, Vulnerability.Read.All) con "
                "consentimiento de administrador."
            )
        if resp.status_code == 404:
            raise DefenderEdrDataError("El dispositivo o recurso solicitado no existe en Defender.")
        if resp.status_code == 429:
            raise DefenderEdrNetworkError("Límite de peticiones de Defender alcanzado; reintenta en un minuto.")
        if resp.status_code >= 500:
            raise DefenderEdrNetworkError(f"Defender respondió {resp.status_code}; reintenta en unos segundos.")
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", {}).get("message", resp.text)
            except ValueError:
                msg = resp.text
            raise DefenderEdrDataError(f"Defender rechazó la petición ({resp.status_code}): {msg[:300]}")
        return resp.json() if resp.content else None

    def ping(self) -> bool:
        """Verifica credenciales y permisos listando un dispositivo.

        Raises:
            DefenderEdrAuthError / DefenderEdrNetworkError / DefenderEdrDataError.
        """
        self._request("GET", "/api/machines", params={"$top": 1})
        self._logger.info("Ping exitoso a Defender for Endpoint")
        return True

    # ------------------------------------------------------------------ #
    # Capacidad 1: alertas
    # ------------------------------------------------------------------ #

    def list_alerts(self, severity: str | None = None, status: str | None = None,
                    limit: int = 50) -> list[dict[str, Any]]:
        """Consulta alertas, de la más reciente a la más antigua.

        Args:
            severity: "Informational", "Low", "Medium" o "High" (opcional).
            status: "New", "InProgress" o "Resolved" (opcional).
            limit: máximo de alertas (1-1000).

        Returns:
            Lista de dicts: id, title, severity, status, category,
            device_id, device_name, created, detection_source.

        Ejemplo:
            >>> client.list_alerts(severity="High", status="New")
            [{'id': 'da637...', 'title': '...', 'severity': 'High', 'status': 'New', ...}]
        """
        limit = _limit(limit)
        filters = []
        if severity:
            filters.append(f"severity eq '{_norm_choice(severity, _SEVERITIES, 'severity')}'")
        if status:
            filters.append(f"status eq '{_norm_choice(status, _ALERT_STATUSES, 'status')}'")
        params: dict[str, Any] = {"$top": limit}
        if filters:
            params["$filter"] = " and ".join(filters)
        alerts = (self._request("GET", "/api/alerts", params=params) or {}).get("value", [])
        alerts.sort(key=lambda a: a.get("alertCreationTime") or "", reverse=True)
        self._logger.info("Alertas listadas: %d", len(alerts))
        return [{
            "id": a.get("id"),
            "title": a.get("title"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "category": a.get("category"),
            "device_id": a.get("machineId"),
            "device_name": a.get("computerDnsName"),
            "created": a.get("alertCreationTime"),
            "detection_source": a.get("detectionSource"),
        } for a in alerts]

    # ------------------------------------------------------------------ #
    # Capacidad 2: dispositivos
    # ------------------------------------------------------------------ #

    def list_devices(self, name_contains: str | None = None, health_status: str | None = None,
                     limit: int = 50) -> list[dict[str, Any]]:
        """Lista los dispositivos incorporados a Defender.

        Args:
            name_contains: filtra por texto en el nombre DNS (opcional).
            health_status: ej. "Active", "Inactive" (opcional).
            limit: máximo de dispositivos (1-1000).

        Returns:
            Lista de dicts: id, name, os, health_status, risk_score,
            exposure_level, last_seen, last_ip.

        Ejemplo:
            >>> client.list_devices(name_contains="laptop", limit=5)
            [{'id': '1e5b...', 'name': 'laptop-ventas-01', 'health_status': 'Active', ...}]
        """
        limit = _limit(limit)
        filters = []
        if name_contains:
            safe = str(name_contains).replace("'", "''")
            filters.append(f"startswith(computerDnsName,'{safe}')")
        if health_status:
            safe = str(health_status).replace("'", "''")
            filters.append(f"healthStatus eq '{safe}'")
        params: dict[str, Any] = {"$top": limit}
        if filters:
            params["$filter"] = " and ".join(filters)
        devices = (self._request("GET", "/api/machines", params=params) or {}).get("value", [])
        self._logger.info("Dispositivos listados: %d", len(devices))
        return [{
            "id": d.get("id"),
            "name": d.get("computerDnsName"),
            "os": f"{d.get('osPlatform', '')} {d.get('osVersion') or ''}".strip(),
            "health_status": d.get("healthStatus"),
            "risk_score": d.get("riskScore"),
            "exposure_level": d.get("exposureLevel"),
            "last_seen": d.get("lastSeen"),
            "last_ip": d.get("lastIpAddress"),
        } for d in devices]

    # ------------------------------------------------------------------ #
    # Capacidad 3: aislar / liberar
    # ------------------------------------------------------------------ #

    def isolate_device(self, device_id: str, comment: str, isolation_type: str = "Selective") -> dict[str, Any]:
        """Aísla un dispositivo de la red (acción real sobre el equipo).

        Args:
            device_id: ID de máquina de Defender (de list_devices).
            comment: motivo; queda en el registro de acciones de Defender.
            isolation_type: "Selective" (default; mantiene Outlook/Teams) o
                "Full" (corta todo salvo la conexión con Defender).

        Returns:
            Dict con action_id, type, status y device_id de la acción creada.

        Ejemplo:
            >>> client.isolate_device("1e5b...", "Malware detectado, ticket INC-123")
            {'action_id': '...', 'type': 'Isolate', 'status': 'Pending', ...}
        """
        device_id = _device_id(device_id)
        if not isinstance(comment, str) or not comment.strip():
            raise DefenderEdrDataError("comment es obligatorio: explica el motivo del aislamiento.")
        itype = _norm_choice(isolation_type, _ISOLATION_TYPES, "isolation_type")
        action = self._request("POST", f"/api/machines/{device_id}/isolate",
                               json={"Comment": comment.strip(), "IsolationType": itype})
        self._logger.info("Aislamiento %s solicitado para %s", itype, device_id)
        return self._action(action, device_id)

    def release_device(self, device_id: str, comment: str) -> dict[str, Any]:
        """Libera un dispositivo aislado (revierte isolate_device).

        Ejemplo:
            >>> client.release_device("1e5b...", "Equipo limpio, INC-123 cerrado")
            {'action_id': '...', 'type': 'Unisolate', 'status': 'Pending', ...}
        """
        device_id = _device_id(device_id)
        if not isinstance(comment, str) or not comment.strip():
            raise DefenderEdrDataError("comment es obligatorio: explica el motivo de la liberación.")
        action = self._request("POST", f"/api/machines/{device_id}/unisolate",
                               json={"Comment": comment.strip()})
        self._logger.info("Liberación solicitada para %s", device_id)
        return self._action(action, device_id)

    @staticmethod
    def _action(action: dict[str, Any] | None, device_id: str) -> dict[str, Any]:
        action = action or {}
        return {
            "action_id": action.get("id"),
            "type": action.get("type"),
            "status": action.get("status"),
            "device_id": action.get("machineId", device_id),
            "requested": action.get("creationDateTimeUtc"),
        }

    # ------------------------------------------------------------------ #
    # Capacidad 4: vulnerabilidades
    # ------------------------------------------------------------------ #

    def get_vulnerabilities(self, device_id: str | None = None, severity: str | None = None,
                            limit: int = 50) -> list[dict[str, Any]]:
        """Obtiene vulnerabilidades (CVE) de un dispositivo o de la organización.

        Args:
            device_id: si se indica, solo las del dispositivo; si no, el
                catálogo de vulnerabilidades expuestas en la organización.
            severity: "Low", "Medium", "High" o "Critical" (filtra en el resultado).
            limit: máximo de resultados (1-1000).

        Returns:
            Lista de dicts: id (CVE), name, severity, cvss, exploit_available,
            exposed_devices, published.

        Ejemplo:
            >>> client.get_vulnerabilities(device_id="1e5b...", severity="Critical")
            [{'id': 'CVE-2026-1234', 'severity': 'Critical', 'cvss': 9.8, ...}]
        """
        limit = _limit(limit)
        sev = _norm_choice(severity, {"Low", "Medium", "High", "Critical"}, "severity") if severity else None
        if device_id:
            path = f"/api/machines/{_device_id(device_id)}/vulnerabilities"
            params: dict[str, Any] = {}
        else:
            path = "/api/vulnerabilities"
            params = {"$top": limit if not sev else 1000}
        vulns = (self._request("GET", path, params=params) or {}).get("value", [])
        if sev:
            vulns = [v for v in vulns if str(v.get("severity", "")).lower() == sev.lower()]
        vulns = vulns[:limit]
        self._logger.info("Vulnerabilidades obtenidas: %d", len(vulns))
        return [{
            "id": v.get("id"),
            "name": v.get("name"),
            "severity": v.get("severity"),
            "cvss": v.get("cvssV3"),
            "exploit_available": v.get("publicExploit"),
            "exposed_devices": v.get("exposedMachines"),
            "published": v.get("publishedOn"),
        } for v in vulns]
