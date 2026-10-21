---
name: defender-edr
description: >
  Usa la librería ruvic_defender_edr_connector para gestionar endpoints con
  Microsoft Defender for Endpoint - consultar alertas (list_alerts), listar
  dispositivos (list_devices), aislar o liberar un dispositivo de la red
  (isolate_device, release_device) y obtener vulnerabilidades
  (get_vulnerabilities). Úsala cuando el usuario pregunte por alertas EDR,
  equipos protegidos, aislamiento de un equipo o vulnerabilidades en
  Microsoft Defender.
triggers:
- defender
- microsoft defender
- defender for endpoint
- mde
- edr
- aislar equipo
- vulnerabilidades
---

# Conector Microsoft Defender for Endpoint (EDR) (ruvic_defender_edr_connector)

Librería Python para la API de Microsoft Defender for Endpoint (WindowsDefenderATP). Está **preinstalada en el runtime** cuando el
conector está configurado (si no, instálala con
`pip install git+https://github.com/RuvicDev/CON-085-Microsoft-Defender-EDR.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de
variables de entorno, disponibles cuando el conector `defender_edr` está
configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_DEFENDER_EDR_TENANT_ID` | Tenant ID (Directory ID) |
| `RUVIC_DEFENDER_EDR_CLIENT_ID` | Client ID (Application ID) |
| `RUVIC_DEFENDER_EDR_CLIENT_SECRET` | Client Secret |
| `RUVIC_DEFENDER_EDR_API_BASE_URL` | (opcional) URL base de la API, default https://api.securitycenter.microsoft.com |
| `RUVIC_DEFENDER_EDR_CONNECT_TIMEOUT` | (opcional) Timeout de conexión (segundos), default 30 |

Si estas variables NO existen, el conector no está configurado: no
generes código que lo use; indica al usuario que lo configure en
**Settings → Conectores**. El código generado **NUNCA** usa nombres con
segmento de alias (`_DEFAULT_INSTANCIA_`, `_PRODUCCION_`, etc.) salvo que
aparezcan en una sección autogenerada `## Variables en tu entorno` al final
de este skill.

## Aislar un equipo es una acción real e inmediata

`list_alerts`, `list_devices` y `get_vulnerabilities` son de solo lectura.
`isolate_device` **corta la red de un equipo real** (salvo la conexión con
Defender) y `release_device` lo revierte. Nunca aísles un equipo sin una
instrucción explícita del usuario, confirma el nombre del equipo con
`list_devices` antes, y escribe siempre un `comment` con el motivo.

## Conexión (siempre igual)

```python
from ruvic_defender_edr_connector import DefenderEdrClient

client = DefenderEdrClient()  # lee RUVIC_DEFENDER_EDR_* del entorno automáticamente
```

## Capacidad 1 — Consultar alertas

```python
alertas = client.list_alerts(severity="High", status="New", limit=20)
for a in alertas:
    print(a["created"], a["severity"], a["title"], a["device_name"])
```

Severidades: `Informational`, `Low`, `Medium`, `High`. Estados: `New`, `InProgress`, `Resolved`.

## Capacidad 2 — Listar dispositivos

```python
equipos = client.list_devices(name_contains="laptop-ventas", limit=10)
for d in equipos:
    print(d["id"], d["name"], d["health_status"], d["risk_score"])
```

## Capacidad 3 — Aislar y liberar un dispositivo

```python
accion = client.isolate_device(equipos[0]["id"], "Malware detectado, ticket INC-123")
print(accion["status"])   # Pending -> la acción se aplica en segundos
# Más tarde, cuando el equipo esté limpio:
client.release_device(equipos[0]["id"], "INC-123 cerrado")
```

`isolation_type="Selective"` (default) mantiene Outlook y Teams; `"Full"` corta todo.

## Capacidad 4 — Obtener vulnerabilidades

```python
del_equipo = client.get_vulnerabilities(device_id=equipos[0]["id"], severity="Critical")
de_la_org = client.get_vulnerabilities(severity="High", limit=20)
```

## Manejo de errores

```python
from ruvic_defender_edr_connector import (
    DefenderEdrAuthError, DefenderEdrDataError, DefenderEdrNetworkError,
)

try:
    client.list_alerts(severity="High")
except DefenderEdrAuthError as e:
    print(f"Credenciales o permisos: {e}")
except DefenderEdrNetworkError as e:
    print(f"No se pudo alcanzar el servicio: {e}")
except DefenderEdrDataError as e:
    print(f"Error de datos: {e}")
```

Muestra el mensaje de la excepción tal cual al usuario: indica qué corregir.

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_DEFENDER_EDR_*` (el constructor de `DefenderEdrClient` ya lo hace).
2. Nunca imprimas `RUVIC_DEFENDER_EDR_CLIENT_SECRET` en logs ni en la salida.
3. Antes de aislar, muestra al usuario el nombre y el ID del equipo y confirma que es el correcto.
4. Incluye en `comment` el motivo y el ticket: queda en el registro de acciones de Defender.
5. La API limita a 100 llamadas por minuto: evita bucles de consultas por equipo.
