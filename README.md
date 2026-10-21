# Conector Microsoft Defender for Endpoint (EDR) (CON-085)

Conector Ruvic para Microsoft Defender for Endpoint: alertas, dispositivos, aislamiento/liberación de equipos y vulnerabilidades. Complementa al CON-045 añadiendo vulnerabilidades y la liberación de equipos aislados.

## Instalación

```bash
pip install git+https://github.com/RuvicDev/CON-085-Microsoft-Defender-EDR.git#subdirectory=lib
```

Python 3.10+. Dependencias: `requests>=2.31,<3.0`.

## Permisos requeridos

Autenticación OAuth2 **client_credentials** con una aplicación de Microsoft Entra ID
(scope `https://api.securitycenter.microsoft.com/.default`).

1. **Microsoft Entra ID → Registros de aplicaciones → Nuevo registro** (ej. "Ruvic Defender").
2. **Permisos de API → Agregar → API que usa mi organización → WindowsDefenderATP → Permisos de aplicación**:
   `Alert.Read.All`, `Machine.Read.All`, `Machine.Isolate`, `Vulnerability.Read.All`.
3. **Conceder consentimiento de administrador**.
4. **Certificados y secretos → Nuevo secreto de cliente**; copia el **Valor** (no el "Id. de secreto").

`Machine.Isolate` permite aislar equipos reales: omítelo si el conector debe ser solo de lectura.

## Variables de entorno (`RUVIC_DEFENDER_EDR_*`)

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_DEFENDER_EDR_TENANT_ID` | Sí | Tenant ID (Directory ID) |
| `RUVIC_DEFENDER_EDR_CLIENT_ID` | Sí | Client ID (Application ID) |
| `RUVIC_DEFENDER_EDR_CLIENT_SECRET` | Sí | Client Secret |
| `RUVIC_DEFENDER_EDR_API_BASE_URL` | No (default `https://api.securitycenter.microsoft.com`) | URL base de la API |
| `RUVIC_DEFENDER_EDR_CONNECT_TIMEOUT` | No (default `30`) | Timeout de conexión (segundos) |

Los campos opcionales vacíos usan su valor por defecto (la plataforma envía
`""` cuando un campo queda en blanco).

## Pruebas locales

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib

export RUVIC_DEFENDER_EDR_TENANT_ID=...
export RUVIC_DEFENDER_EDR_CLIENT_ID=...
export RUVIC_DEFENDER_EDR_CLIENT_SECRET=...

python test_connection.py
python validate_local.py
```

`validate_local.py` lista alertas, dispositivos y vulnerabilidades. El aislamiento está comentado: úsalo solo con un equipo de pruebas.

## Notas de integración

- El token se cachea hasta 60 s antes de vencer.
- `api_base_url` admite endpoints regionales (ej. `https://us.api.security.microsoft.com`).
- `isolate_device` y `release_device` exigen un `comment` no vacío y un ID de máquina de 40 caracteres hexadecimales.
- Los errores 403 indican permisos de aplicación faltantes o sin consentimiento de administrador.
- Límite de la API: 100 llamadas por minuto y 1500 por hora en las acciones de máquina.

## Limitaciones conocidas

- No resuelve ni asigna alertas, ni ejecuta escaneos antivirus o Live Response.
- `get_vulnerabilities` sin `device_id` y con `severity` filtra sobre las primeras 1000 vulnerabilidades.
- Los equipos detrás de una VPN de túnel completo pueden perder la conexión con Defender al aislarse.
