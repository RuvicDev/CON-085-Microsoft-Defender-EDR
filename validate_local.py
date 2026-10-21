"""Validación local del conector defender_edr (solo lectura por defecto).

Uso:
    python validate_local.py

Requiere RUVIC_DEFENDER_EDR_TENANT_ID, RUVIC_DEFENDER_EDR_CLIENT_ID y
RUVIC_DEFENDER_EDR_CLIENT_SECRET exportadas.
"""

from ruvic_defender_edr_connector import DefenderEdrClient, setup_logging

setup_logging("INFO")
client = DefenderEdrClient()

print("== 0. Ping ==")
client.ping()

print("== 1. Alertas ==")
for a in client.list_alerts(limit=5):
    print(f"  {a['severity']} {a['title']} {a['device_name']}")

print("== 2. Dispositivos ==")
equipos = client.list_devices(limit=5)
for d in equipos:
    print(f"  {d['id']} {d['name']} {d['health_status']}")

print("== 3. Vulnerabilidades críticas de la organización ==")
for v in client.get_vulnerabilities(severity="Critical", limit=5):
    print(f"  {v['id']} cvss={v['cvss']} equipos={v['exposed_devices']}")

# == 4. Aislar y liberar (ESCRIBE): solo con un equipo de PRUEBAS ==
# EQUIPO_PRUEBA = "<id de 40 caracteres>"
# print(client.isolate_device(EQUIPO_PRUEBA, "Prueba Ruvic QA"))
# print(client.release_device(EQUIPO_PRUEBA, "Fin prueba Ruvic QA"))

print("\nTodo OK.")
