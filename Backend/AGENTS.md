# DoppelSSID (Backend)

Aplicación local en Python que detecta redes WiFi falsas (Evil Twin),
lista dispositivos de la red local y estima el consumo por dispositivo.
Proyecto académico de Fundamentos de Redes. Enfoque DEFENSIVO únicamente.

## Reglas
- Todo corre en local. Sin servicios en la nube.
- `core/` no importa nada de `cli/` ni `server/` (solo lógica, sin UI).
- Sin modo monitor: el escaneo usa comandos del SO (netsh / nmcli).
- Sin ML ni SDN.
- Sin funciones ofensivas (no deauth, no crear APs falsos). ARP spoofing solo en Fase 4, con consentimiento explícito del usuario y únicamente en redes propias o administradas por el usuario.
- Soporte: Windows y Linux. macOS opcional.
- Stack: Python, Scapy (ARP), Flask o FastAPI, rich, PyInstaller.
- La app no debe caerse si no hay red ni internet.
- Windows en español: la salida de netsh viene en cp850 y con etiquetas
  en español; soportar también inglés.
- No crear carpetas ni archivos fuera de la estructura de abajo.

## Estructura (este directorio es Backend/)
main.py        punto de entrada
core/          motor: wifi_scanner, classifier, arp_scanner, traffic, trusted, oui
cli/           menú con rich
server/        API local
data/          trusted_networks.json
tests/         pruebas con datos fijos
../Frontend/   HTML/CSS/JS (lo sirve server/, no tocar hasta la Fase 6)

## Fases (hacer UNA a la vez, probar antes de seguir)
1. Escaneo de redes WiFi, agrupar por SSID, ordenar por BSSID
2. Clasificador segura / precaución / riesgo
3. Escaneo ARP (IP, MAC, fabricante)
4. Conteo de tráfico
5. Servidor local con API JSON
6. Frontend web
7. Empaquetado con PyInstaller (y pywebview opcional)