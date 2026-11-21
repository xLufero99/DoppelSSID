from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import unicodedata
from itertools import islice


def _a_texto(salida: object) -> str:
    if isinstance(salida, (bytes, bytearray)):
        datos = bytes(salida)
        for codificacion in ("utf-8", "cp850", "cp437"):
            try:
                return datos.decode(codificacion)
            except UnicodeDecodeError:
                continue
        return datos.decode("cp437", errors="replace")
    return str(salida or "")


def _ejecutar(comando: list[str]) -> str:
    try:
        resultado = subprocess.run(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return _a_texto(resultado.stdout)


def _clave(valor: object) -> str:
    texto = unicodedata.normalize("NFKD", str(valor or ""))
    texto = texto.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", " ", texto).strip()


def _valor_ip(valor: object) -> str:
    texto = str(valor or "").replace("\xa0", " ")
    coincidencia = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", texto)
    return coincidencia.group(0) if coincidencia else ""


def _es_link_local(ip: str) -> bool:
    return ip.startswith("169.254.")


def _ip_windows() -> tuple[str, str] | None:
    texto = _ejecutar(["ipconfig"])
    if not texto:
        return None

    etiquetas_wifi = ("wi fi", "wireless", "inalambr", "wlan")
    es_wifi = False
    ip = ""
    mascara = ""

    for linea in texto.splitlines():
        original = linea.strip()
        if not original:
            continue
        clave = _clave(original)

        if original.endswith(":") and (
            "adaptador" in clave
            or "adapter" in clave
            or any(etiqueta in clave for etiqueta in etiquetas_wifi)
        ):
            es_wifi = any(etiqueta in clave for etiqueta in etiquetas_wifi)
            ip = ""
            mascara = ""
            continue

        if not es_wifi or ":" not in original:
            continue

        nombre, valor = original.split(":", 1)
        nombre = _clave(nombre)
        if any(etiqueta in nombre for etiqueta in ("direccion ipv4", "ipv4 address")):
            ip = _valor_ip(valor)
        elif any(etiqueta in nombre for etiqueta in ("mascara de subred", "subnet mask")):
            mascara = _valor_ip(valor)

        if ip and mascara:
            if _es_link_local(ip):
                es_wifi = False
                ip = ""
                mascara = ""
                continue
            return ip, mascara
    return None


def _mascara_desde_prefix(prefix: int) -> str:
    try:
        red = ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False)
    except ValueError:
        return "255.255.255.0"
    return str(red.netmask)


def _interfaz_default(rutas: str) -> str:
    for linea in rutas.splitlines():
        coincidencia = re.match(r"^default\s+via\s+\S+\s+dev\s+(\S+)", linea.strip())
        if coincidencia:
            return coincidencia.group(1).split("@")[0]
    return ""


def _ip_hostname() -> tuple[str, str] | None:
    texto = _ejecutar(["hostname", "-I"])
    for candidato in texto.split():
        ip = _valor_ip(candidato)
        if ip and ip != "127.0.0.1" and not _es_link_local(ip):
            return ip, _mascara_desde_prefix(24)
    return None


def _ip_linux() -> tuple[str, str] | None:
    texto = _ejecutar(["ip", "-4", "addr", "show"])
    candidatos: list[tuple[str, str, int]] = []
    interfaz = ""

    for linea in texto.splitlines():
        cabecera = re.match(r"^\d+:\s+([^:]+):", linea)
        if cabecera:
            interfaz = cabecera.group(1).split("@")[0].strip()
            continue
        inet = re.search(
            r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b",
            linea,
        )
        if not inet or interfaz in ("", "lo"):
            continue
        ip = inet.group(1)
        prefix = int(inet.group(2))
        if not _es_link_local(ip):
            candidatos.append((interfaz, ip, prefix))

    if candidatos:
        rutas = _ejecutar(["ip", "route"])
        default = _interfaz_default(rutas)
        elegido = next((c for c in candidatos if c[0] == default), candidatos[0])
        return elegido[1], _mascara_desde_prefix(elegido[2])
    return _ip_hostname()


def get_red_local() -> dict | None:
    sistema = platform.system()
    datos = _ip_windows() if sistema == "Windows" else _ip_linux()
    if not datos:
        return None

    ip, mascara = datos
    try:
        red = ipaddress.IPv4Network(f"{ip}/{mascara}", strict=False)
    except ValueError:
        return None

    limitado = red.prefixlen < 24
    if limitado:
        red = ipaddress.IPv4Network(f"{ip}/24", strict=False)

    rango = [str(host) for host in islice(red.hosts(), 254)]
    return {
        "ip_local": ip,
        "red": str(red),
        "rango": rango,
        "rango_limitado": limitado,
    }
