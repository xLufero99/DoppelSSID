from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import unicodedata
from concurrent.futures import ThreadPoolExecutor

from core.oui import fabricante_de
from core.red_local import get_red_local


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


def _normalizar_mac(valor: object) -> str:
    partes = re.split(r"[-:]", str(valor or "").strip())
    if len(partes) != 6:
        return ""
    try:
        return ":".join(f"{int(parte, 16):02X}" for parte in partes)
    except ValueError:
        return ""


def _es_descartable(mac: str) -> bool:
    try:
        primer_octeto = int(mac.split(":")[0], 16)
    except (IndexError, ValueError):
        return True
    return bool(primer_octeto & 0x01)


def ping_subred(rango, timeout_ms=400, paralelo=40) -> None:
    ips = [str(ip) for ip in (rango or [])]
    if not ips:
        return

    sistema = platform.system()
    segundos = max(0.001, float(timeout_ms) / 1000)

    def comando(ip: str) -> list[str]:
        if sistema == "Windows":
            return ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
        return ["ping", "-c", "1", "-W", f"{segundos:g}", ip]

    def ping(ip: str) -> None:
        try:
            subprocess.run(
                comando(ip),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=segundos + 1,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return None

    with ThreadPoolExecutor(max_workers=max(1, int(paralelo))) as executor:
        list(executor.map(ping, ips))


def _parsear_windows(texto: str) -> list[dict]:
    resultados: list[dict] = []
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        clave = _clave(linea)
        if clave.startswith("interfaz") or clave.startswith("interface"):
            continue

        partes = linea.split()
        if len(partes) < 2:
            continue
        ip = partes[0]
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            continue
        mac = _normalizar_mac(partes[1])
        if not mac:
            continue

        tipo = _clave(" ".join(partes[2:]))
        if "static" in tipo or "estatic" in tipo:
            continue
        if tipo and "dynamic" not in tipo and "dinamic" not in tipo:
            continue
        resultados.append({"ip": ip, "mac": mac})
    return resultados


def _parsear_linux(texto: str) -> list[dict]:
    patron = re.compile(
        r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
        r"(?P<mac>[0-9A-Fa-f:.-]{17})"
    )
    resultados: list[dict] = []
    for linea in texto.splitlines():
        coincidencia = patron.search(linea)
        if not coincidencia:
            continue
        mac = _normalizar_mac(coincidencia.group("mac"))
        if not mac:
            continue
        resultados.append({"ip": coincidencia.group("ip"), "mac": mac})
    return resultados


def leer_arp() -> list[dict]:
    texto = _a_texto(_ejecutar(["arp", "-a"]))
    if not texto:
        return []
    if platform.system() == "Windows":
        return _parsear_windows(texto)
    return _parsear_linux(texto)


def scan_dispositivos(marcar_ip_local=True) -> list[dict]:
    red = get_red_local()
    if not red:
        return []

    rango = red.get("rango") or []
    ping_subred(rango)
    entradas = leer_arp()

    permitidas = set(rango)
    ip_local = str(red.get("ip_local") or "")
    vistos: dict[tuple[str, str], dict] = {}

    for entrada in entradas:
        ip = str(entrada.get("ip") or "").strip()
        mac = _normalizar_mac(entrada.get("mac"))
        if ip not in permitidas or not mac or _es_descartable(mac):
            continue
        clave = (ip, mac)
        if clave in vistos:
            continue
        vistos[clave] = {
            "ip": ip,
            "mac": mac,
            "fabricante": fabricante_de(mac),
            "es_este_equipo": bool(marcar_ip_local and ip == ip_local),
        }

    return sorted(vistos.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
