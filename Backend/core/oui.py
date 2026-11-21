from __future__ import annotations

import csv
import re
from pathlib import Path

RUTA_OUI = Path(__file__).resolve().parent.parent / "data" / "oui_fabricantes.csv"
_FABRICANTES: dict[str, str] | None = None
_PREFIJO_OUI = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){2}")


def _normalizar_oui(mac: object) -> str:
    partes = re.split(r":|-", str(mac or "").strip().upper())
    if len(partes) < 3:
        return ""
    try:
        primero = int(partes[0], 16) & ~0x02
        return f"{primero:02X}:{int(partes[1], 16):02X}:{int(partes[2], 16):02X}"
    except ValueError:
        return ""


def _es_local(mac: object) -> bool:
    partes = re.split(r":|-", str(mac or "").strip())
    if not partes:
        return False
    try:
        return bool(int(partes[0], 16) & 0x02)
    except ValueError:
        return False


def _cargar_fabricantes() -> dict[str, str]:
    global _FABRICANTES
    if _FABRICANTES is not None:
        return _FABRICANTES

    fabricantes: dict[str, str] = {}
    try:
        with RUTA_OUI.open("r", encoding="utf-8", newline="") as archivo:
            for fila in csv.DictReader(archivo):
                prefijo = str(fila.get("prefijo") or "").strip().upper()
                nombre = str(fila.get("fabricante") or "").strip()
                if _PREFIJO_OUI.fullmatch(prefijo) and nombre:
                    fabricantes[prefijo] = nombre
    except (OSError, csv.Error):
        fabricantes = {}

    _FABRICANTES = fabricantes
    return _FABRICANTES


def fabricante_de(mac: str) -> str:
    if _es_local(mac):
        return "Desconocido (MAC aleatoria)"
    return _cargar_fabricantes().get(_normalizar_oui(mac), "Desconocido")
