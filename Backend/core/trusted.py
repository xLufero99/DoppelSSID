from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

RUTA_CONFIABLES = (
    Path(__file__).resolve().parent.parent / "data" / "trusted_networks.json"
)


def _leer_crudo() -> list:
    try:
        with RUTA_CONFIABLES.open("r", encoding="utf-8") as archivo:
            datos = json.load(archivo)
    except (OSError, ValueError, UnicodeError):
        return []
    return datos if isinstance(datos, list) else []


def load_trusted() -> list[dict]:
    try:
        RUTA_CONFIABLES.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    perfiles: list[dict] = []
    for perfil in _leer_crudo():
        if not isinstance(perfil, dict):
            continue
        if not isinstance(perfil.get("ssid"), str):
            continue
        if not isinstance(perfil.get("bssids"), dict):
            continue
        perfiles.append(perfil)
    return perfiles


def save_trusted(lista: list[dict]) -> None:
    RUTA_CONFIABLES.parent.mkdir(parents=True, exist_ok=True)
    temporal: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=RUTA_CONFIABLES.parent,
            prefix=".trusted_",
            suffix=".tmp",
            delete=False,
        ) as archivo:
            temporal = Path(archivo.name)
            json.dump(lista, archivo, ensure_ascii=False, indent=2)
            archivo.flush()
            os.fsync(archivo.fileno())
        os.replace(temporal, RUTA_CONFIABLES)
    except Exception:
        if temporal is not None:
            try:
                temporal.unlink()
            except OSError:
                pass
        raise


def trust_ssid(ssid: str, redes: list[dict]) -> None:
    if not ssid or ssid == "<oculta>":
        return

    coincidentes = [
        red for red in redes if str(red.get("ssid") or "").strip() == ssid
    ]
    if not coincidentes:
        return

    bssids: dict[str, dict] = {}
    for red in coincidentes:
        bssid = str(red.get("bssid") or "").strip().upper()
        if not bssid:
            continue
        bssids[bssid] = {
            "canal": int(red.get("canal") or 0),
            "banda": str(red.get("banda") or ""),
            "senal": int(red.get("senal") or 0),
        }

    if not bssids:
        return

    perfiles = [
        perfil for perfil in load_trusted() if perfil.get("ssid") != ssid
    ]
    primera = coincidentes[0]
    perfiles.append(
        {
            "ssid": ssid,
            "autenticacion": str(primera.get("autenticacion") or "").strip(),
            "cifrado": str(primera.get("cifrado") or "").strip(),
            "bssids": bssids,
        }
    )
    save_trusted(perfiles)


def untrust_ssid(ssid: str) -> None:
    if not ssid or ssid == "<oculta>":
        return
    perfiles = [perfil for perfil in load_trusted() if perfil.get("ssid") != ssid]
    save_trusted(perfiles)


def get_profile(ssid: str) -> dict | None:
    if not ssid or ssid == "<oculta>":
        return None
    for perfil in load_trusted():
        if perfil.get("ssid") == ssid:
            return perfil
    return None
