from __future__ import annotations

from flask import Blueprint, abort, jsonify, request

from core.trusted import load_trusted, trust_ssid, untrust_ssid
from core.wifi_scanner import scan_merged
from server.cache import cache_por_nombre

bp = Blueprint("confiables", __name__, url_prefix="/api")


@bp.get("/confiables")
def listar_confiables():
    return jsonify(load_trusted())


@bp.post("/confiables")
def agregar_confiable():
    datos = request.get_json(silent=True)
    ssid = datos.get("ssid") if isinstance(datos, dict) else None
    if not isinstance(ssid, str) or not ssid.strip():
        abort(400, description='Debes enviar un SSID válido: {"ssid": "..."}.')
    ssid = ssid.strip()
    if ssid == "<oculta>":
        abort(400, description="No se puede confiar en una red oculta.")

    redes = scan_merged(n=2)
    if not any(str(red.get("ssid") or "").strip() == ssid for red in redes):
        abort(400, description=f"No se encontró el SSID '{ssid}' en el escaneo actual.")

    trust_ssid(ssid, redes)
    cache_por_nombre("redes").invalidar()
    return jsonify(ok=True, ssid=ssid), 201


@bp.delete("/confiables/<path:ssid>")
def quitar_confiable(ssid: str):
    untrust_ssid(ssid)
    cache_por_nombre("redes").invalidar()
    return jsonify(ok=True, ssid=ssid)
