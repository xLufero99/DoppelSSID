from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from core.classifier import classify
from core.trusted import load_trusted
from core.wifi_scanner import scan_merged
from server.cache import cache_por_nombre

bp = Blueprint("redes", __name__, url_prefix="/api")


def _clasificar() -> list[dict]:
    # scan_merged(n=2, pausa=2.0): dos llamadas a netsh/nmcli más una pausa de 2 s;
    # conviene esperar entre 3 y 10 s antes de considerar fallido el escaneo.
    redes = scan_merged(n=2)
    return classify(redes, load_trusted())


@bp.get("/redes")
def listar_redes():
    resultado = _clasificar()
    cache_por_nombre("redes").establecer(resultado)
    return jsonify(resultado)


@bp.get("/redes/estado")
def estado_redes():
    ttl = float(current_app.config["CACHE_REDES_SEGUNDOS"])
    return jsonify(cache_por_nombre("redes").obtener(ttl, _clasificar))
