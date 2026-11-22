from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from core.arp_scanner import scan_dispositivos
from server.cache import cache_por_nombre

bp = Blueprint("dispositivos", __name__, url_prefix="/api")


@bp.get("/dispositivos")
def listar_dispositivos():
    # scan_dispositivos() hace ping a toda la subred y lee la tabla ARP;
    # suele tardar varios segundos, por eso su caché es más larga que la de WiFi.
    ttl = float(current_app.config["CACHE_DISPOSITIVOS_SEGUNDOS"])
    return jsonify(cache_por_nombre("dispositivos").obtener(ttl, scan_dispositivos))
