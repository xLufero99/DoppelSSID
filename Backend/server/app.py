from __future__ import annotations

import atexit
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from server import rutas_confiables, rutas_dispositivos, rutas_redes, rutas_trafico
from server.cache import CacheConTTL


FRONTEND_DIR = Path(__file__).resolve().parents[2] / "Frontend"


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )
    app.config["CACHE_REDES_SEGUNDOS"] = 5
    app.config["CACHE_DISPOSITIVOS_SEGUNDOS"] = 15
    app.config["CORS_ORIGENES"] = []
    app.extensions["doppelssid_cache"] = {
        "redes": CacheConTTL(),
        "dispositivos": CacheConTTL(),
    }

    @app.get("/")
    def indice():
        return app.send_static_file("index.html")

    @app.errorhandler(HTTPException)
    def _error_http(error: HTTPException):
        return jsonify(error=error.description or error.name), error.code

    @app.errorhandler(Exception)
    def _error_interno(error: Exception):
        app.logger.exception("Error no controlado: %s", error)
        return jsonify(error="Error interno del servidor"), 500

    app.register_blueprint(rutas_redes.bp)
    app.register_blueprint(rutas_dispositivos.bp)
    app.register_blueprint(rutas_confiables.bp)
    app.register_blueprint(rutas_trafico.bp)

    @app.get("/api/salud")
    def salud():
        return jsonify(estado="ok")

    origenes = app.config.get("CORS_ORIGENES") or []
    if origenes:
        # Solo orígenes de la red local; nunca un comodín abierto a internet.
        CORS(app, resources={r"/api/*": {"origins": origenes}})

    return app


def ejecutar_servidor() -> None:
    from core.red_local import get_red_local

    app = create_app()
    red = get_red_local()
    ip_local = red.get("ip_local") if red else None
    destino = f"http://{ip_local}:5000" if ip_local else "http://<IP-LOCAL>:5000"
    print(
        f"Servidor disponible en http://localhost:5000 y {destino} "
        "(para el celular en la misma red)"
    )
    atexit.register(rutas_trafico.detener_monitoreo)
    try:
        app.run(
            host="0.0.0.0",
            port=5000,
            threaded=True,
            use_reloader=False,
            debug=False,
        )
    finally:
        rutas_trafico.detener_monitoreo()
