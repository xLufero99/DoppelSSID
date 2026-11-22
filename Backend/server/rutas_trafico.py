from __future__ import annotations

import logging
import platform
import threading
from functools import wraps

from flask import Blueprint, abort, jsonify, request

from core.arp_scanner import scan_dispositivos
from core.entorno import es_administrador, npcap_instalado
from core.red_local import get_red_local
from core.trafico import (
    _gateway_ip,
    deshabilitar_ip_forwarding,
    monitorear,
    obtener_mac,
    restaurar_arp,
)

bp = Blueprint("trafico", __name__, url_prefix="/api")

MENSAJE_NO_ADMIN = (
    "Esta función necesita permisos de administrador. "
    "Cierra el programa y vuelve a abrirlo con 'Ejecutar como "
    "administrador' (Windows) o con sudo (Linux)."
)
MENSAJE_NO_NPCAP = (
    "No tienes Npcap instalado (necesario para ver el tráfico "
    "de otros dispositivos). Sin él, solo puedes ver el consumo de tu "
    "propio equipo."
)
MENSAJE_SIN_RED = "No estás conectado a ninguna red WiFi. Conéctate para ver el tráfico."
MENSAJE_SIN_DISPOSITIVOS = "No se detectaron dispositivos. Intenta de nuevo en unos segundos."
MENSAJE_SIN_ROUTER = "No se pudo identificar el router de la red."
MENSAJE_YA_ACTIVO = "Ya hay un monitoreo de tráfico activo."
MENSAJE_NO_ACTIVO = "No hay monitoreo de tráfico activo."


class _SolicitudDetencion(Exception):
    pass


class _EstadoMonitoreo:
    def __init__(self) -> None:
        self.bloqueo = threading.Lock()
        self.evento = threading.Event()
        self.hilo: threading.Thread | None = None
        self.resultados: list[dict] = []
        self.dispositivos: list[dict] = []
        self.router_ip = ""
        self.router_mac = ""
        self.activo = False


_estado = _EstadoMonitoreo()


def solo_localhost(view):
    @wraps(view)
    def envuelta(*args, **kwargs):
        if request.remote_addr not in ("127.0.0.1", "::1"):
            abort(403, description="Estos endpoints solo se permiten desde localhost.")
        return view(*args, **kwargs)

    return envuelta


def _correr_monitoreo(
    estado: _EstadoMonitoreo,
    dispositivos: list[dict],
    router_ip: str,
    router_mac: str,
) -> None:
    def actualizar(nuevos: list[dict]) -> None:
        with estado.bloqueo:
            estado.resultados = nuevos
        if estado.evento.is_set():
            raise _SolicitudDetencion()

    try:
        try:
            resultados = monitorear(
                dispositivos,
                router_ip,
                router_mac,
                intervalo=2,
                actualizar=actualizar,
            )
        except _SolicitudDetencion:
            resultados = None
        with estado.bloqueo:
            if resultados is not None:
                estado.resultados = resultados
    except Exception:
        logging.getLogger(__name__).exception("El monitoreo de tráfico terminó con error")
    finally:
        with estado.bloqueo:
            estado.activo = False


def _restaurar_respaldo() -> None:
    with _estado.bloqueo:
        dispositivos = list(_estado.dispositivos)
        router_ip = _estado.router_ip
        router_mac = _estado.router_mac

    for dispositivo in dispositivos:
        ip = str(dispositivo.get("ip") or "").strip()
        mac = str(dispositivo.get("mac") or "").strip()
        if (
            not ip
            or not mac
            or dispositivo.get("es_este_equipo")
            or ip == router_ip
        ):
            continue
        try:
            restaurar_arp(ip, ip, mac, router_ip, router_mac)
        except Exception:
            pass
    deshabilitar_ip_forwarding()


def detener_monitoreo() -> list[dict]:
    with _estado.bloqueo:
        hilo = _estado.hilo
        evento = _estado.evento
        activo = _estado.activo
    if not activo or hilo is None:
        return []

    evento.set()
    if hilo is not threading.current_thread():
        hilo.join(timeout=8)
        if hilo.is_alive():
            _restaurar_respaldo()

    with _estado.bloqueo:
        resultados = list(_estado.resultados)
        _estado.activo = False
        _estado.hilo = None
        _estado.resultados = []
    return resultados


def _reiniciar_estado() -> None:
    global _estado
    _estado = _EstadoMonitoreo()


@bp.get("/trafico/capacidades")
@solo_localhost
def capacidades():
    return jsonify(
        es_administrador=es_administrador(),
        npcap_instalado=npcap_instalado(),
    )


@bp.post("/trafico/iniciar")
@solo_localhost
def iniciar():
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict) or datos.get("confirmo_red_propia") is not True:
        abort(
            400,
            description=(
                'Debes enviar {"confirmo_red_propia": true} para confirmar que es '
                "tu propia red y que autorizas el monitoreo de tráfico "
                "(ARP spoofing)."
            ),
        )

    if not es_administrador():
        abort(409, description=MENSAJE_NO_ADMIN)
    if platform.system() == "Windows" and not npcap_instalado():
        abort(409, description=MENSAJE_NO_NPCAP)

    with _estado.bloqueo:
        if _estado.activo:
            abort(409, description=MENSAJE_YA_ACTIVO)

    red = get_red_local()
    if red is None:
        abort(409, description=MENSAJE_SIN_RED)

    dispositivos = scan_dispositivos()
    if not dispositivos:
        abort(409, description=MENSAJE_SIN_DISPOSITIVOS)

    router_ip = _gateway_ip(red.get("rango") or [])
    if not router_ip:
        abort(409, description=MENSAJE_SIN_ROUTER)

    router_mac = obtener_mac(router_ip)
    if not router_mac:
        abort(409, description=f"No se pudo resolver la MAC del router {router_ip}.")

    hilo = threading.Thread(
        target=_correr_monitoreo,
        args=(_estado, dispositivos, router_ip, router_mac),
        daemon=True,
        name="doppelssid-trafico",
    )
    with _estado.bloqueo:
        if _estado.activo:
            abort(409, description=MENSAJE_YA_ACTIVO)
        _estado.evento = threading.Event()
        _estado.resultados = []
        _estado.dispositivos = dispositivos
        _estado.router_ip = router_ip
        _estado.router_mac = router_mac
        _estado.hilo = hilo
        _estado.activo = True
    try:
        hilo.start()
    except Exception:
        with _estado.bloqueo:
            _estado.activo = False
            _estado.hilo = None
        raise

    return jsonify(aceptado=True), 202


@bp.get("/trafico/estado")
@solo_localhost
def estado():
    with _estado.bloqueo:
        if not _estado.activo:
            abort(404, description=MENSAJE_NO_ACTIVO)
        return jsonify(_estado.resultados)


@bp.post("/trafico/detener")
@solo_localhost
def detener():
    with _estado.bloqueo:
        if not _estado.activo:
            abort(404, description=MENSAJE_NO_ACTIVO)
    resumen = detener_monitoreo()
    return jsonify(resumen=resumen, activo=False)
