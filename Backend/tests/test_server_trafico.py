import threading
import time

import pytest

from server import rutas_trafico
from server.app import create_app

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
DISPOSITIVO = {
    "ip": "192.168.1.10",
    "mac": "00:11:22:33:44:55",
    "fabricante": "REALTEK",
    "es_este_equipo": False,
}
PRIMER_SNAPSHOT = [
    {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "bytes": 10, "porcentaje": 100}
]
ULTIMO_SNAPSHOT = [
    {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "bytes": 20, "porcentaje": 100}
]
NOMBRES_CORE = (
    "es_administrador",
    "npcap_instalado",
    "get_red_local",
    "scan_dispositivos",
    "_gateway_ip",
    "obtener_mac",
    "monitorear",
    "restaurar_arp",
    "deshabilitar_ip_forwarding",
)


def prohibir(nombre):
    def fallo(*args, **kwargs):
        pytest.fail(f"no se debe llamar {nombre}")

    return fallo


def prohibir_core(monkeypatch):
    for nombre in NOMBRES_CORE:
        monkeypatch.setattr(rutas_trafico, nombre, prohibir(nombre), raising=False)


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


@pytest.fixture(autouse=True)
def estado_limpio():
    rutas_trafico._reiniciar_estado()
    yield
    rutas_trafico.detener_monitoreo()
    rutas_trafico._reiniciar_estado()


@pytest.mark.parametrize(
    "metodo,ruta",
    [
        ("get", "/api/trafico/capacidades"),
        ("post", "/api/trafico/iniciar"),
        ("get", "/api/trafico/estado"),
        ("post", "/api/trafico/detener"),
    ],
)
def test_ip_ajena_recibe_403_sin_ejecutar_core(cliente, monkeypatch, metodo, ruta):
    prohibir_core(monkeypatch)
    opciones = {"environ_base": {"REMOTE_ADDR": "1.2.3.4"}}
    if metodo == "post":
        opciones["json"] = {"confirmo_red_propia": True}

    respuesta = getattr(cliente, metodo)(ruta, **opciones)

    assert respuesta.status_code == 403
    assert "localhost" in respuesta.get_json()["error"]


def test_localhost_ipv6_esta_permitido(cliente, monkeypatch):
    monkeypatch.setattr(rutas_trafico, "es_administrador", lambda: False)
    monkeypatch.setattr(rutas_trafico, "npcap_instalado", lambda: True)

    respuesta = cliente.get(
        "/api/trafico/capacidades",
        environ_base={"REMOTE_ADDR": "::1"},
    )

    assert respuesta.status_code == 200
    assert respuesta.get_json() == {"es_administrador": False, "npcap_instalado": True}


def test_ipv4_mapeado_no_cuenta_como_localhost(cliente, monkeypatch):
    prohibir_core(monkeypatch)

    respuesta = cliente.get(
        "/api/trafico/capacidades",
        environ_base={"REMOTE_ADDR": "::ffff:127.0.0.1"},
    )

    assert respuesta.status_code == 403


@pytest.mark.parametrize(
    "cuerpo",
    [{}, {"confirmo_red_propia": False}, {"confirmo_red_propia": "true"}, None],
)
def test_iniciar_requiere_confirmacion_explicita(cliente, monkeypatch, cuerpo):
    prohibir_core(monkeypatch)

    opciones = {}
    if cuerpo is not None:
        opciones["json"] = cuerpo
    respuesta = cliente.post("/api/trafico/iniciar", **opciones)

    assert respuesta.status_code == 400
    assert "confirmo_red_propia" in respuesta.get_json()["error"]


def test_iniciar_sin_administrador_devuelve_409(cliente, monkeypatch):
    prohibir_core(monkeypatch)
    monkeypatch.setattr(rutas_trafico, "es_administrador", lambda: False)

    respuesta = cliente.post(
        "/api/trafico/iniciar", json={"confirmo_red_propia": True}
    )

    assert respuesta.status_code == 409
    assert respuesta.get_json()["error"] == MENSAJE_NO_ADMIN


def test_iniciar_sin_npcap_devuelve_409(cliente, monkeypatch):
    prohibir_core(monkeypatch)
    monkeypatch.setattr(rutas_trafico, "es_administrador", lambda: True)
    monkeypatch.setattr(rutas_trafico.platform, "system", lambda: "Windows")
    monkeypatch.setattr(rutas_trafico, "npcap_instalado", lambda: False)

    respuesta = cliente.post(
        "/api/trafico/iniciar", json={"confirmo_red_propia": True}
    )

    assert respuesta.status_code == 409
    assert respuesta.get_json()["error"] == MENSAJE_NO_NPCAP


def test_estado_y_detener_sin_monitoreo_devuelven_404(cliente, monkeypatch):
    prohibir_core(monkeypatch)

    assert cliente.get("/api/trafico/estado").status_code == 404
    assert cliente.post("/api/trafico/detener").status_code == 404


def test_ciclo_iniciar_estado_detener(cliente, monkeypatch):
    limpieza = []

    def falso_monitorear(
        dispositivos, router_ip, router_mac, intervalo=2, actualizar=None
    ):
        try:
            actualizar(PRIMER_SNAPSHOT)
            while not rutas_trafico._estado.evento.is_set():
                time.sleep(0.01)
            actualizar(ULTIMO_SNAPSHOT)
            return ULTIMO_SNAPSHOT
        finally:
            limpieza.append("finally-core")

    monkeypatch.setattr(rutas_trafico.platform, "system", lambda: "Windows")
    monkeypatch.setattr(rutas_trafico, "es_administrador", lambda: True)
    monkeypatch.setattr(rutas_trafico, "npcap_instalado", lambda: True)
    monkeypatch.setattr(
        rutas_trafico, "get_red_local", lambda: {"rango": ["192.168.1.1"]}
    )
    monkeypatch.setattr(rutas_trafico, "scan_dispositivos", lambda: [DISPOSITIVO])
    monkeypatch.setattr(rutas_trafico, "_gateway_ip", lambda rango: "192.168.1.1")
    monkeypatch.setattr(rutas_trafico, "obtener_mac", lambda ip: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr(rutas_trafico, "monitorear", falso_monitorear)
    monkeypatch.setattr(rutas_trafico, "restaurar_arp", prohibir("restaurar_arp"))
    monkeypatch.setattr(
        rutas_trafico, "deshabilitar_ip_forwarding", prohibir("forwarding")
    )

    respuesta = cliente.post("/api/trafico/iniciar", json={"confirmo_red_propia": True})
    assert respuesta.status_code == 202

    for _ in range(300):
        snapshot = cliente.get("/api/trafico/estado")
        if snapshot.status_code == 200 and snapshot.get_json() == PRIMER_SNAPSHOT:
            break
        time.sleep(0.01)
    else:
        pytest.fail("el estado nunca mostró el primer snapshot")

    repetido = cliente.post(
        "/api/trafico/iniciar", json={"confirmo_red_propia": True}
    )
    assert repetido.status_code == 409

    detenido = cliente.post("/api/trafico/detener")
    assert detenido.status_code == 200
    assert detenido.get_json() == {"resumen": ULTIMO_SNAPSHOT, "activo": False}
    assert limpieza == ["finally-core"]
    assert cliente.get("/api/trafico/estado").status_code == 404


def test_respaldo_restaura_si_el_hilo_no_termina(monkeypatch):
    llamadas = []
    monkeypatch.setattr(
        rutas_trafico,
        "restaurar_arp",
        lambda *args: llamadas.append(args),
    )
    monkeypatch.setattr(
        rutas_trafico,
        "deshabilitar_ip_forwarding",
        lambda: llamadas.append("deshabilitar"),
    )

    class HiloPerezoso:
        def join(self, timeout=None):
            return None

        def is_alive(self):
            return True

    estado = rutas_trafico._estado
    estado.activo = True
    estado.evento = threading.Event()
    estado.hilo = HiloPerezoso()
    estado.dispositivos = [
        DISPOSITIVO,
        {"ip": "192.168.1.5", "mac": "00:AA:BB:00:00:01", "es_este_equipo": True},
    ]
    estado.router_ip = "192.168.1.1"
    estado.router_mac = "AA:BB:CC:DD:EE:FF"

    assert rutas_trafico.detener_monitoreo() == []
    assert llamadas == [
        (
            "192.168.1.10",
            "192.168.1.10",
            "00:11:22:33:44:55",
            "192.168.1.1",
            "AA:BB:CC:DD:EE:FF",
        ),
        "deshabilitar",
    ]
    assert estado.activo is False
