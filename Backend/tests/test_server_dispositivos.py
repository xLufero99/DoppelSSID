import pytest

from server import rutas_dispositivos
from server.app import create_app

DISPOSITIVOS = [
    {
        "ip": "192.168.1.10",
        "mac": "00:E0:4C:11:22:33",
        "fabricante": "REALTEK",
        "es_este_equipo": False,
    }
]


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


def test_dispositivos_llama_core(cliente, monkeypatch):
    llamadas = []

    def falso_scan():
        llamadas.append("scan")
        return DISPOSITIVOS

    monkeypatch.setattr(rutas_dispositivos, "scan_dispositivos", falso_scan)

    respuesta = cliente.get("/api/dispositivos")

    assert respuesta.status_code == 200
    assert respuesta.get_json() == DISPOSITIVOS
    assert llamadas == ["scan"]


def test_cache_dispositivos_no_rescanea_y_expira(cliente, monkeypatch):
    llamadas = []

    def falso_scan():
        llamadas.append("scan")
        return DISPOSITIVOS

    monkeypatch.setattr(rutas_dispositivos, "scan_dispositivos", falso_scan)
    ahora = [500.0]
    monkeypatch.setattr("server.cache.time.monotonic", lambda: ahora[0])

    assert cliente.get("/api/dispositivos").get_json() == DISPOSITIVOS
    assert cliente.get("/api/dispositivos").get_json() == DISPOSITIVOS
    assert llamadas == ["scan"]

    ahora[0] += 14
    cliente.get("/api/dispositivos")
    assert llamadas == ["scan"]

    ahora[0] += 2
    cliente.get("/api/dispositivos")
    assert llamadas == ["scan", "scan"]
