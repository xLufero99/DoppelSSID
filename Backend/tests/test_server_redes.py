import pytest

from server import rutas_redes
from server.app import create_app

REDES = [
    {
        "ssid": "Casa",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "senal": 70,
        "canal": 6,
        "banda": "2.4 GHz",
        "autenticacion": "WPA2-Personal",
        "cifrado": "CCMP",
    }
]
CONFIABLES = [{"ssid": "Casa"}]
CLASIFICADO = [
    {
        "ssid": "Casa",
        "estado": "segura",
        "puntaje": 0,
        "motivos": [],
        "redes": [],
    }
]


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


def preparar_core(monkeypatch):
    llamadas = []

    def falso_scan(n):
        llamadas.append("scan")
        return REDES

    def falso_trusted():
        llamadas.append("trusted")
        return CONFIABLES

    def falso_classify(redes, confiables):
        llamadas.append(("classify", redes, confiables))
        return CLASIFICADO

    monkeypatch.setattr(rutas_redes, "scan_merged", falso_scan)
    monkeypatch.setattr(rutas_redes, "load_trusted", falso_trusted)
    monkeypatch.setattr(rutas_redes, "classify", falso_classify)
    return llamadas


def test_redes_llama_scan_trusted_y_classify(cliente, monkeypatch):
    llamadas = preparar_core(monkeypatch)

    respuesta = cliente.get("/api/redes")

    assert respuesta.status_code == 200
    assert respuesta.get_json() == CLASIFICADO
    assert llamadas[:2] == ["scan", "trusted"]
    assert llamadas[2] == ("classify", REDES, CONFIABLES)


def test_redes_actualiza_la_cache_para_estado(cliente, monkeypatch):
    llamadas = preparar_core(monkeypatch)

    cliente.get("/api/redes")
    respuesta = cliente.get("/api/redes/estado")

    assert respuesta.get_json() == CLASIFICADO
    assert llamadas.count("scan") == 1


def test_cache_redes_no_rescanea_y_expira(cliente, monkeypatch):
    llamadas = preparar_core(monkeypatch)
    ahora = [1000.0]
    monkeypatch.setattr("server.cache.time.monotonic", lambda: ahora[0])

    assert cliente.get("/api/redes/estado").get_json() == CLASIFICADO
    assert cliente.get("/api/redes/estado").get_json() == CLASIFICADO
    assert llamadas.count("scan") == 1

    ahora[0] += 6
    assert cliente.get("/api/redes/estado").status_code == 200
    assert llamadas.count("scan") == 2
