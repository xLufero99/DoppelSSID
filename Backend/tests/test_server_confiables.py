import pytest

from server import rutas_confiables
from server.app import create_app
from server.cache import cache_por_nombre

REDES = [
    {
        "ssid": "Casa",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "canal": 6,
        "banda": "2.4 GHz",
        "senal": 70,
        "autenticacion": "WPA2-Personal",
        "cifrado": "CCMP",
    }
]
PERFILES = [{"ssid": "Casa", "bssids": {"AA:BB:CC:DD:EE:FF": {}}}]


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


def test_listar_confiables(cliente, monkeypatch):
    monkeypatch.setattr(rutas_confiables, "load_trusted", lambda: PERFILES)

    respuesta = cliente.get("/api/confiables")

    assert respuesta.status_code == 200
    assert respuesta.get_json() == PERFILES


@pytest.mark.parametrize(
    "cuerpo",
    [{}, {"ssid": ""}, {"ssid": "   "}, {"ssid": "<oculta>"}, {"ssid": 123}],
)
def test_post_ssid_invalido_no_toca_core(cliente, monkeypatch, cuerpo):
    monkeypatch.setattr(
        rutas_confiables,
        "scan_merged",
        lambda n: pytest.fail("no se debe escanear"),
    )
    monkeypatch.setattr(
        rutas_confiables,
        "trust_ssid",
        lambda *args: pytest.fail("no se debe guardar"),
    )

    respuesta = cliente.post("/api/confiables", json=cuerpo)

    assert respuesta.status_code == 400
    assert "error" in respuesta.get_json()


def test_post_ssid_ausente_en_escaneo(cliente, monkeypatch):
    monkeypatch.setattr(rutas_confiables, "scan_merged", lambda n: REDES)
    monkeypatch.setattr(
        rutas_confiables,
        "trust_ssid",
        lambda *args: pytest.fail("no se debe guardar"),
    )

    respuesta = cliente.post("/api/confiables", json={"ssid": "Otro"})

    assert respuesta.status_code == 400
    assert "No se encontró" in respuesta.get_json()["error"]


def test_post_guarda_confianza_e_invalida_cache(cliente, monkeypatch):
    guardados = []
    monkeypatch.setattr(rutas_confiables, "scan_merged", lambda n: REDES)
    monkeypatch.setattr(
        rutas_confiables,
        "trust_ssid",
        lambda ssid, redes: guardados.append((ssid, redes)),
    )
    with cliente.application.app_context():
        cache_por_nombre("redes").establecer(["resultado viejo"])

    respuesta = cliente.post("/api/confiables", json={"ssid": "Casa"})

    assert respuesta.status_code == 201
    assert respuesta.get_json() == {"ok": True, "ssid": "Casa"}
    assert guardados == [("Casa", REDES)]
    with cliente.application.app_context():
        cache = cache_por_nombre("redes")
        assert cache.valor is None
        assert cache.creado is None


def test_delete_llama_untrust_e_invalida_cache(cliente, monkeypatch):
    eliminados = []
    monkeypatch.setattr(
        rutas_confiables,
        "untrust_ssid",
        lambda ssid: eliminados.append(ssid),
    )
    with cliente.application.app_context():
        cache_por_nombre("redes").establecer(["resultado viejo"])

    respuesta = cliente.delete("/api/confiables/Casa")

    assert respuesta.status_code == 200
    assert respuesta.get_json() == {"ok": True, "ssid": "Casa"}
    assert eliminados == ["Casa"]
    with cliente.application.app_context():
        assert cache_por_nombre("redes").valor is None
