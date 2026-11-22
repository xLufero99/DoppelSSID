import sys

import pytest

import main
from server import app as servidor_app
from server import rutas_trafico
from server.app import create_app


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


def test_salud(cliente):
    respuesta = cliente.get("/api/salud")
    assert respuesta.status_code == 200
    assert respuesta.get_json() == {"estado": "ok"}


def test_error_404_es_json(cliente):
    respuesta = cliente.get("/api/ruta-inexistente")
    assert respuesta.status_code == 404
    assert "error" in respuesta.get_json()


def test_cors_no_habilitado_por_defecto(cliente):
    respuesta = cliente.get("/api/salud", headers={"Origin": "http://127.0.0.1:5000"})
    assert "Access-Control-Allow-Origin" not in respuesta.headers


def test_flags_servidor_y_web(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--servidor"])
    assert main._parse_args().servidor is True
    monkeypatch.setattr(sys, "argv", ["main.py", "--web"])
    assert main._parse_args().servidor is True


def test_main_con_flag_servidor_llama_al_servidor(monkeypatch):
    llamadas = []
    monkeypatch.setattr(main, "_advertencia_inicial", lambda consola: None)
    monkeypatch.setattr("server.app.ejecutar_servidor", lambda: llamadas.append("servir"))
    monkeypatch.setattr(sys, "argv", ["main.py", "--servidor"])

    main.main()

    assert llamadas == ["servir"]


def test_ejecutar_servidor_imprime_urls_y_limpia_al_salir(monkeypatch, capsys):
    class AppFalsa:
        def run(self, **kwargs):
            assert kwargs["host"] == "0.0.0.0"
            assert kwargs["port"] == 5000
            assert kwargs["use_reloader"] is False
            raise KeyboardInterrupt

    limpiezas = []
    monkeypatch.setattr("server.app.create_app", lambda: AppFalsa())
    monkeypatch.setattr(
        "core.red_local.get_red_local", lambda: {"ip_local": "192.168.1.50"}
    )
    monkeypatch.setattr(
        rutas_trafico,
        "detener_monitoreo",
        lambda: limpiezas.append("detener") or [],
    )
    monkeypatch.setattr("server.app.atexit.register", lambda funcion: None)

    with pytest.raises(KeyboardInterrupt):
        servidor_app.ejecutar_servidor()

    texto = capsys.readouterr().out
    assert "http://localhost:5000" in texto
    assert "http://192.168.1.50:5000" in texto
    assert "para el celular en la misma red" in texto
    assert limpiezas == ["detener"]
