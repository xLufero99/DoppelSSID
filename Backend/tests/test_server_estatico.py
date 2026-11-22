import pytest

from server.app import create_app


@pytest.fixture
def cliente():
    aplicacion = create_app()
    aplicacion.config["TESTING"] = True
    return aplicacion.test_client()


def test_get_devuelve_index(cliente):
    respuesta = cliente.get("/")

    assert respuesta.status_code == 200
    texto = respuesta.get_data(as_text=True)
    assert "DoppelSSID" in texto
    assert "css/estilo.css" in texto
    assert "js/app.js" in texto


def test_assets_se_sirven_en_rutas_relativas(cliente):
    css = cliente.get("/css/estilo.css")
    js = cliente.get("/js/app.js")

    assert css.status_code == 200
    assert "text/css" in css.content_type
    assert "--color-canvas" in css.get_data(as_text=True)

    assert js.status_code == 200
    assert "javascript" in js.content_type
    assert "fetchJson" in js.get_data(as_text=True)
