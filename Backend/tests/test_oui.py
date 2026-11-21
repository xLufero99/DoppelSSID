from pathlib import Path

from core import oui
from core.oui import fabricante_de


def test_ruta_csv_es_relativa_al_modulo():
    esperada = Path(oui.__file__).resolve().parent.parent / "data" / "oui_fabricantes.csv"
    assert oui.RUTA_OUI == esperada


def test_fabricante_de_csv_real():
    casos = {
        "CC:47:40:11:22:33": "AzureWave",
        "00:E0:4C:10:20:30": "Realtek",
        "B8:27:EB:11:22:33": "Raspberry Pi",
        "F4:F5:D8:00:00:01": "Google",
    }
    for mac, esperado in casos.items():
        assert esperado.lower() in fabricante_de(mac).lower()


def test_fabricante_de_bit_local_es_aleatoria():
    assert fabricante_de("BA:27:EB:11:22:33") == "Desconocido (MAC aleatoria)"


def test_fabricante_de_no_registrado():
    assert fabricante_de("00:AA:BB:11:22:33") == "Desconocido"


def test_csv_se_carga_una_sola_vez(monkeypatch, tmp_path):
    ruta = tmp_path / "oui_fabricantes.csv"
    ruta.write_text(
        "prefijo,fabricante\n00:AA:BB,Proveedor Temporal\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(oui, "RUTA_OUI", ruta)
    monkeypatch.setattr(oui, "_FABRICANTES", None)

    assert fabricante_de("00:AA:BB:00:00:01") == "Proveedor Temporal"

    ruta.write_text(
        "prefijo,fabricante\n00:AA:BB,Otro Proveedor\n",
        encoding="utf-8",
    )

    assert fabricante_de("00:AA:BB:00:00:01") == "Proveedor Temporal"
