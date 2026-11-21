import json

from core import wifi_scanner
from core import trusted
from core.classifier import classify, normalizar_oui, tiene_bit_local


def red(
    bssid,
    ssid="Prueba",
    autenticacion="WPA2-Personal",
    cifrado="CCMP",
    canal=11,
    banda="2.4 GHz",
    senal=60,
):
    return {
        "ssid": ssid,
        "bssid": bssid,
        "canal": canal,
        "senal": senal,
        "banda": banda,
        "autenticacion": autenticacion,
        "cifrado": cifrado,
        "estaciones": None,
        "uso_canal": None,
    }


def perfil(ssid="Casa", bssids=None):
    return {
        "ssid": ssid,
        "autenticacion": "WPA2-Personal",
        "cifrado": "CCMP",
        "bssids": bssids
        or {
            "44:48:B9:F6:51:C0": {
                "canal": 11,
                "banda": "2.4 GHz",
                "senal": 50,
            }
        },
    }


def usar_tmp(monkeypatch, tmp_path):
    ruta = tmp_path / "trusted_networks.json"
    monkeypatch.setattr(trusted, "RUTA_CONFIABLES", ruta)
    return ruta


def test_mesh_mismo_oui_misma_banda_mismo_cifrado():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Malla"),
        red("44:48:B9:F6:51:C1", ssid="Malla"),
    ]

    resultado = classify(redes)[0]

    assert resultado["estado"] == "segura"
    assert resultado["puntaje"] == 0
    assert all(red_resultado["estado"] == "segura" for red_resultado in resultado["redes"])


def test_doble_banda_con_bit_local():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Doble", banda="2.4 GHz"),
        red("46:48:B9:F6:51:C7", ssid="Doble", banda="5 GHz"),
    ]

    resultado = classify(redes)[0]

    assert resultado["estado"] == "segura"
    assert resultado["puntaje"] == 0
    assert all(red_resultado["puntaje"] == 0 for red_resultado in resultado["redes"])


def test_wpa2_y_abierta_empate_ambos_riesgo():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Mixta"),
        red(
            "44:48:B9:F6:51:C1",
            ssid="Mixta",
            autenticacion="Abierta",
            cifrado="Ninguna",
        ),
    ]

    resultado = classify(redes)[0]

    assert [item["estado"] for item in resultado["redes"]] == ["riesgo", "riesgo"]
    assert all(item["puntaje"] == 100 for item in resultado["redes"])
    assert all(item["motivos"] for item in resultado["redes"])


def test_tres_bssid_solo_uno_difiere():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Tres"),
        red("44:48:B9:F6:51:C1", ssid="Tres"),
        red(
            "11:22:33:44:55:66",
            ssid="Tres",
            autenticacion="Abierta",
            cifrado="Ninguna",
        ),
    ]

    resultado = classify(redes)[0]
    por_bssid = {item["bssid"]: item for item in resultado["redes"]}

    assert por_bssid["11:22:33:44:55:66"]["estado"] == "riesgo"
    assert por_bssid["44:48:B9:F6:51:C0"]["estado"] == "segura"
    assert por_bssid["44:48:B9:F6:51:C1"]["estado"] == "segura"
    assert not por_bssid["44:48:B9:F6:51:C0"]["motivos"]
    assert not por_bssid["44:48:B9:F6:51:C1"]["motivos"]


def test_oui_distinto_mismo_cifrado_precaucion():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="OUI"),
        red("11:22:33:44:55:66", ssid="OUI"),
    ]

    resultado = classify(redes)[0]

    assert resultado["estado"] == "precaucion"
    assert [item["puntaje"] for item in resultado["redes"]] == [25, 25]


def test_motivo_oui_distinto_muestra_dos_ouis_reales():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="OUI"),
        red("11:22:33:44:55:66", ssid="OUI"),
    ]

    resultado = classify(redes)[0]
    mensajes = [
        motivo
        for item in resultado["redes"]
        for motivo in item["motivos"]
        if motivo.startswith("OUI distinto (")
    ]

    assert len(mensajes) == 2
    for mensaje in mensajes:
        assert "44:48:B9" in mensaje
        assert "11:22:33" in mensaje
        assert mensaje.count("44:48:B9") == 1
        assert mensaje.count("11:22:33") == 1
        assert " vs " in mensaje


def test_motivo_auth_distinta_muestra_dos_valores_reales():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Mixta"),
        red(
            "44:48:B9:F6:51:C1",
            ssid="Mixta",
            autenticacion="Abierta",
            cifrado="Ninguna",
        ),
    ]

    resultado = classify(redes)[0]
    mensajes = [
        motivo
        for item in resultado["redes"]
        for motivo in item["motivos"]
        if motivo.startswith("Mismo nombre con otra seguridad (")
    ]

    assert len(mensajes) == 2
    for mensaje in mensajes:
        assert "WPA2-Personal/CCMP" in mensaje
        assert "Abierta/Ninguna" in mensaje
        assert mensaje.count("WPA2-Personal/CCMP") == 1
        assert mensaje.count("Abierta/Ninguna") == 1


def test_oui_distinto_y_cifrado_distinto_riesgo():
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Mixta"),
        red(
            "11:22:33:44:55:66",
            ssid="Mixta",
            autenticacion="WPA3-Personal",
            cifrado="GCMP",
        ),
    ]

    resultado = classify(redes)[0]

    assert resultado["estado"] == "riesgo"
    assert all(item["puntaje"] == 75 for item in resultado["redes"])


def test_unico_wpa2_segura_y_unico_abierto_precaucion():
    segura = classify([red("44:48:B9:F6:51:C0", ssid="Sola")])[0]
    abierta = classify(
        [
            red(
                "44:48:B9:F6:51:C1",
                ssid="Abierta",
                autenticacion="Abierta",
                cifrado="Ninguna",
            )
        ]
    )[0]

    assert segura["estado"] == "segura"
    assert segura["puntaje"] == 0
    assert abierta["estado"] == "precaucion"
    assert abierta["puntaje"] == 25


def test_red_oculta():
    resultado = classify([red("44:48:B9:F6:51:C0", ssid="<oculta>")])[0]

    assert resultado["estado"] == "oculta"
    assert resultado["puntaje"] == 0
    assert resultado["motivos"] == ["Red oculta: no se puede comparar por nombre"]


def test_confiable_todos_bssid_en_perfil():
    perfiles = [perfil()]
    redes = [red("44:48:B9:F6:51:C0", ssid="Casa", senal=50)]

    resultado = classify(redes, perfiles)[0]

    assert resultado["estado"] == "segura"
    assert resultado["puntaje"] == 0
    assert resultado["redes"][0]["motivos"] == []


def test_confiable_bssid_nuevo_mismo_oui_misma_auth():
    perfiles = [perfil()]
    redes = [red("44:48:B9:F6:51:C1", ssid="Casa", canal=11, senal=60)]

    resultado = classify(redes, perfiles)[0]

    assert resultado["estado"] == "precaucion"
    assert resultado["puntaje"] == 40


def test_confiable_bssid_nuevo_oui_distinto_y_senal_mayor():
    perfiles = [perfil()]
    redes = [
        red(
            "11:22:33:44:55:66",
            ssid="Casa",
            canal=11,
            senal=90,
        )
    ]

    resultado = classify(redes, perfiles)[0]

    assert resultado["estado"] == "riesgo"
    assert resultado["puntaje"] == 80


def test_confiable_bssid_nuevo_abierto_regla_dura():
    perfiles = [perfil()]
    redes = [
        red(
            "44:48:B9:F6:51:C1",
            ssid="Casa",
            autenticacion="Abierta",
            cifrado="Ninguna",
            canal=11,
            senal=50,
        )
    ]

    resultado = classify(redes, perfiles)[0]

    assert resultado["estado"] == "riesgo"
    assert resultado["puntaje"] == 100


def test_puntaje_nunca_fuera_de_rango():
    malla = classify(
        [
            red("44:48:B9:F6:51:C0", ssid="+100"),
            red("44:48:B9:F6:51:C1", ssid="+100"),
        ]
    )[0]
    extremo = classify(
        [
            red(
                "11:22:33:44:55:66",
                ssid="Casa",
                autenticacion="Abierta",
                cifrado="Ninguna",
                canal=6,
                senal=99,
            )
        ],
        [perfil()],
    )[0]

    assert all(0 <= item["puntaje"] <= 100 for item in malla["redes"])
    assert 0 <= extremo["puntaje"] <= 100
    assert extremo["puntaje"] == 100


def test_normalizar_oui_y_tiene_bit_local():
    assert normalizar_oui("44:48:B9:F6:51:C0") == "44:48:B9"
    assert normalizar_oui("46:48:B9:F6:51:C7") == "44:48:B9"
    assert tiene_bit_local("44:48:B9:F6:51:C0") is False
    assert tiene_bit_local("46:48:B9:F6:51:C7") is True


def test_load_trusted_sin_archivo_vacio_y_corrupto(monkeypatch, tmp_path):
    ruta = usar_tmp(monkeypatch, tmp_path / "nueva" / "data")

    assert trusted.load_trusted() == []
    assert ruta.parent.is_dir()

    ruta.write_text("", encoding="utf-8")
    assert trusted.load_trusted() == []

    ruta.write_text("{mal", encoding="utf-8")
    assert trusted.load_trusted() == []


def test_save_trusted_y_recargar(monkeypatch, tmp_path):
    ruta = usar_tmp(monkeypatch, tmp_path)
    perfiles = [perfil()]

    trusted.save_trusted(perfiles)

    assert trusted.load_trusted() == perfiles
    assert json.loads(ruta.read_text(encoding="utf-8")) == perfiles
    assert list(ruta.parent.glob(".trusted_*.tmp")) == []


def test_trust_ssid_rechaza_oculta_y_reemplaza(monkeypatch, tmp_path):
    usar_tmp(monkeypatch, tmp_path)
    redes = [
        red("44:48:B9:F6:51:C0", ssid="Casa"),
        red("44:48:B9:F6:51:C1", ssid="Casa"),
        red("11:22:33:44:55:66", ssid="<oculta>"),
    ]

    trusted.trust_ssid("<oculta>", redes)
    assert trusted.load_trusted() == []

    trusted.trust_ssid("Casa", redes)
    guardado = trusted.get_profile("Casa")
    assert set(guardado["bssids"]) == {
        "44:48:B9:F6:51:C0",
        "44:48:B9:F6:51:C1",
    }

    trusted.trust_ssid("Casa", [red("AA:BB:CC:DD:EE:FF", ssid="Casa")])
    assert set(trusted.get_profile("Casa")["bssids"]) == {"AA:BB:CC:DD:EE:FF"}

    trusted.untrust_ssid("Casa")
    assert trusted.get_profile("Casa") is None


def test_scan_merged_conserva_senal_mayor(monkeypatch):
    escaneos = [
        [red("44:48:B9:F6:51:C0", ssid="Casa", senal=50)],
        [
            red("44:48:B9:F6:51:C0", ssid="Casa", senal=90),
            red("44:48:B9:F6:51:C1", ssid="Casa", senal=40),
        ],
    ]

    def falso_scan():
        return escaneos.pop(0) if escaneos else []

    monkeypatch.setattr(wifi_scanner, "scan_networks", falso_scan)
    monkeypatch.setattr(wifi_scanner.time, "sleep", lambda _: None)

    redes = wifi_scanner.scan_merged(n=2, pausa=0)

    assert len(redes) == 2
    assert redes[0]["bssid"] == "44:48:B9:F6:51:C0"
    assert redes[0]["senal"] == 90
