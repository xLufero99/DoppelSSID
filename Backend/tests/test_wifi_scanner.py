import subprocess

from core import wifi_scanner
from core.wifi_scanner import (
    _decode_netsh,
    group_by_ssid,
    parse_netsh,
    parse_nmcli,
    scan_networks,
)

NETSH_REAL_MOJIBAKE = """Nombre de interfaz : Wi-Fi
Actualmente hay 24 redes visibles.

SSID 1 : FAMGARZON_CLARO
    Tipo de red             : Infraestructura
    Autenticaci├│n           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 44:3b:14:6a:39:48
         Se├▒al             : 95%
         Tipo de radio         : 802.11ax
         Banda               : 2,4┬áGHz
         Canal            : 11
         Carga Bss:
             Estaciones conectadas:          4
             Uso del canal:          166 (65 %)
             Capacidad disponible media: 31250 (1000000 us/s)
mscs QoS          admitidos: 0
         Asignaci├│n de QoS admitida: 0
  Velocidades b├ísicas (Mbps): 1 2 5.5 11
    Otras velocidades (Mbps): 6 9 12 18 24 36 48 54
    BSSID 2                 : 44:3b:14:6a:39:4f
         Se├▒al             : 75%
         Tipo de radio         : 802.11ax
         Banda               : 5 GHz
         Canal            : 149
"""

NETSH_ES_CORRECTO = """Nombre de interfaz : Wi-Fi
Actualmente hay 6 redes visibles.

SSID 1 : Café-Centro
    Tipo de red : Infraestructura
    Autenticación : WPA3-Personal
    Cifrado : GCMP
    BSSID 1 : aa:bb:cc:dd:ee:01
         Señal : 88%
         Banda : 2,4\xa0GHz
         Canal : 6
         Carga Bss:
             Estaciones conectadas: 3
             Uso del canal: 100 (40 %)
"""

NETSH_EN = """Interface name : Wi-Fi
State : connected

SSID 1 : Office-5G
    Network type : Infrastructure
    Authentication : WPA2-Enterprise
    Encryption : CCMP
    BSSID 1 : 11:22:33:44:55:66
        Signal : 72%
        Band : 5 GHz
        Channel : 36
    BSSID 2 : 11:22:33:44:55:77
        Signal : 55%
        Band : 6 GHz
        Channel : 149
"""

NETSH_OCULTA = """SSID 1 :
    Autenticación : WPA2-Personal
    Cifrado : CCMP
    BSSID 1 : 00:11:22:33:44:99
        Señal : 42%
        Banda : 2,4 GHz
        Canal : 1
"""

NETSH_ES = """Interfaz nombre : Wi-Fi
Estado : conectado

SSID 1 : CasaÑa
    Tipo de red : Infraestructura
    Autenticación : WPA2-Personal
    Cifrado : CCMP
    Señal : 81%
    BSSID 1 : 00:11:22:33:44:55
        Señal : 78%
        Canal : 6
        Velocidad de recepción (Mbps) : 130
    BSSID 2 : 00:11:22:33:44:66
        Señal : 61%
        Canal : 11

SSID 2 :
    Tipo de red : Infraestructura
    Autenticación : WPA2-Personal
    Cifrado : CCMP
    Señal : 40%
    BSSID 1 : aa:bb:cc:dd:ee:ff
        Señal : 35%
        Canal : 1
"""

NMCLI = r"""Mi\:Cafe:00:11:22:33:44:55:6:85:WPA2 WPA3
--:aa:bb:cc:dd:ee:ff:1:20:--
"""


def test_parse_netsh_mojibake_real_dos_bssid():
    redes = parse_netsh(NETSH_REAL_MOJIBAKE)

    assert redes == [
        {
            "ssid": "FAMGARZON_CLARO",
            "bssid": "44:3B:14:6A:39:48",
            "canal": 11,
            "senal": 95,
            "banda": "2.4 GHz",
            "autenticacion": "WPA2-Personal",
            "cifrado": "CCMP",
            "estaciones": 4,
            "uso_canal": 65,
        },
        {
            "ssid": "FAMGARZON_CLARO",
            "bssid": "44:3B:14:6A:39:4F",
            "canal": 149,
            "senal": 75,
            "banda": "5 GHz",
            "autenticacion": "WPA2-Personal",
            "cifrado": "CCMP",
            "estaciones": None,
            "uso_canal": None,
        },
    ]


def test_parse_netsh_etiquetas_correctas_y_nbsp():
    redes = parse_netsh(NETSH_ES_CORRECTO)

    assert redes[0]["ssid"] == "Café-Centro"
    assert redes[0]["autenticacion"] == "WPA3-Personal"
    assert redes[0]["cifrado"] == "GCMP"
    assert redes[0]["banda"] == "2.4 GHz"
    assert redes[0]["estaciones"] == 3
    assert redes[0]["uso_canal"] == 40


def test_parse_netsh_ingles():
    redes = parse_netsh(NETSH_EN)

    assert len(redes) == 2
    assert [red["senal"] for red in redes] == [72, 55]
    assert [red["canal"] for red in redes] == [36, 149]
    assert [red["banda"] for red in redes] == ["5 GHz", "6 GHz"]
    assert all(red["autenticacion"] == "WPA2-Enterprise" for red in redes)
    assert all(red["cifrado"] == "CCMP" for red in redes)


def test_parse_netsh_red_oculta():
    redes = parse_netsh(NETSH_OCULTA)

    assert redes[0]["ssid"] == "<oculta>"


def test_decodificacion_utf8_y_cp850_dan_mismo_resultado():
    texto = NETSH_REAL_MOJIBAKE
    redes_utf8 = parse_netsh(_decode_netsh(texto.encode("utf-8")))
    redes_cp850 = parse_netsh(_decode_netsh(texto.encode("cp850")))

    assert redes_utf8 == redes_cp850
    assert redes_utf8[0]["senal"] == 95
    assert redes_utf8[0]["autenticacion"] == "WPA2-Personal"


def test_parse_netsh_espanol_campos_separados_y_senal_int():
    redes = parse_netsh(NETSH_ES)

    assert redes[0] == {
        "ssid": "CasaÑa",
        "bssid": "00:11:22:33:44:55",
        "canal": 6,
        "senal": 78,
        "banda": "",
        "autenticacion": "WPA2-Personal",
        "cifrado": "CCMP",
        "estaciones": None,
        "uso_canal": None,
    }
    assert redes[2]["ssid"] == "<oculta>"
    assert redes[2]["senal"] == 35


def test_parse_netsh_un_ssid_con_dos_bssid():
    redes = parse_netsh(NETSH_ES)

    assert [red["bssid"] for red in redes if red["ssid"] == "CasaÑa"] == [
        "00:11:22:33:44:55",
        "00:11:22:33:44:66",
    ]
    assert [red["senal"] for red in redes if red["ssid"] == "CasaÑa"] == [78, 61]


def test_scan_networks_windows_decodifica_cp850(monkeypatch):
    monkeypatch.setattr(wifi_scanner.platform, "system", lambda: "Windows")

    def falso_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, NETSH_ES.encode("cp850"), b"")

    monkeypatch.setattr(wifi_scanner.subprocess, "run", falso_run)
    redes = scan_networks()

    assert redes[0]["ssid"] == "CasaÑa"
    assert redes[0]["senal"] == 78
    assert redes[0]["canal"] == 6


def test_scan_networks_devuelve_vacio_si_comando_falla(monkeypatch):
    monkeypatch.setattr(wifi_scanner.platform, "system", lambda: "Windows")

    def falso_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, b"", b"error")

    monkeypatch.setattr(wifi_scanner.subprocess, "run", falso_run)

    assert scan_networks() == []


def test_parse_nmcli_ssid_con_dos_puntos_y_red_oculta():
    redes = parse_nmcli(NMCLI)

    assert redes[0]["ssid"] == "Mi:Cafe"
    assert redes[0]["bssid"] == "00:11:22:33:44:55"
    assert redes[0]["canal"] == 6
    assert redes[0]["senal"] == 85
    assert redes[0]["banda"] == ""
    assert redes[0]["autenticacion"] == "WPA2 WPA3"
    assert redes[0]["cifrado"] == ""
    assert redes[0]["estaciones"] is None
    assert redes[0]["uso_canal"] is None
    assert redes[1]["ssid"] == "<oculta>"
    assert redes[1]["autenticacion"] == "abierta"


def test_group_by_ssid_ordena_bssid():
    redes = [
        {
            "ssid": "Casa",
            "bssid": "00:11:22:33:44:66",
            "senal": 50,
        },
        {
            "ssid": "Casa",
            "bssid": "00:11:22:33:44:55",
            "senal": 80,
        },
        {
            "ssid": "Oficina",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "senal": 40,
        },
    ]

    agrupadas = group_by_ssid(redes)

    assert list(agrupadas) == ["Casa", "Oficina"]
    assert [red["bssid"] for red in agrupadas["Casa"]] == [
        "00:11:22:33:44:55",
        "00:11:22:33:44:66",
    ]
