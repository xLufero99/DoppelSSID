import subprocess

from core import arp_scanner, red_local


IPCONFIG_ES = (
    "Windows IP Configuration\r\n"
    "\r\n"
    "Adaptador LAN inalámbrico Wi-Fi:\r\n"
    "\r\n"
    "   Dirección IPv4. . . . . . . . . . . : 192.168.1.5\r\n"
    "   Máscara de subred . . . . . . . . . : 255.255.255.0\r\n"
    "   Puerta de enlace predeterminada . . : 192.168.1.1\r\n"
)

IPCONFIG_LIMITADO = (
    "Wireless LAN adapter Wi-Fi:\r\n"
    "\r\n"
    "   IPv4 Address. . . . . . . . . . . : 10.0.0.5\r\n"
    "   Subnet Mask . . . . . . . . . . . : 255.255.0.0\r\n"
)

IPCONFIG_LINK_LOCAL = (
    "Adaptador LAN inalámbrico Wi-Fi:\r\n"
    "\r\n"
    "   Dirección IPv4. . . . . . . . . . : 169.254.3.4\r\n"
    "   Máscara de subred . . . . . . . . : 255.255.0.0\r\n"
)

IP_ADDR_LINUX = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n"
    "    inet 127.0.0.1/8 scope host lo\r\n"
    "\r\n"
    "2: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n"
    "    inet 192.168.1.5/24 brd 192.168.1.255 "
    "scope global dynamic wlp3s0\r\n"
)

RUTA_LINUX = "default via 192.168.1.1 dev wlp3s0 proto dhcp metric 600\n"

ARP_WINDOWS = (
    "Interfaz: 192.168.1.5 --- 0x9\r\n"
    "  Dirección de Internet      Dirección física      Tipo\r\n"
    "  192.168.1.1                00-11-22-33-44-55     dinámico\r\n"
    "  192.168.1.50               B8-27-EB-11-22-33     dinámico\r\n"
    "  192.168.1.255              FF-FF-FF-FF-FF-FF     estático\r\n"
    "\r\n"
    "Interface: 10.0.0.5 --- 0xa\r\n"
    "  Internet Address      Physical Address      Type\r\n"
    "  10.0.0.1              00-1B-21-AA-BB-CC     dynamic\r\n"
    "  10.0.0.2              00-05-5D-01-02-03     static\r\n"
)

ARP_LINUX = (
    "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on wlp3s0\n"
    "? (192.168.1.50) at B8:27:EB:11:22:33 [ether] on wlp3s0\n"
    "? (192.168.1.60) at <incomplete> on wlp3s0\n"
)


def respuesta(texto: str, codigo: int = 0, codificacion: str = "utf-8"):
    return subprocess.CompletedProcess("", codigo, texto.encode(codificacion), b"")


def test_leer_arp_windows_ignora_estaticos_y_normaliza_mac(monkeypatch):
    monkeypatch.setattr(arp_scanner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        arp_scanner.subprocess,
        "run",
        lambda args, **kwargs: respuesta(ARP_WINDOWS, codificacion="cp850"),
    )

    assert arp_scanner.leer_arp() == [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
        {"ip": "192.168.1.50", "mac": "B8:27:EB:11:22:33"},
        {"ip": "10.0.0.1", "mac": "00:1B:21:AA:BB:CC"},
    ]


def test_leer_arp_linux_descarta_incomplete(monkeypatch):
    monkeypatch.setattr(arp_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        arp_scanner.subprocess,
        "run",
        lambda args, **kwargs: respuesta(ARP_LINUX),
    )

    assert arp_scanner.leer_arp() == [
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
        {"ip": "192.168.1.50", "mac": "B8:27:EB:11:22:33"},
    ]


def test_ping_subred_windows_construye_comandos(monkeypatch):
    comandos = []

    def falso_run(args, **kwargs):
        comandos.append(list(args))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(arp_scanner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(arp_scanner.subprocess, "run", falso_run)

    arp_scanner.ping_subred(
        ["192.168.1.1", "192.168.1.2"],
        timeout_ms=250,
        paralelo=2,
    )

    assert sorted(comandos) == sorted(
        [
            ["ping", "-n", "1", "-w", "250", "192.168.1.1"],
            ["ping", "-n", "1", "-w", "250", "192.168.1.2"],
        ]
    )


def test_ping_subred_linux_construye_comandos(monkeypatch):
    comandos = []

    def falso_run(args, **kwargs):
        comandos.append(list(args))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(arp_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(arp_scanner.subprocess, "run", falso_run)

    arp_scanner.ping_subred(["192.168.1.1"], timeout_ms=400, paralelo=1)

    assert comandos == [["ping", "-c", "1", "-W", "0.4", "192.168.1.1"]]


def test_get_red_local_calcula_rango(monkeypatch):
    monkeypatch.setattr(red_local.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        red_local.subprocess,
        "run",
        lambda args, **kwargs: respuesta(IPCONFIG_ES, codificacion="cp850"),
    )

    red = red_local.get_red_local()

    assert red["ip_local"] == "192.168.1.5"
    assert red["red"] == "192.168.1.0/24"
    assert red["rango_limitado"] is False
    assert len(red["rango"]) == 254
    assert red["rango"][0] == "192.168.1.1"
    assert red["rango"][-1] == "192.168.1.254"


def test_get_red_local_limita_red_mayor_a_24(monkeypatch):
    monkeypatch.setattr(red_local.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        red_local.subprocess,
        "run",
        lambda args, **kwargs: respuesta(IPCONFIG_LIMITADO),
    )

    red = red_local.get_red_local()

    assert red["ip_local"] == "10.0.0.5"
    assert red["red"] == "10.0.0.0/24"
    assert red["rango_limitado"] is True
    assert len(red["rango"]) == 254
    assert red["rango"][0] == "10.0.0.1"
    assert red["rango"][-1] == "10.0.0.254"


def test_get_red_local_linux_usa_interfaz_de_ruta_default(monkeypatch):
    def falso_run(args, **kwargs):
        if args[:2] == ["ip", "-4"]:
            return respuesta(IP_ADDR_LINUX)
        if args[:2] == ["ip", "route"]:
            return respuesta(RUTA_LINUX)
        return respuesta("")

    monkeypatch.setattr(red_local.platform, "system", lambda: "Linux")
    monkeypatch.setattr(red_local.subprocess, "run", falso_run)

    red = red_local.get_red_local()

    assert red["ip_local"] == "192.168.1.5"
    assert red["red"] == "192.168.1.0/24"
    assert red["rango_limitado"] is False


def test_get_red_local_ignora_link_local(monkeypatch):
    monkeypatch.setattr(red_local.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        red_local.subprocess,
        "run",
        lambda args, **kwargs: respuesta(IPCONFIG_LINK_LOCAL, codificacion="cp850"),
    )

    assert red_local.get_red_local() is None


def test_scan_dispositivos_cruza_y_descarta(monkeypatch):
    rango = ["192.168.1.1", "192.168.1.5", "192.168.1.50", "192.168.1.99"]
    red = {
        "ip_local": "192.168.1.5",
        "red": "192.168.1.0/24",
        "rango": rango,
        "rango_limitado": False,
    }
    llamadas = []

    monkeypatch.setattr(arp_scanner, "get_red_local", lambda: red)
    monkeypatch.setattr(
        arp_scanner,
        "ping_subred",
        lambda valores: llamadas.append(list(valores)),
    )
    monkeypatch.setattr(
        arp_scanner,
        "leer_arp",
        lambda: [
            {"ip": "192.168.1.1", "mac": "00-E0-4C-11-22-33"},
            {"ip": "192.168.1.5", "mac": "00-AA-BB-CC-DD-EE"},
            {"ip": "192.168.1.50", "mac": "B8:27:EB:11:22:33"},
            {"ip": "192.168.1.255", "mac": "FF:FF:FF:FF:FF:FF"},
            {"ip": "192.168.1.60", "mac": "01:00:5E:00:00:01"},
            {"ip": "10.0.0.1", "mac": "00:1B:21:AA:BB:CC"},
        ],
    )

    assert arp_scanner.scan_dispositivos() == [
        {
            "ip": "192.168.1.1",
            "mac": "00:E0:4C:11:22:33",
            "fabricante": "REALTEK SEMICONDUCTOR",
            "es_este_equipo": False,
        },
        {
            "ip": "192.168.1.5",
            "mac": "00:AA:BB:CC:DD:EE",
            "fabricante": "Desconocido",
            "es_este_equipo": True,
        },
        {
            "ip": "192.168.1.50",
            "mac": "B8:27:EB:11:22:33",
            "fabricante": "Raspberry Pi Foundation",
            "es_este_equipo": False,
        },
    ]
    assert llamadas == [rango]


def test_scan_dispositivos_sin_red_devuelve_vacio_y_no_pinguea(monkeypatch):
    def no_debe_llamar(*args, **kwargs):
        raise AssertionError("no se debe escanear sin red")

    monkeypatch.setattr(arp_scanner, "get_red_local", lambda: None)
    monkeypatch.setattr(arp_scanner, "ping_subred", no_debe_llamar)
    monkeypatch.setattr(arp_scanner, "leer_arp", no_debe_llamar)

    assert arp_scanner.scan_dispositivos() == []
