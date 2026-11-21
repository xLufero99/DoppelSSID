import io
import logging
import sys
from types import ModuleType, SimpleNamespace

import pytest
from rich.console import Console

import main
from core import entorno, trafico


class EventoFalso:
    def __init__(self):
        self.estado = False

    def set(self):
        self.estado = True

    def is_set(self):
        return self.estado

    def wait(self, timeout=None):
        return self.estado


class HiloFalso:
    def join(self, timeout=None):
        return None


def consola_prueba(salida=None):
    return Console(file=salida if salida is not None else io.StringIO(), width=100)


def test_advertencia_inicial_requiere_confirmacion_y_guarda_marcador(monkeypatch, tmp_path):
    ruta = tmp_path / "data" / ".advertencia_aceptada"
    monkeypatch.setattr(main, "RUTA_ADVERTENCIA", ruta)

    respuestas = iter(["n"])
    monkeypatch.setattr("builtins.input", lambda mensaje="": next(respuestas))
    with pytest.raises(SystemExit) as salida:
        main._advertencia_inicial(consola_prueba())
    assert salida.value.code == 0
    assert not ruta.exists()

    respuestas = iter(["s"])
    monkeypatch.setattr("builtins.input", lambda mensaje="": next(respuestas))
    main._advertencia_inicial(consola_prueba())
    assert ruta.exists()

    def no_preguntar(mensaje=""):
        raise AssertionError("no debe repetir la advertencia")

    monkeypatch.setattr("builtins.input", no_preguntar)
    main._advertencia_inicial(consola_prueba())


def test_calcular_porcentajes_ordena_y_suma_cien(monkeypatch):
    dispositivos = [
        {
            "ip": "192.168.1.10",
            "mac": "00:E0:4C:11:22:33",
            "fabricante": "REALTEK SEMICONDUCTOR",
            "es_este_equipo": False,
        },
        {
            "ip": "192.168.1.20",
            "mac": "B8:27:EB:00:00:01",
            "fabricante": "Raspberry Pi Foundation",
            "es_este_equipo": False,
        },
        {
            "ip": "192.168.1.5",
            "mac": "00:AA:BB:00:00:01",
            "fabricante": "Desconocido",
            "es_este_equipo": True,
        },
    ]
    monkeypatch.setattr(trafico, "_INFO_DISPOSITIVOS", {})
    trafico.registrar_dispositivos(dispositivos)

    resultados = trafico.calcular_porcentajes(
        {
            "192.168.1.10": 500,
            "192.168.1.20": 300,
            "192.168.1.5": 200,
        }
    )

    assert [item["ip"] for item in resultados] == [
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.5",
    ]
    assert [item["porcentaje"] for item in resultados] == [50, 30, 20]
    assert [item["bytes"] for item in resultados] == [500, 300, 200]
    assert sum(item["porcentaje"] for item in resultados) == 100
    assert resultados[0]["fabricante"] == "REALTEK SEMICONDUCTOR"
    assert resultados[-1]["es_este_equipo"] is True


def test_calcular_porcentajes_reparte_redondeo():
    resultados = trafico.calcular_porcentajes({"a": 1, "b": 1, "c": 1})
    assert sum(item["porcentaje"] for item in resultados) == 100
    assert sorted(item["porcentaje"] for item in resultados) == [33, 33, 34]


def test_calcular_porcentajes_usa_oui_cuando_falta_fabricante(monkeypatch):
    monkeypatch.setattr(trafico, "_INFO_DISPOSITIVOS", {})
    monkeypatch.setattr(trafico, "fabricante_de", lambda mac: "Fabricante Oui")
    trafico.registrar_dispositivos(
        [{"ip": "192.168.1.70", "mac": "00:E0:4C:00:00:70"}]
    )

    assert trafico.calcular_porcentajes({"192.168.1.70": 10})[0]["fabricante"] == (
        "Fabricante Oui"
    )


def test_restaurar_arp_en_finally_si_captura_falla(monkeypatch):
    dispositivos = [
        {
            "ip": "192.168.1.10",
            "mac": "00:11:22:33:44:55",
            "fabricante": "Desconocido",
            "es_este_equipo": False,
        },
        {
            "ip": "192.168.1.5",
            "mac": "00:AA:BB:00:00:01",
            "fabricante": "Desconocido",
            "es_este_equipo": True,
        },
    ]
    llamadas = []

    monkeypatch.setattr(
        trafico,
        "registrar_dispositivos",
        lambda valores: llamadas.append(("registrar", valores)),
    )
    monkeypatch.setattr(
        trafico,
        "habilitar_ip_forwarding",
        lambda: llamadas.append(("habilitar",)) or True,
    )
    monkeypatch.setattr(
        trafico,
        "iniciar_spoofing",
        lambda *args: (HiloFalso(), EventoFalso()),
    )

    def captura_falla(*args, **kwargs):
        raise RuntimeError("captura rota")

    monkeypatch.setattr(trafico, "_interfaz_activa", lambda: "eth0")
    monkeypatch.setattr(trafico, "iniciar_captura", captura_falla)
    monkeypatch.setattr(
        trafico,
        "restaurar_arp",
        lambda *args: llamadas.append(("restaurar", args)),
    )
    monkeypatch.setattr(
        trafico,
        "deshabilitar_ip_forwarding",
        lambda: llamadas.append(("deshabilitar",)),
    )
    monkeypatch.setattr(trafico.signal, "getsignal", lambda *_: None)
    monkeypatch.setattr(trafico.signal, "signal", lambda *_: None)

    with pytest.raises(RuntimeError, match="captura rota"):
        trafico.monitorear(dispositivos, "192.168.1.1", "AA:BB:CC:DD:EE:FF")

    restauraciones = [
        datos[1] for datos in llamadas if len(datos) == 2 and datos[0] == "restaurar"
    ]
    assert len(restauraciones) == 1
    assert restauraciones[0][0] == "192.168.1.10"
    assert llamadas[-1] == ("deshabilitar",)


def test_flujo_trafico_confirmacion_n_no_toca_red(monkeypatch):
    entradas = iter(["n"])
    monkeypatch.setattr("builtins.input", lambda mensaje="": next(entradas))
    monkeypatch.setattr(main, "es_administrador", lambda: True)
    monkeypatch.setattr(main, "npcap_instalado", lambda: True)
    monkeypatch.setattr(
        main,
        "get_red_local",
        lambda: pytest.fail("no se debe buscar red"),
    )
    monkeypatch.setattr(
        main,
        "scan_dispositivos",
        lambda: pytest.fail("no se deben escanear dispositivos"),
    )
    monkeypatch.setattr(
        main,
        "monitorear",
        lambda *args, **kwargs: pytest.fail("no se debe monitorear"),
    )
    monkeypatch.setattr(
        trafico,
        "habilitar_ip_forwarding",
        lambda: pytest.fail("no se debe habilitar forwarding"),
    )
    monkeypatch.setattr(
        trafico,
        "spoof",
        lambda *args: pytest.fail("no se debe hacer spoof"),
    )
    monkeypatch.setattr(
        trafico,
        "iniciar_captura",
        lambda *args, **kwargs: pytest.fail("no se debe capturar"),
    )

    main._flujo_trafico(consola_prueba())


def test_flujo_trafico_sin_npcap_cae_a_modo_limitado(monkeypatch):
    entradas = iter(["n"])
    monkeypatch.setattr("builtins.input", lambda mensaje="": next(entradas))
    monkeypatch.setattr(main, "es_administrador", lambda: True)
    monkeypatch.setattr(main.platform, "system", lambda: "Windows")
    monkeypatch.setattr(main, "npcap_instalado", lambda: False)
    monkeypatch.setattr(
        main,
        "descargar_e_instalar_npcap",
        lambda: pytest.fail("el usuario rechazó la instalación"),
    )

    llamadas = []

    def consumo(duracion=10):
        llamadas.append(duracion)
        return {
            "bytes_enviados": 10,
            "bytes_recibidos": 20,
            "bytes_totales": 30,
            "kb_s": 0.03,
        }

    monkeypatch.setattr(main, "medir_consumo_propio", consumo)
    monkeypatch.setattr(
        main,
        "monitorear",
        lambda *args, **kwargs: pytest.fail("no se debe monitorear"),
    )
    monkeypatch.setattr(
        trafico,
        "habilitar_ip_forwarding",
        lambda: pytest.fail("no se debe habilitar forwarding"),
    )
    monkeypatch.setattr(
        trafico,
        "spoof",
        lambda *args: pytest.fail("no se debe hacer spoof"),
    )
    monkeypatch.setattr(
        trafico,
        "iniciar_captura",
        lambda *args, **kwargs: pytest.fail("no se debe capturar"),
    )

    main._flujo_trafico(consola_prueba())

    assert llamadas == [10]


def test_flujo_trafico_sin_npcap_no_toca_scapy_ni_red(monkeypatch, tmp_path):
    monkeypatch.setattr(main.platform, "system", lambda: "Windows")
    monkeypatch.setattr(entorno, "_ruta_npcap", lambda: tmp_path / "NpcapAusente")
    monkeypatch.setattr(
        entorno,
        "_scapy_sin_libpcap",
        lambda: pytest.fail("no se debe importar Scapy"),
    )
    monkeypatch.setattr(main, "npcap_instalado", entorno.npcap_instalado)
    monkeypatch.setattr(main, "es_administrador", lambda: True)

    respuestas = iter(["n"])

    def responder(mensaje=""):
        if mensaje.startswith("¿Deseas descargarlo"):
            return next(respuestas)
        pytest.fail(f"prompt inesperado: {mensaje}")

    monkeypatch.setattr("builtins.input", responder)

    consumos = []

    def consumo(duracion=10):
        consumos.append(duracion)
        return {
            "bytes_enviados": 10,
            "bytes_recibidos": 20,
            "bytes_totales": 30,
            "kb_s": 0.03,
        }

    monkeypatch.setattr(main, "medir_consumo_propio", consumo)

    def prohibir(nombre):
        def fallo(*args, **kwargs):
            pytest.fail(f"no se debe llamar {nombre}")

        return fallo

    for modulo, nombre in (
        (main, "obtener_mac"),
        (main, "_gateway_ip"),
        (main, "get_red_local"),
        (main, "scan_dispositivos"),
        (main, "monitorear"),
        (main, "descargar_e_instalar_npcap"),
        (trafico, "habilitar_ip_forwarding"),
        (trafico, "spoof"),
        (trafico, "iniciar_captura"),
        (trafico, "iniciar_spoofing"),
        (trafico, "restaurar_arp"),
    ):
        monkeypatch.setattr(modulo, nombre, prohibir(nombre), raising=False)

    salida = io.StringIO()
    main._flujo_trafico(consola_prueba(salida))

    texto = salida.getvalue()
    assert "No tienes Npcap instalado" in texto
    assert "¿Es esta tu propia red" not in texto
    assert consumos == [10]


def test_envios_arp_configuran_scapy_silencioso(monkeypatch):
    envios = []
    conf = SimpleNamespace(verb=1, iface="eth0")

    class ARP:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def enviar(paquete, **kwargs):
        envios.append((paquete, kwargs))

    modulo_scapy = ModuleType("scapy")
    modulo_all = ModuleType("scapy.all")
    modulo_all.ARP = ARP
    modulo_all.send = enviar
    modulo_all.conf = conf
    modulo_all.get_if_hwaddr = lambda interfaz: "AA:BB:CC:DD:EE:FF"
    monkeypatch.setitem(sys.modules, "scapy", modulo_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", modulo_all)
    monkeypatch.setattr(trafico, "_MAC_LOCAL", None)

    logger = logging.getLogger("scapy.runtime")
    nivel = logger.level
    try:
        trafico.spoof("192.168.1.10", "192.168.1.1", "00:11:22:33:44:55")
        trafico.restaurar_arp(
            "192.168.1.10",
            "192.168.1.10",
            "00:11:22:33:44:55",
            "192.168.1.1",
            "AA:BB:CC:DD:EE:FF",
        )
        assert conf.verb == 0
        assert logger.level == logging.ERROR
    finally:
        logger.setLevel(nivel)

    assert len(envios) == 3
    assert all(kwargs.get("verbose") == 0 for _, kwargs in envios)


def test_flujo_trafico_tabla_en_vivo_sin_warnings(monkeypatch):
    monkeypatch.setattr(main, "es_administrador", lambda: True)
    monkeypatch.setattr(main, "npcap_instalado", lambda: True)
    monkeypatch.setattr("builtins.input", lambda mensaje="": "s")
    monkeypatch.setattr(
        main,
        "get_red_local",
        lambda: {"rango": ["192.168.0.1", "192.168.0.10"]},
    )
    dispositivos = [
        {
            "ip": "192.168.0.10",
            "mac": "00:E0:4C:11:22:33",
            "fabricante": "REALTEK SEMICONDUCTOR",
            "es_este_equipo": False,
        }
    ]
    monkeypatch.setattr(main, "scan_dispositivos", lambda: dispositivos)
    monkeypatch.setattr(main, "_gateway_ip", lambda rango: "192.168.0.1")
    monkeypatch.setattr(main, "obtener_mac", lambda ip: "AA:BB:CC:DD:EE:FF")

    resultados = [
        {
            "ip": "192.168.0.10",
            "mac": "00:E0:4C:11:22:33",
            "fabricante": "REALTEK SEMICONDUCTOR",
            "bytes": 1024,
            "porcentaje": 100,
            "es_este_equipo": False,
        }
    ]

    def monitorear_falso(dispositivos, router_ip, router_mac, intervalo=2, actualizar=None):
        if actualizar:
            actualizar(resultados)
        return resultados

    monkeypatch.setattr(main, "monitorear", monitorear_falso)

    salida = io.StringIO()
    main._flujo_trafico(consola_prueba(salida))

    texto = salida.getvalue()
    assert "192.168.0.10" in texto
    assert "100" in texto
    assert "WARNING" not in texto
