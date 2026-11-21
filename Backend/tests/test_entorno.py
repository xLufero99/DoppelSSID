import io
import logging
import subprocess
import sys
import urllib.error
from types import ModuleType, SimpleNamespace

import pytest

from core import entorno


def test_es_administrador_windows(monkeypatch):
    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    windll = SimpleNamespace(
        shell32=SimpleNamespace(IsUserAnAdmin=lambda: 1)
    )
    monkeypatch.setattr(entorno.ctypes, "windll", windll, raising=False)
    assert entorno.es_administrador() is True

    windll = SimpleNamespace(
        shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0)
    )
    monkeypatch.setattr(entorno.ctypes, "windll", windll, raising=False)
    assert entorno.es_administrador() is False


def test_es_administrador_linux(monkeypatch):
    monkeypatch.setattr(entorno.platform, "system", lambda: "Linux")
    monkeypatch.setattr(entorno.os, "geteuid", lambda: 0, raising=False)
    assert entorno.es_administrador() is True
    monkeypatch.setattr(entorno.os, "geteuid", lambda: 1000, raising=False)
    assert entorno.es_administrador() is False


def test_npcap_instalado_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    carpeta = tmp_path / "Npcap"
    carpeta.mkdir()
    (carpeta / "wpcap.dll").write_bytes(b"dll")
    (carpeta / "packet.dll").write_bytes(b"dll")
    monkeypatch.setattr(entorno, "_ruta_npcap", lambda: carpeta)
    monkeypatch.setattr(entorno, "_scapy_sin_libpcap", lambda: False)
    assert entorno.npcap_instalado() is True

    (carpeta / "packet.dll").unlink()
    monkeypatch.setattr(entorno, "_scapy_sin_libpcap", lambda: True)
    assert entorno.npcap_instalado() is False

    monkeypatch.setattr(entorno, "_ruta_npcap", lambda: tmp_path / "ausente")
    monkeypatch.setattr(entorno, "_scapy_sin_libpcap", lambda: False)
    assert entorno.npcap_instalado() is False


def test_npcap_instalado_detecta_warning_de_scapy(monkeypatch, tmp_path):
    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    carpeta = tmp_path / "Npcap"
    carpeta.mkdir()
    (carpeta / "wpcap.dll").write_bytes(b"dll")
    (carpeta / "packet.dll").write_bytes(b"dll")
    monkeypatch.setattr(entorno, "_ruta_npcap", lambda: carpeta)
    monkeypatch.setattr(entorno, "_scapy_sin_libpcap", lambda: True)
    assert entorno.npcap_instalado() is False


def test_npcap_instalado_linux_no_aplica(monkeypatch):
    monkeypatch.setattr(entorno.platform, "system", lambda: "Linux")
    assert entorno.npcap_instalado() is True


def _preparar_scapy_falso(monkeypatch, usar_pcap=True, avisar=False):
    modulo_scapy = ModuleType("scapy")
    modulo_all = ModuleType("scapy.all")
    modulo_config = ModuleType("scapy.config")

    def get_if_list():
        if avisar:
            logging.getLogger("scapy.loading").warning(
                "No libpcap provider available ! pcap won't be used"
            )
        return []

    modulo_all.get_if_list = get_if_list
    modulo_config.conf = SimpleNamespace(use_pcap=usar_pcap)
    monkeypatch.setitem(sys.modules, "scapy", modulo_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", modulo_all)
    monkeypatch.setitem(sys.modules, "scapy.config", modulo_config)


def test_scapy_sin_libpcap_detecta_warning(monkeypatch):
    _preparar_scapy_falso(monkeypatch, usar_pcap=True, avisar=True)
    logger = logging.getLogger("scapy")
    manejadores = list(logger.handlers)

    assert entorno._scapy_sin_libpcap() is True
    assert logger.handlers == manejadores


def test_scapy_sin_libpcap_detecta_use_pcap_falso(monkeypatch):
    _preparar_scapy_falso(monkeypatch, usar_pcap=False, avisar=False)
    assert entorno._scapy_sin_libpcap() is True


def test_scapy_sin_libpcap_sin_senales(monkeypatch):
    _preparar_scapy_falso(monkeypatch, usar_pcap=True, avisar=False)
    assert entorno._scapy_sin_libpcap() is False


def test_descargar_e_instalar_npcap_exito(monkeypatch):
    pagina = b'<a href="https://npcap.com/dist/npcap-1.80.exe">Descargar</a>'

    def falso_urlopen(url, timeout=None):
        if url == entorno.PAGINA_NPCAP:
            return io.BytesIO(pagina)
        return io.BytesIO(b"MZinstalador")

    comandos = []

    def falso_run(args, **kwargs):
        comandos.append((list(args), kwargs))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    monkeypatch.setattr(entorno.urllib.request, "urlopen", falso_urlopen)
    monkeypatch.setattr(entorno.subprocess, "run", falso_run)
    monkeypatch.setattr(entorno, "npcap_instalado", lambda: True)

    assert entorno.descargar_e_instalar_npcap() is True
    assert len(comandos) == 1
    args, kwargs = comandos[0]
    assert args[0].lower().endswith(".exe")
    assert kwargs.get("check") is False
    assert all("silent" not in arg.lower() for arg in args)


def test_descargar_e_instalar_npcap_sin_internet(monkeypatch):
    def sin_red(url, timeout=None):
        raise urllib.error.URLError("sin internet")

    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    monkeypatch.setattr(entorno.urllib.request, "urlopen", sin_red)
    monkeypatch.setattr(
        entorno.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("no se debe instalar sin descarga"),
    )

    assert entorno.descargar_e_instalar_npcap() is False


def test_descargar_e_instalar_npcap_instalador_cancelado(monkeypatch):
    pagina = b'<a href="https://npcap.com/dist/npcap-1.80.exe">Descargar</a>'

    def falso_urlopen(url, timeout=None):
        if url == entorno.PAGINA_NPCAP:
            return io.BytesIO(pagina)
        return io.BytesIO(b"MZinstalador")

    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    monkeypatch.setattr(entorno.urllib.request, "urlopen", falso_urlopen)
    monkeypatch.setattr(
        entorno.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, b"", b""),
    )
    monkeypatch.setattr(entorno, "npcap_instalado", lambda: False)

    assert entorno.descargar_e_instalar_npcap() is False


def test_descargar_e_instalar_npcap_fallback_manual(monkeypatch):
    abiertos = []

    monkeypatch.setattr(entorno.platform, "system", lambda: "Windows")
    monkeypatch.setattr(entorno, "_resolver_url_npcap", lambda: "")
    monkeypatch.setattr(entorno.webbrowser, "open", abiertos.append)
    monkeypatch.setattr("builtins.input", lambda mensaje="": "")
    monkeypatch.setattr(entorno, "npcap_instalado", lambda: True)

    assert entorno.descargar_e_instalar_npcap() is True
    assert abiertos == [entorno.PAGINA_NPCAP]
