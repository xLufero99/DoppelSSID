from __future__ import annotations

import ctypes
import html as html_mod
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

PAGINA_NPCAP = "https://npcap.com/#download"


def es_administrador() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _ruta_npcap() -> Path:
    return Path(r"C:\Windows\System32\Npcap")


def _npcap_en_equipo() -> bool:
    carpeta = _ruta_npcap()
    if not carpeta.is_dir():
        return False
    return all((carpeta / nombre).is_file() for nombre in ("wpcap.dll", "packet.dll"))


def _scapy_sin_libpcap() -> bool:
    mensajes: list[str] = []

    class Capturador(logging.Handler):
        def emit(self, registro: logging.LogRecord) -> None:
            mensajes.append(registro.getMessage())

    logger_carga = logging.getLogger("scapy.loading")
    logger_scapy = logging.getLogger("scapy")
    capturador = Capturador()
    manejadores = list(logger_scapy.handlers)
    agregar_manejador = logger_scapy.addHandler
    nivel = logger_carga.level

    logger_carga.addHandler(capturador)
    logger_carga.setLevel(logging.WARNING)
    logger_scapy.handlers = []
    logger_scapy.addHandler = lambda manejador: None
    try:
        from scapy.all import get_if_list
        from scapy.config import conf

        get_if_list()
        aviso = any(
            "no libpcap provider available" in mensaje.lower()
            or "pcap won't be used" in mensaje.lower()
            for mensaje in mensajes
        )
        return aviso or getattr(conf, "use_pcap", True) is False
    except Exception:
        return True
    finally:
        logger_scapy.addHandler = agregar_manejador
        logger_scapy.handlers = manejadores
        logger_carga.removeHandler(capturador)
        logger_carga.setLevel(nivel)


def npcap_instalado() -> bool:
    if platform.system() != "Windows":
        return True
    if not _npcap_en_equipo():
        return False
    return not _scapy_sin_libpcap()


def _resolver_url_npcap() -> str:
    with urllib.request.urlopen(PAGINA_NPCAP, timeout=10) as respuesta:
        pagina = respuesta.read().decode("utf-8", errors="replace")

    coincidencia = re.search(
        r"https?://[^\"'\s<>]+npcap[^\"'\s<>]*\.exe",
        pagina,
        re.I,
    )
    if coincidencia:
        return html_mod.unescape(coincidencia.group(0))

    coincidencia = re.search(
        r"(?:href|src)=[\"']([^\"']+\.exe)[\"']",
        pagina,
        re.I,
    )
    if coincidencia:
        relativa = html_mod.unescape(coincidencia.group(1))
        return urllib.parse.urljoin("https://npcap.com/", relativa)
    return ""


def _descargar_exe(url: str) -> Path:
    with tempfile.NamedTemporaryFile(
        prefix="npcap-",
        suffix=".exe",
        delete=False,
    ) as temporal:
        with urllib.request.urlopen(url, timeout=30) as respuesta:
            shutil.copyfileobj(respuesta, temporal)
        return Path(temporal.name)


def descargar_e_instalar_npcap() -> bool:
    if platform.system() != "Windows":
        return True

    print("Buscando el instalador oficial de Npcap...")
    try:
        url = _resolver_url_npcap()
    except Exception as error:
        print(f"No se pudo acceder a {PAGINA_NPCAP}: {error}")
        print(f"Sin internet no se puede descargar. Instálalo manualmente desde {PAGINA_NPCAP}.")
        return False

    if not url:
        print("No pude resolver automáticamente la URL del instalador más reciente.")
        print(f"Abriré {PAGINA_NPCAP} para que lo descargues manualmente.")
        try:
            webbrowser.open(PAGINA_NPCAP)
        except Exception:
            print(f"Ábrelo manualmente: {PAGINA_NPCAP}")
        try:
            input("Cuando termines de instalar Npcap, presiona Enter para continuar: ")
        except EOFError:
            pass
        return npcap_instalado()

    try:
        ruta = _descargar_exe(url)
    except Exception as error:
        print(f"No se pudo descargar Npcap: {error}")
        print(f"Instálalo manualmente desde {PAGINA_NPCAP}.")
        return False

    try:
        print("Abriendo el instalador oficial de Npcap; acepta la licencia en la ventana.")
        subprocess.run([str(ruta)], check=False)
    except Exception as error:
        print(f"No se pudo ejecutar el instalador: {error}")
        print(f"Instálalo manualmente desde {PAGINA_NPCAP}.")
        return False
    finally:
        try:
            ruta.unlink(missing_ok=True)
        except OSError:
            pass

    if not npcap_instalado():
        print(f"Npcap sigue sin detectarse. Instálalo manualmente desde {PAGINA_NPCAP}.")
        return False
    return True
