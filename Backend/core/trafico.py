from __future__ import annotations

import logging
import math
import platform
import re
import signal
import subprocess
import threading
import time
import unicodedata
from pathlib import Path

from core.oui import fabricante_de

_ESTADO_FORWARDING: dict | None = None
_INFO_DISPOSITIVOS: dict[str, dict] = {}
_MAC_LOCAL: str | None = None


def _a_texto(salida: object) -> str:
    if isinstance(salida, (bytes, bytearray)):
        datos = bytes(salida)
        for codificacion in ("utf-8", "cp850", "cp437"):
            try:
                return datos.decode(codificacion)
            except UnicodeDecodeError:
                continue
        return datos.decode("cp437", errors="replace")
    return str(salida or "")


def _clave(valor: object) -> str:
    texto = unicodedata.normalize("NFKD", str(valor or ""))
    texto = texto.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", " ", texto).strip()


def _preparar_envio_silencioso() -> None:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    try:
        from scapy.all import conf

        conf.verb = 0
    except Exception:
        pass


def registrar_dispositivos(dispositivos: list[dict]) -> None:
    global _INFO_DISPOSITIVOS
    info: dict[str, dict] = {}
    for dispositivo in dispositivos or []:
        ip = str(dispositivo.get("ip") or "").strip()
        if not ip:
            continue
        mac = str(dispositivo.get("mac") or "").strip()
        info[ip] = {
            "mac": mac,
            "fabricante": str(dispositivo.get("fabricante") or "")
            or fabricante_de(mac),
            "es_este_equipo": bool(dispositivo.get("es_este_equipo")),
        }
    _INFO_DISPOSITIVOS = info


def obtener_mac(ip: str) -> str | None:
    try:
        from scapy.all import ARP, Ether, srp

        _preparar_envio_silencioso()
        respuesta, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2,
            verbose=0,
        )
        if respuesta:
            return str(respuesta[0][1].hwsrc)
    except Exception:
        return None
    return None


def _mac_local() -> str:
    global _MAC_LOCAL
    if _MAC_LOCAL:
        return _MAC_LOCAL
    try:
        from scapy.all import conf, get_if_hwaddr

        _MAC_LOCAL = str(get_if_hwaddr(conf.iface))
    except Exception:
        _MAC_LOCAL = "00:00:00:00:00:00"
    return _MAC_LOCAL


def habilitar_ip_forwarding() -> bool:
    global _ESTADO_FORWARDING
    if platform.system() != "Windows":
        ruta = Path("/proc/sys/net/ipv4/ip_forward")
        try:
            anterior = ruta.read_text(encoding="ascii").strip()
        except OSError:
            _ESTADO_FORWARDING = {"cambiar": False}
            return False
        if anterior == "1":
            _ESTADO_FORWARDING = {"cambiar": False, "anterior": anterior}
            return True
        try:
            ruta.write_text("1", encoding="ascii")
        except OSError:
            _ESTADO_FORWARDING = {"cambiar": False}
            return False
        _ESTADO_FORWARDING = {"cambiar": True, "anterior": anterior}
        return True

    try:
        import winreg

        ruta_registro = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        clave = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            ruta_registro,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        )
        try:
            try:
                anterior, tipo = winreg.QueryValueEx(clave, "IPEnableRouter")
                existia = True
            except FileNotFoundError:
                anterior, tipo, existia = 0, winreg.REG_DWORD, False
            if anterior == 1:
                _ESTADO_FORWARDING = {"cambiar": False}
                return True
            winreg.SetValueEx(clave, "IPEnableRouter", 0, tipo, 1)
            _ESTADO_FORWARDING = {
                "cambiar": True,
                "anterior": anterior,
                "tipo": tipo,
                "existia": existia,
            }
            return True
        finally:
            winreg.CloseKey(clave)
    except Exception:
        _ESTADO_FORWARDING = {"cambiar": False}
        return False


def deshabilitar_ip_forwarding() -> None:
    global _ESTADO_FORWARDING
    estado = _ESTADO_FORWARDING
    if not estado or not estado.get("cambiar"):
        _ESTADO_FORWARDING = None
        return

    try:
        if platform.system() == "Windows":
            import winreg

            ruta_registro = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            clave = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                ruta_registro,
                0,
                winreg.KEY_WRITE,
            )
            try:
                if estado.get("existia"):
                    winreg.SetValueEx(
                        clave,
                        "IPEnableRouter",
                        0,
                        estado["tipo"],
                        estado["anterior"],
                    )
                else:
                    winreg.DeleteValue(clave, "IPEnableRouter")
            finally:
                winreg.CloseKey(clave)
        else:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(
                str(estado.get("anterior", "0")),
                encoding="ascii",
            )
    except Exception:
        pass
    finally:
        _ESTADO_FORWARDING = None


def spoof(ip_objetivo: str, ip_simular: str, mac_objetivo: str) -> None:
    from scapy.all import ARP, send

    _preparar_envio_silencioso()
    send(
        ARP(
            op=2,
            pdst=ip_objetivo,
            hwdst=mac_objetivo,
            psrc=ip_simular,
            hwsrc=_mac_local(),
        ),
        verbose=0,
    )


def restaurar_arp(
    ip_objetivo: str,
    ip_real: str,
    mac_real: str,
    ip_router: str,
    mac_router: str,
) -> None:
    from scapy.all import ARP, send

    _preparar_envio_silencioso()
    if mac_objetivo := str(mac_real or "").strip():
        try:
            send(
                ARP(
                    op=2,
                    pdst=ip_objetivo,
                    hwdst=mac_objetivo,
                    psrc=ip_router,
                    hwsrc=mac_router,
                ),
                count=2,
                verbose=0,
            )
        except Exception:
            pass

    if mac_router and mac_objetivo:
        try:
            send(
                ARP(
                    op=2,
                    pdst=ip_router,
                    hwdst=mac_router,
                    psrc=ip_real,
                    hwsrc=mac_objetivo,
                ),
                count=2,
                verbose=0,
            )
        except Exception:
            pass


def iniciar_spoofing(
    dispositivos: list[dict],
    router_ip: str,
    router_mac: str,
    intervalo=2,
):
    detener = threading.Event()

    def bucle() -> None:
        while not detener.is_set():
            try:
                for dispositivo in dispositivos or []:
                    ip = str(dispositivo.get("ip") or "").strip()
                    mac = str(dispositivo.get("mac") or "").strip()
                    if not ip or not mac:
                        continue
                    spoof(ip, router_ip, mac)
                    spoof(router_ip, ip, router_mac)
            except Exception:
                detener.set()
                break
            detener.wait(max(0.1, float(intervalo)))

    hilo = threading.Thread(target=bucle, daemon=True)
    hilo.start()
    return hilo, detener


def iniciar_captura(interfaz, ips_monitoreadas):
    from scapy.all import IP, sniff

    detener = threading.Event()
    monitoreadas = {str(ip) for ip in (ips_monitoreadas or [])}
    contador: dict[str, int] = {ip: 0 for ip in monitoreadas}
    bloqueo = threading.Lock()

    def procesar(paquete) -> None:
        if not paquete.haslayer(IP):
            return
        ip = str(paquete[IP].src)
        if ip not in monitoreadas:
            return
        with bloqueo:
            contador[ip] += len(paquete)

    def capturar() -> None:
        try:
            sniff(
                iface=interfaz,
                filter="ip",
                prn=procesar,
                store=False,
                stop_filter=lambda _: detener.is_set(),
            )
        except Exception:
            detener.set()

    hilo = threading.Thread(target=capturar, daemon=True)
    hilo.start()
    return hilo, detener, contador, bloqueo


def calcular_porcentajes(contador: dict) -> list[dict]:
    copia = {
        str(ip): max(0, int(bytes_))
        for ip, bytes_ in dict(contador or {}).items()
    }
    total = sum(copia.values())
    if total <= 0:
        return []

    participacion = {
        ip: (cantidad * 100 / total) for ip, cantidad in copia.items()
    }
    base = {ip: math.floor(valor) for ip, valor in participacion.items()}
    faltantes = 100 - sum(base.values())
    orden = sorted(
        copia,
        key=lambda ip: (
            -(participacion[ip] - base[ip]),
            -copia[ip],
            ip,
        ),
    )
    for ip in orden[:faltantes]:
        base[ip] += 1

    resultados = []
    for ip, cantidad in copia.items():
        info = _INFO_DISPOSITIVOS.get(ip, {})
        mac = str(info.get("mac") or "")
        resultados.append(
            {
                "ip": ip,
                "mac": mac,
                "fabricante": str(info.get("fabricante") or "")
                or fabricante_de(mac),
                "bytes": cantidad,
                "porcentaje": base[ip],
                "es_este_equipo": bool(info.get("es_este_equipo")),
            }
        )
    return sorted(resultados, key=lambda item: (-item["bytes"], item["ip"]))


def _interfaz_activa() -> str | None:
    try:
        from scapy.all import conf, get_if_list

        if getattr(conf, "iface", None):
            return str(conf.iface)
        interfaces = get_if_list()
        return str(interfaces[0]) if interfaces else None
    except Exception:
        return None


def _gateway_ip(rango: list[str]) -> str | None:
    texto = ""
    sistema = platform.system()
    try:
        if sistema == "Windows":
            resultado = subprocess.run(
                ["ipconfig"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        else:
            resultado = subprocess.run(
                ["ip", "route"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        texto = _a_texto(resultado.stdout)
    except Exception:
        texto = ""

    for linea in texto.splitlines():
        normalizada = _clave(linea)
        if sistema == "Windows":
            if "gateway" not in normalizada and "enlace predeterminada" not in normalizada:
                continue
        elif not normalizada.startswith("default"):
            continue
        encontrada = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", linea)
        if encontrada and (not rango or encontrada.group(0) in set(rango)):
            return encontrada.group(0)
    return rango[0] if rango else None


def monitorear(
    dispositivos: list[dict],
    router_ip: str,
    router_mac: str,
    intervalo=2,
    actualizar=None,
) -> list[dict]:
    registrados = list(dispositivos or [])
    spoofed = [
        dispositivo
        for dispositivo in registrados
        if not dispositivo.get("es_este_equipo")
        and str(dispositivo.get("ip") or "") != router_ip
        and str(dispositivo.get("mac") or "").strip()
    ]
    registrar_dispositivos(registrados)

    hilo_spoof = None
    hilo_captura = None
    detener_spoof = None
    detener_captura = None
    contador: dict[str, int] = {}
    bloqueo = threading.Lock()
    manejador_anterior = None

    def detener_todo(*_) -> None:
        if detener_spoof is not None:
            detener_spoof.set()
        if detener_captura is not None:
            detener_captura.set()

    try:
        if not habilitar_ip_forwarding():
            raise RuntimeError("No se pudo habilitar el reenvío IP")

        hilo_spoof, detener_spoof = iniciar_spoofing(
            spoofed,
            router_ip,
            router_mac,
            intervalo,
        )

        ips = {
            str(dispositivo.get("ip"))
            for dispositivo in registrados
            if dispositivo.get("ip")
        }
        hilo_captura, detener_captura, contador, bloqueo = iniciar_captura(
            _interfaz_activa(),
            ips,
        )

        try:
            manejador_anterior = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, detener_todo)
        except (ValueError, OSError):
            manejador_anterior = None

        while not detener_spoof.is_set() and not detener_captura.is_set():
            with bloqueo:
                copia = dict(contador)
            resultados = calcular_porcentajes(copia)
            if actualizar:
                actualizar(resultados)
            time.sleep(2)
    finally:
        detener_todo()
        for hilo in (hilo_captura, hilo_spoof):
            if hilo is not None:
                hilo.join(timeout=2)
        for dispositivo in spoofed:
            try:
                restaurar_arp(
                    str(dispositivo.get("ip") or ""),
                    str(dispositivo.get("ip") or ""),
                    str(dispositivo.get("mac") or ""),
                    router_ip,
                    router_mac,
                )
            except Exception:
                pass
        deshabilitar_ip_forwarding()
        if manejador_anterior is not None:
            try:
                signal.signal(signal.SIGINT, manejador_anterior)
            except (ValueError, OSError):
                pass

    with bloqueo:
        copia = dict(contador)
    return calcular_porcentajes(copia)
