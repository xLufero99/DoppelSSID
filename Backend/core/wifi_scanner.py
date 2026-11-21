from __future__ import annotations

import platform
import re
import subprocess
import time
import unicodedata

NETSH_ARGS = ["netsh", "wlan", "show", "networks", "mode=bssid"]
NMCLI_ARGS = [
    "nmcli",
    "-t",
    "-f",
    "SSID,BSSID,CHAN,SIGNAL,SECURITY",
    "dev",
    "wifi",
    "list",
    "--rescan",
    "yes",
]
TIMEOUT = 15

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_SSID_NUM_RE = re.compile(r"^ssid\s+\d+$")
_BSSID_NUM_RE = re.compile(r"^bssid\s+\d+$")

_ETIQUETAS = {
    "ssid": "ssid",
    "bssid": "bssid",
    "autenticacion": "autenticacion",
    "authentication": "autenticacion",
    "autenticaci├│n": "autenticacion",
    "cifrado": "cifrado",
    "encryption": "cifrado",
    "senal": "senal",
    "se├▒al": "senal",
    "signal": "senal",
    "canal": "canal",
    "channel": "canal",
    "banda": "banda",
    "band": "banda",
    "estaciones conectadas": "estaciones",
    "station count": "estaciones",
    "uso del canal": "uso_canal",
    "channel utilization": "uso_canal",
}


def _normalizar_texto(texto: object) -> str:
    texto = str(texto or "").replace("\xa0", " ").lower()
    descompuesto = unicodedata.normalize("NFKD", texto)
    return "".join(
        caracter for caracter in descompuesto if not unicodedata.combining(caracter)
    )


def _clave_etiqueta(etiqueta: str) -> str | None:
    normalizada = _normalizar_texto(etiqueta).strip()
    if _SSID_NUM_RE.fullmatch(normalizada) is not None:
        return "ssid"
    if _BSSID_NUM_RE.fullmatch(normalizada) is not None:
        return "bssid"
    return _ETIQUETAS.get(normalizada)


def _limitar(valor: int, minimo: int, maximo: int) -> int:
    return max(minimo, min(maximo, valor))


def _primer_entero(valor: object, defecto: int | None = None) -> int | None:
    coincidencia = re.search(r"-?\d+", str(valor or ""))
    if coincidencia is None:
        return defecto
    return int(coincidencia.group())


def _parse_senal(valor: object) -> int:
    numero = _primer_entero(valor, 0)
    return _limitar(numero if numero is not None else 0, 0, 100)


def _parse_uso_canal(valor: object) -> int | None:
    texto = str(valor or "")
    coincidencia = re.search(r"\(\s*(\d+)\s*%?\s*\)", texto)
    if coincidencia is None:
        coincidencia = re.search(r"(\d+)\s*%", texto)
    if coincidencia is None:
        return None
    return _limitar(int(coincidencia.group(1)), 0, 100)


def _parse_banda(valor: object) -> str:
    texto = str(valor or "").replace("\xa0", " ").replace("┬á", " ")
    texto = texto.replace(",", ".")
    return re.sub(r"\s+", " ", texto).strip()


def _decode_netsh(salida: bytes) -> str:
    try:
        return salida.decode("utf-8")
    except UnicodeDecodeError:
        return salida.decode("cp850", errors="replace")


def _a_texto(salida: object) -> str:
    if isinstance(salida, (bytes, bytearray)):
        return _decode_netsh(bytes(salida))
    return str(salida or "")


def _nueva_red(ssid: str, bssid: str, meta_ssid: dict) -> dict:
    return {
        "ssid": ssid.strip() or "<oculta>",
        "bssid": bssid.strip().upper(),
        "canal": 0,
        "senal": 0,
        "banda": "",
        "autenticacion": str(meta_ssid.get("autenticacion", "")).strip(),
        "cifrado": str(meta_ssid.get("cifrado", "")).strip(),
        "estaciones": None,
        "uso_canal": None,
    }


def parse_netsh(texto: str) -> list[dict]:
    redes: list[dict] = []
    ssid_actual: str | None = None
    entrada_actual: dict | None = None
    meta_ssid: dict = {}

    def volcar() -> None:
        nonlocal entrada_actual
        if entrada_actual is not None:
            redes.append(entrada_actual)
            entrada_actual = None

    for linea in texto.splitlines():
        izquierda, separador, derecho = linea.partition(":")
        if not separador:
            continue

        clave = _clave_etiqueta(izquierda)
        if clave is None:
            continue

        valor = derecho.strip()

        if clave == "ssid":
            volcar()
            ssid_actual = valor
            meta_ssid = {}
            continue

        if clave == "bssid":
            if ssid_actual is None or _MAC_RE.fullmatch(valor.upper()) is None:
                continue
            volcar()
            entrada_actual = _nueva_red(ssid_actual, valor, meta_ssid)
            continue

        if clave in ("autenticacion", "cifrado"):
            meta_ssid[clave] = valor
            ssid_normalizado = (ssid_actual or "").strip() or "<oculta>"
            for red in redes:
                if red["ssid"] == ssid_normalizado:
                    red[clave] = valor
            if entrada_actual is not None:
                entrada_actual[clave] = valor
            continue

        if entrada_actual is None:
            continue

        if clave == "senal":
            entrada_actual["senal"] = _parse_senal(valor)
        elif clave == "canal":
            numero = _primer_entero(valor, 0)
            entrada_actual["canal"] = numero if numero is not None else 0
        elif clave == "banda":
            entrada_actual["banda"] = _parse_banda(valor)
        elif clave == "estaciones":
            entrada_actual["estaciones"] = _primer_entero(valor)
        elif clave == "uso_canal":
            entrada_actual["uso_canal"] = _parse_uso_canal(valor)

    volcar()
    return redes


def _dividir_nmcli(linea: str) -> list[str]:
    texto = linea.replace("\\\\", "\x01").replace("\\:", "\x00")
    partes = texto.rsplit(":", 3)
    if len(partes) != 4:
        return []

    prefijo, canal, senal, seguridad = partes
    prefijo = prefijo.replace("\x00", ":")
    coincidencia = re.match(
        r"^(.*):((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$", prefijo
    )
    if coincidencia is None:
        return []

    ssid = coincidencia.group(1).replace("\x00", ":").replace("\x01", "\\")
    return [ssid, coincidencia.group(2), canal, senal, seguridad]


def parse_nmcli(texto: str) -> list[dict]:
    redes: list[dict] = []

    for linea in texto.splitlines():
        if not linea.strip():
            continue

        partes = _dividir_nmcli(linea.strip())
        if len(partes) < 5:
            continue

        ssid, bssid, canal, senal, seguridad = partes[:5]
        bssid = bssid.strip().upper()
        if _MAC_RE.fullmatch(bssid) is None:
            continue

        ssid = ssid.strip()
        if not ssid or ssid == "--":
            ssid = "<oculta>"

        seguridad = seguridad.strip()
        if seguridad == "--":
            seguridad = "abierta"

        numero_canal = _primer_entero(canal, 0)
        redes.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "canal": numero_canal if numero_canal is not None else 0,
                "senal": _parse_senal(senal),
                "banda": "",
                "autenticacion": seguridad,
                "cifrado": "",
                "estaciones": None,
                "uso_canal": None,
            }
        )

    return redes


def scan_networks() -> list[dict]:
    sistema = platform.system()

    try:
        if sistema == "Windows":
            resultado = subprocess.run(
                NETSH_ARGS, capture_output=True, timeout=TIMEOUT, check=False
            )
            if resultado.returncode != 0:
                return []
            return parse_netsh(_a_texto(resultado.stdout))

        if sistema == "Linux":
            resultado = subprocess.run(
                NMCLI_ARGS, capture_output=True, timeout=TIMEOUT, check=False
            )
            if resultado.returncode != 0:
                return []
            return parse_nmcli(_a_texto(resultado.stdout))
    except Exception:
        return []

    return []


def group_by_ssid(redes: list[dict]) -> dict[str, list[dict]]:
    agrupadas: dict[str, list[dict]] = {}

    for red in sorted(
        redes,
        key=lambda item: (
            str(item.get("ssid") or "<oculta>"),
            str(item.get("bssid") or ""),
        ),
    ):
        ssid = str(red.get("ssid") or "<oculta>")
        agrupadas.setdefault(ssid, []).append(red)

    return agrupadas


def scan_merged(n: int = 2, pausa: float = 2.0) -> list[dict]:
    veces = max(1, int(n))
    por_bssid: dict[str, dict] = {}

    for intento in range(veces):
        for red in scan_networks():
            bssid = str(red.get("bssid") or "").strip().upper()
            if not bssid:
                continue

            senal = int(red.get("senal") or 0)
            actual = por_bssid.get(bssid)
            if actual is None or senal > int(actual.get("senal") or 0):
                fusionada = dict(red)
                fusionada["bssid"] = bssid
                fusionada["senal"] = senal
                por_bssid[bssid] = fusionada

        if intento < veces - 1 and pausa > 0:
            time.sleep(pausa)

    return sorted(
        por_bssid.values(),
        key=lambda red: (
            str(red.get("ssid") or "<oculta>"),
            str(red.get("bssid") or ""),
        ),
    )
