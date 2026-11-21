from __future__ import annotations

import re
from collections import Counter

from core.wifi_scanner import group_by_ssid

PESOS = {
    "auth_distinta": 50,
    "abierta_con_gemelo": 60,
    "oui_distinto": 25,
    "bit_local_oui_distinto": 15,
    "abierta_sola": 25,
    "no_confiable": 40,
    "perfil_auth_distinta": 50,
    "perfil_abierta": 60,
    "senal_mayor": 15,
    "canal_distinto": 10,
    "doble_banda": -20,
    "mesh": -20,
}
UMBRAL_PRECAUCION = 25
UMBRAL_RIESGO = 50


def normalizar_oui(bssid: object) -> str:
    partes = re.split(r":|-", str(bssid or "").strip().upper())
    if len(partes) < 3:
        return ""
    try:
        primero = int(partes[0], 16) & ~0x02
        return f"{primero:02X}:{int(partes[1], 16):02X}:{int(partes[2], 16):02X}"
    except ValueError:
        return ""


def tiene_bit_local(bssid: object) -> bool:
    partes = re.split(r":|-", str(bssid or "").strip().upper())
    if not partes:
        return False
    try:
        return bool(int(partes[0], 16) & 0x02)
    except ValueError:
        return False


def _clave(valor: object) -> str:
    texto = str(valor or "").strip().lower().replace("-", " ").replace("_", " ")
    return " ".join(texto.split())


def _seguridad_clave(red: dict) -> str:
    return f"{_clave(red.get('autenticacion'))}|{_clave(red.get('cifrado'))}"


def _es_abierta_valores(autenticacion: object, cifrado: object) -> bool:
    auth = _clave(autenticacion)
    cifra = _clave(cifrado)
    return auth in {"abierta", "open", "sin autenticacion"} or cifra in {
        "ninguna",
        "none",
        "open",
        "abierta",
    }


def _es_abierta(red: dict) -> bool:
    return _es_abierta_valores(red.get("autenticacion"), red.get("cifrado"))


def _seguridad(red: dict) -> str:
    autenticacion = str(red.get("autenticacion") or "").strip() or "desconocida"
    cifrado = str(red.get("cifrado") or "").strip()
    return autenticacion if not cifrado else f"{autenticacion}/{cifrado}"


def _limitar(puntaje: int) -> int:
    return max(0, min(100, int(puntaje)))


def _estado_por_puntaje(puntaje: int) -> str:
    if puntaje >= UMBRAL_RIESGO:
        return "riesgo"
    if puntaje >= UMBRAL_PRECAUCION:
        return "precaucion"
    return "segura"


def _peor_estado(estados: list[str]) -> str:
    if "riesgo" in estados:
        return "riesgo"
    if "precaucion" in estados:
        return "precaucion"
    if "oculta" in estados:
        return "oculta"
    return "segura"


def _minority(valores: list[str]) -> tuple[set[int], int | None]:
    conteos = Counter(valores)
    if len(conteos) < 2:
        return set(), None

    maximo = max(conteos.values())
    ganadores = [valor for valor, cantidad in conteos.items() if cantidad == maximo]
    if len(ganadores) > 1:
        return set(range(len(valores))), 0

    mayoritario = ganadores[0]
    referencia = next(i for i, valor in enumerate(valores) if valor == mayoritario)
    return {i for i, valor in enumerate(valores) if valor != mayoritario}, referencia


def _otro_valor(valores: list[str], indice: int, referencia: int | None) -> str:
    if (
        referencia is not None
        and referencia != indice
        and valores[referencia] != valores[indice]
    ):
        return valores[referencia]

    for otro, valor in enumerate(valores):
        if otro != indice and valor != valores[indice]:
            return valor
    return ""


def _nuevo_resultado(red: dict) -> dict:
    return {
        "bssid": str(red.get("bssid") or "").strip().upper(),
        "canal": int(red.get("canal") or 0),
        "banda": str(red.get("banda") or ""),
        "senal": int(red.get("senal") or 0),
        "autenticacion": str(red.get("autenticacion") or ""),
        "cifrado": str(red.get("cifrado") or ""),
        "estado": "segura",
        "puntaje": 0,
        "motivos": [],
        "fuerza_riesgo": False,
    }


def _sumar(resultado: dict, clave: str, motivo: str, fuerza: bool = False) -> None:
    resultado["puntaje"] += PESOS[clave]
    resultado["motivos"].append(motivo)
    if fuerza:
        resultado["fuerza_riesgo"] = True


def _descontar(resultado: dict, clave: str) -> None:
    resultado["puntaje"] += PESOS[clave]


def _clasificar_no_confiable(aps: list[dict]) -> list[dict]:
    resultados = [_nuevo_resultado(red) for red in aps]

    if len(aps) == 1:
        if _es_abierta(aps[0]):
            _sumar(
                resultados[0],
                "abierta_sola",
                "Red abierta: el tráfico no está cifrado",
            )
        return resultados

    seguridades = [_seguridad_clave(red) for red in aps]
    abiertas = [_es_abierta(red) for red in aps]
    ouis = [normalizar_oui(red.get("bssid")) for red in aps]
    bandas = [_clave(red.get("banda")) for red in aps]
    cifrados = [_clave(red.get("cifrado")) for red in aps]

    minoria, referencia = _minority(seguridades)
    for indice in minoria:
        otro_valor = _otro_valor(seguridades, indice, referencia)
        otro = aps[seguridades.index(otro_valor)] if otro_valor else aps[0]
        _sumar(
            resultados[indice],
            "auth_distinta",
            f"Mismo nombre con otra seguridad ({_seguridad(aps[indice])} vs {_seguridad(otro)})",
        )

    minoria, _ = _minority([str(valor) for valor in abiertas])
    for indice in minoria:
        _sumar(
            resultados[indice],
            "abierta_con_gemelo",
            "Mismo nombre con un BSSID abierto y otro protegido",
            fuerza=True,
        )

    minoria, referencia = _minority(ouis)
    for indice in minoria:
        otro_oui = _otro_valor(ouis, indice, referencia)
        _sumar(
            resultados[indice],
            "oui_distinto",
            f"OUI distinto ({ouis[indice]} vs {otro_oui})",
        )

    conteo_ouis = Counter(ouis)
    for indice, red in enumerate(aps):
        if tiene_bit_local(red.get("bssid")) and conteo_ouis.get(ouis[indice], 0) == 1:
            _sumar(
                resultados[indice],
                "bit_local_oui_distinto",
                "Bit local activo y OUI distinto al resto",
            )

    for indice in range(len(aps)):
        iguales = [
            otro
            for otro in range(len(aps))
            if otro != indice and ouis[indice] and ouis[otro] == ouis[indice]
        ]
        if not iguales:
            continue
        if any(bandas[otro] != bandas[indice] for otro in iguales):
            _descontar(resultados[indice], "doble_banda")
        elif any(cifrados[otro] == cifrados[indice] for otro in iguales):
            _descontar(resultados[indice], "mesh")

    return resultados


def _clasificar_confiable(aps: list[dict], perfil: dict) -> list[dict]:
    resultados = [_nuevo_resultado(red) for red in aps]
    datos_perfil = perfil.get("bssids")
    bssids_perfil: dict[str, dict] = {}

    if isinstance(datos_perfil, dict):
        for bssid, datos in datos_perfil.items():
            if isinstance(datos, dict):
                bssids_perfil[str(bssid).strip().upper()] = datos

    ouis_perfil = {normalizar_oui(bssid) for bssid in bssids_perfil}
    canales_perfil: set[int] = set()
    mejor_senal = 0

    for datos in bssids_perfil.values():
        try:
            canales_perfil.add(int(datos.get("canal") or 0))
        except (TypeError, ValueError):
            pass
        try:
            mejor_senal = max(mejor_senal, int(datos.get("senal") or 0))
        except (TypeError, ValueError):
            pass

    auth_perfil = perfil.get("autenticacion")
    cifrado_perfil = perfil.get("cifrado")
    perfil_protegido = not _es_abierta_valores(auth_perfil, cifrado_perfil)

    for red, resultado in zip(aps, resultados):
        bssid = resultado["bssid"]
        conocido = bssids_perfil.get(bssid)
        coincide_auth = _clave(red.get("autenticacion")) == _clave(auth_perfil)
        coincide_cifrado = _clave(red.get("cifrado")) == _clave(cifrado_perfil)

        if conocido is not None and coincide_auth and coincide_cifrado:
            continue

        if conocido is not None:
            _sumar(
                resultado,
                "perfil_auth_distinta",
                "El perfil de confianza cambió autenticación/cifrado",
                fuerza=True,
            )
            continue

        _sumar(
            resultado,
            "no_confiable",
            "BSSID desconocido en una red de confianza",
        )

        if not coincide_auth or not coincide_cifrado:
            _sumar(
                resultado,
                "perfil_auth_distinta",
                "Autenticación/cifrado distinta del perfil",
                fuerza=True,
            )

        if perfil_protegido and _es_abierta(red):
            _sumar(
                resultado,
                "perfil_abierta",
                "La red de confianza aparece abierta",
                fuerza=True,
            )

        oui = normalizar_oui(bssid)
        if oui not in ouis_perfil:
            _sumar(resultado, "oui_distinto", "OUI distinto al del perfil")

        if resultado["senal"] >= mejor_senal + 25:
            _sumar(resultado, "senal_mayor", "Señal mucho mayor que la del perfil")

        if resultado["canal"] not in canales_perfil:
            _sumar(resultado, "canal_distinto", "Canal no usado por el perfil")

    return resultados


def _finalizar(bssids: list[dict]) -> list[dict]:
    for red in bssids:
        fuerza = red.pop("fuerza_riesgo", False)
        red["puntaje"] = _limitar(red["puntaje"])
        red["estado"] = "riesgo" if fuerza else _estado_por_puntaje(red["puntaje"])
    return bssids


def classify(redes: list[dict], trusted: list[dict] | None = None) -> list[dict]:
    resultados: list[dict] = []
    perfiles = {
        str(perfil.get("ssid")): perfil
        for perfil in (trusted or [])
        if isinstance(perfil, dict) and perfil.get("ssid")
    }

    for ssid, aps in group_by_ssid(redes).items():
        if ssid == "<oculta>":
            bssids = _finalizar([_nuevo_resultado(red) for red in aps])
            for red in bssids:
                red["estado"] = "oculta"
                red["puntaje"] = 0
                red["motivos"] = ["Red oculta: no se puede comparar por nombre"]

            resultados.append(
                {
                    "ssid": ssid,
                    "estado": "oculta",
                    "puntaje": 0,
                    "motivos": ["Red oculta: no se puede comparar por nombre"],
                    "redes": bssids,
                }
            )
            continue

        perfil = perfiles.get(ssid)
        if perfil is None:
            bssids = _clasificar_no_confiable(aps)
        else:
            bssids = _clasificar_confiable(aps, perfil)
        bssids = _finalizar(bssids)

        motivos: list[str] = []
        for red in bssids:
            for motivo in red["motivos"]:
                if motivo not in motivos:
                    motivos.append(motivo)

        resultados.append(
            {
                "ssid": ssid,
                "estado": _peor_estado([red["estado"] for red in bssids]),
                "puntaje": max((red["puntaje"] for red in bssids), default=0),
                "motivos": motivos,
                "redes": bssids,
            }
        )

    return sorted(resultados, key=lambda item: (-item["puntaje"], item["ssid"]))
