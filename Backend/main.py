import argparse
import platform
import sys
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from core.arp_scanner import scan_dispositivos
from core.classifier import classify
from core.consumo_propio import medir_consumo_propio
from core.entorno import descargar_e_instalar_npcap, es_administrador, npcap_instalado
from core.red_local import get_red_local
from core.trafico import (
    _gateway_ip,
    obtener_mac,
    monitorear,
)
from core.trusted import load_trusted, trust_ssid, untrust_ssid
from core.wifi_scanner import scan_merged

RUTA_ADVERTENCIA = Path(__file__).resolve().parent / "data" / ".advertencia_aceptada"

ESTADOS = {
    "segura": "[green]🟢 segura[/green]",
    "precaucion": "[yellow]🟡 precaución[/yellow]",
    "riesgo": "[red]🔴 riesgo[/red]",
    "oculta": "[white]⚪ oculta[/white]",
}
ORDEN_ESTADOS = ("segura", "precaucion", "riesgo", "oculta")


def _confirmar(pregunta: str) -> bool:
    try:
        respuesta = input(pregunta)
    except EOFError:
        return False
    return respuesta.strip().lower() in ("s", "si")


def _advertencia_inicial(consola: Console) -> None:
    if RUTA_ADVERTENCIA.exists():
        return

    consola.print(
        "[yellow]DoppelSSID incluye una función de monitoreo de tráfico que "
        "intercepta temporalmente las comunicaciones de otros dispositivos "
        "en la red (ARP spoofing). Úsala ÚNICAMENTE en una red que tú "
        "administres o poseas (tu casa, tu laboratorio). Usarla en redes "
        "ajenas sin autorización explícita es ilegal en la mayoría de "
        "países, incluyendo Colombia (Ley 1273 de 2009).[/yellow]"
    )
    if not _confirmar("Entendido (s/N): "):
        raise SystemExit(0)

    try:
        RUTA_ADVERTENCIA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_ADVERTENCIA.write_text("aceptada\n", encoding="utf-8")
    except OSError:
        pass


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detector local de posibles redes WiFi falsas (Evil Twin)."
    )
    parser.add_argument(
        "--escaneos",
        type=int,
        default=2,
        help="número de escaneos a combinar (por defecto: 2)",
    )
    parser.add_argument(
        "--confiar",
        metavar="SSID",
        help="guarda el SSID actual como red de confianza",
    )
    parser.add_argument(
        "--olvidar",
        metavar="SSID",
        help="elimina un SSID de la lista de confianza",
    )
    parser.add_argument(
        "--confiables",
        action="store_true",
        help="lista los perfiles de confianza guardados",
    )
    parser.add_argument(
        "--dispositivos",
        action="store_true",
        help="lista los dispositivos de la red local mediante ARP",
    )
    parser.add_argument(
        "--trafico",
        action="store_true",
        help="monitorea el consumo de tráfico por dispositivo",
    )
    return parser.parse_args()


def _seguridad(red: dict) -> str:
    autenticacion = str(red.get("autenticacion") or "").strip()
    cifrado = str(red.get("cifrado") or "").strip()
    if autenticacion and cifrado:
        return f"{autenticacion} ({cifrado})"
    return autenticacion or cifrado or "-"


def _sin_redes(consola: Console) -> None:
    consola.print(
        "[yellow]No se encontraron redes WiFi. "
        "Comprueba que el adaptador WiFi esté activo.[/yellow]"
    )


def _listar_confiables(consola: Console) -> None:
    perfiles = load_trusted()
    if not perfiles:
        consola.print("[yellow]No hay SSID de confianza guardados.[/yellow]")
        return

    tabla = Table(title="Redes de confianza", min_width=70)
    tabla.add_column("SSID", style="cyan", no_wrap=True)
    tabla.add_column("BSSID", style="magenta", no_wrap=True)
    tabla.add_column("Autenticación")
    tabla.add_column("Cifrado")

    for perfil in perfiles:
        bssids = perfil.get("bssids")
        if not isinstance(bssids, dict):
            bssids = {}
        for indice, bssid in enumerate(sorted(bssids)):
            tabla.add_row(
                str(perfil.get("ssid") or "") if indice == 0 else "",
                str(bssid),
                str(perfil.get("autenticacion") or "-"),
                str(perfil.get("cifrado") or "-"),
            )

    consola.print(tabla)


def _mostrar_dispositivos(consola: Console) -> None:
    if get_red_local() is None:
        consola.print(
            "[yellow]No estás conectado a ninguna red WiFi. "
            "Conéctate para ver los dispositivos.[/yellow]"
        )
        return

    with consola.status("Escaneando red local (esto puede tardar unos segundos)..."):
        dispositivos = scan_dispositivos()

    if not dispositivos:
        consola.print(
            "[yellow]No se detectaron otros dispositivos. "
            "Intenta de nuevo en unos segundos.[/yellow]"
        )
        return

    tabla = Table(title="Dispositivos en la red local", min_width=80)
    tabla.add_column("IP", style="cyan", no_wrap=True)
    tabla.add_column("MAC", style="magenta", no_wrap=True)
    tabla.add_column("Fabricante")
    tabla.add_column("Este equipo", justify="center")

    for dispositivo in dispositivos:
        tabla.add_row(
            str(dispositivo.get("ip") or "-"),
            str(dispositivo.get("mac") or "-"),
            str(dispositivo.get("fabricante") or "Desconocido"),
            "🖥️" if dispositivo.get("es_este_equipo") else "",
        )

    consola.print(tabla)


def _confiar(consola: Console, ssid: str, escaneos: int) -> None:
    if ssid == "<oculta>":
        consola.print("[red]No se puede confiar en una red oculta.[/red]")
        return

    redes = scan_merged(n=escaneos)
    if not redes:
        _sin_redes(consola)
        return

    coincidentes = [red for red in redes if red.get("ssid") == ssid]
    if not coincidentes:
        consola.print(f"[yellow]No se encontró el SSID '{ssid}'.[/yellow]")
        return

    consola.print(
        "[yellow]Hazlo solo si estás seguro de estar en tu red real.[/yellow]"
    )
    respuesta = input(
        f"¿Confiar en '{ssid}' con {len(coincidentes)} BSSID? (s/N): "
    )
    if respuesta.strip().lower() != "s":
        consola.print("[yellow]No se guardó ningún perfil.[/yellow]")
        return

    trust_ssid(ssid, coincidentes)
    consola.print(f"[green]SSID '{ssid}' guardado como confiable.[/green]")


def _olvidar(consola: Console, ssid: str) -> None:
    if ssid == "<oculta>":
        consola.print("[yellow]No hay perfiles ocultos que olvidar.[/yellow]")
        return
    untrust_ssid(ssid)
    consola.print(f"[green]Se olvidó el SSID '{ssid}'.[/green]")


def _mostrar_resultados(consola: Console, resultados: list[dict]) -> None:
    tabla = Table(title="Clasificación de redes WiFi", min_width=110)
    tabla.add_column("SSID", style="cyan")
    tabla.add_column("BSSID", style="magenta", no_wrap=True)
    tabla.add_column("Banda", no_wrap=True)
    tabla.add_column("Canal", justify="right")
    tabla.add_column("Señal", justify="right")
    tabla.add_column("Seguridad")
    tabla.add_column("Estado")

    for indice_grupo, grupo in enumerate(resultados):
        if indice_grupo:
            tabla.add_section()

        for indice, red in enumerate(grupo["redes"]):
            tabla.add_row(
                grupo["ssid"] if indice == 0 else "",
                str(red.get("bssid") or "-"),
                str(red.get("banda") or "-"),
                str(red.get("canal") if red.get("canal") is not None else "-"),
                f"{red.get('senal', 0)}%",
                _seguridad(red),
                ESTADOS.get(red.get("estado"), str(red.get("estado") or "-")),
            )

        motivos = grupo.get("motivos") or []
        if motivos:
            tabla.add_row(
                Text(" · ".join(motivos), style="grey58"),
                "",
                "",
                "",
                "",
                "",
                "",
            )

    consola.print(tabla)

    conteos = Counter(grupo["estado"] for grupo in resultados)
    resumen = " · ".join(
        f"{ESTADOS[estado]} {conteos.get(estado, 0)}" for estado in ORDEN_ESTADOS
    )
    consola.print(f"[bold]Resumen:[/bold] {resumen}")


def _tabla_trafico(resultados: list[dict], titulo: str) -> Table:
    tabla = Table(title=titulo, min_width=70)
    tabla.add_column("IP", style="cyan", no_wrap=True)
    tabla.add_column("Fabricante")
    tabla.add_column("KB", justify="right")
    tabla.add_column("%", justify="right")
    tabla.add_column("Barra")

    if not resultados:
        tabla.add_row("-", "-", "0,0", "0", "")
        return tabla

    for resultado in resultados:
        porcentaje = int(resultado.get("porcentaje") or 0)
        llenos = min(20, max(0, round(porcentaje / 5)))
        barra = "█" * llenos + "·" * (20 - llenos)
        ip = str(resultado.get("ip") or "-")
        if resultado.get("es_este_equipo"):
            ip += " (este equipo)"
        tabla.add_row(
            ip,
            str(resultado.get("fabricante") or "Desconocido"),
            f"{int(resultado.get('bytes') or 0) / 1024:.1f}",
            str(porcentaje),
            barra,
        )
    return tabla


def _mostrar_consumo_propio(consola: Console) -> None:
    with consola.status("Midiendo tu consumo durante 10 segundos..."):
        datos = medir_consumo_propio()

    tabla = Table(title="Consumo de este equipo", min_width=60)
    tabla.add_column("Métrica")
    tabla.add_column("Valor", justify="right")
    tabla.add_row("Enviados", f"{int(datos.get('bytes_enviados') or 0)} B")
    tabla.add_row("Recibidos", f"{int(datos.get('bytes_recibidos') or 0)} B")
    tabla.add_row("Totales", f"{int(datos.get('bytes_totales') or 0)} B")
    tabla.add_row("Tasa", f"{float(datos.get('kb_s') or 0):.2f} KB/s")
    consola.print(tabla)


def _flujo_trafico(consola: Console) -> None:
    if not es_administrador():
        consola.print(
            "[red]Esta función necesita permisos de administrador. "
            "Cierra el programa y vuelve a abrirlo con 'Ejecutar como "
            "administrador' (Windows) o con sudo (Linux).[/red]"
        )
        return

    if platform.system() == "Windows" and not npcap_instalado():
        consola.print(
            "[yellow]No tienes Npcap instalado (necesario para ver el tráfico "
            "de otros dispositivos). Sin él, solo puedes ver el consumo de tu "
            "propio equipo.[/yellow]"
        )
        if _confirmar("¿Deseas descargarlo e instalarlo ahora? (s/N): "):
            with consola.status("Descargando e instalando Npcap..."):
                instalado = descargar_e_instalar_npcap()
            if not instalado or not npcap_instalado():
                consola.print(
                    "[red]Instala Npcap manualmente desde "
                    "https://npcap.com/#download y vuelve a intentarlo.[/red]"
                )
                return
        else:
            consola.print(
                "[yellow]Continuando en modo limitado: solo se mostrará "
                "tu propio consumo.[/yellow]"
            )
            _mostrar_consumo_propio(consola)
            return

    consola.print(
        "[bold red]⚠️  Vas a interceptar tráfico de TODOS los dispositivos de "
        "esta red para medir su consumo. Solo continúa si administras esta red.[/bold red]"
    )
    if not _confirmar(
        "¿Es esta tu propia red y confirmas que tienes autorización para monitorearla? (s/N): "
    ):
        consola.print("[yellow]Operación cancelada; no se tocó la red.[/yellow]")
        return

    red = get_red_local()
    if red is None:
        consola.print(
            "[yellow]No estás conectado a ninguna red WiFi. "
            "Conéctate para ver el tráfico.[/yellow]"
        )
        return

    dispositivos = scan_dispositivos()
    if not dispositivos:
        consola.print(
            "[yellow]No se detectaron dispositivos. Intenta de nuevo en unos segundos.[/yellow]"
        )
        return

    router_ip = _gateway_ip(red.get("rango") or [])
    if not router_ip:
        consola.print("[red]No se pudo identificar el router de la red.[/red]")
        return

    with consola.status("Resolviendo la MAC del router..."):
        router_mac = obtener_mac(router_ip)
    if not router_mac:
        consola.print(f"[red]No se pudo resolver la MAC del router {router_ip}.[/red]")
        return

    resultados: list[dict] = []
    with Live(console=consola, refresh_per_second=4, screen=False) as live:
        def actualizar(nuevos: list[dict]) -> None:
            nonlocal resultados
            resultados = nuevos
            live.update(_tabla_trafico(resultados, "Tráfico en vivo"))

        try:
            resultados = monitorear(
                dispositivos,
                router_ip,
                router_mac,
                intervalo=2,
                actualizar=actualizar,
            )
        finally:
            live.update(_tabla_trafico(resultados, "Resumen final"))

    consola.print(_tabla_trafico(resultados, "Resumen final"))


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    consola = Console()
    if consola.width < 110:
        consola = Console(width=110)

    _advertencia_inicial(consola)
    args = _parse_args()

    if args.confiables:
        _listar_confiables(consola)
        return
    if args.dispositivos:
        _mostrar_dispositivos(consola)
        return
    if args.trafico:
        _flujo_trafico(consola)
        return
    if args.olvidar:
        _olvidar(consola, args.olvidar)
        return
    if args.confiar:
        _confiar(consola, args.confiar, args.escaneos)
        return

    redes = scan_merged(n=args.escaneos)
    if not redes:
        _sin_redes(consola)
        return

    resultados = classify(redes, load_trusted())
    _mostrar_resultados(consola, resultados)


if __name__ == "__main__":
    main()
