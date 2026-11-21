import argparse
import sys
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.arp_scanner import scan_dispositivos
from core.classifier import classify
from core.red_local import get_red_local
from core.trusted import load_trusted, trust_ssid, untrust_ssid
from core.wifi_scanner import scan_merged

ESTADOS = {
    "segura": "[green]🟢 segura[/green]",
    "precaucion": "[yellow]🟡 precaución[/yellow]",
    "riesgo": "[red]🔴 riesgo[/red]",
    "oculta": "[white]⚪ oculta[/white]",
}
ORDEN_ESTADOS = ("segura", "precaucion", "riesgo", "oculta")


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


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    consola = Console()
    if consola.width < 110:
        consola = Console(width=110)

    args = _parse_args()

    if args.confiables:
        _listar_confiables(consola)
        return
    if args.dispositivos:
        _mostrar_dispositivos(consola)
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
