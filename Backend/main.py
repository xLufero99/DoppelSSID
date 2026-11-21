from rich.console import Console
from rich.table import Table

from core.wifi_scanner import group_by_ssid, scan_networks


def _seguridad(red: dict) -> str:
    autenticacion = str(red.get("autenticacion") or "").strip()
    cifrado = str(red.get("cifrado") or "").strip()
    if autenticacion and cifrado:
        return f"{autenticacion} ({cifrado})"
    return autenticacion or cifrado or "-"


def main() -> None:
    consola = Console()
    redes = scan_networks()

    if not redes:
        consola.print(
            "[yellow]No se encontraron redes WiFi. "
            "Comprueba que el adaptador WiFi esté activo.[/yellow]"
        )
        return

    tabla = Table(title="Redes WiFi detectadas")
    tabla.add_column("SSID", style="cyan", no_wrap=True)
    tabla.add_column("BSSID", style="magenta", no_wrap=True)
    tabla.add_column("Banda", no_wrap=True)
    tabla.add_column("Canal", justify="right")
    tabla.add_column("Señal", justify="right")
    tabla.add_column("Seguridad")

    for indice_grupo, (ssid, aps) in enumerate(group_by_ssid(redes).items()):
        if indice_grupo:
            tabla.add_section()
        for indice, red in enumerate(aps):
            tabla.add_row(
                ssid if indice == 0 else "",
                str(red.get("bssid") or "-"),
                str(red.get("banda") or "-"),
                str(red.get("canal") if red.get("canal") is not None else "-"),
                f"{red.get('senal', 0)}%",
                _seguridad(red),
            )

    consola.print(tabla)


if __name__ == "__main__":
    main()
