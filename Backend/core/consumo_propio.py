from __future__ import annotations

import time

import psutil


def medir_consumo_propio(duracion=10) -> dict:
    antes = psutil.net_io_counters()
    time.sleep(max(0, duracion))
    despues = psutil.net_io_counters()

    if antes is None or despues is None:
        return {
            "bytes_enviados": 0,
            "bytes_recibidos": 0,
            "bytes_totales": 0,
            "kb_s": 0.0,
        }

    enviados = max(0, despues.bytes_sent - antes.bytes_sent)
    recibidos = max(0, despues.bytes_recv - antes.bytes_recv)
    total = enviados + recibidos
    segundos = max(float(duracion), 0.001)

    return {
        "bytes_enviados": enviados,
        "bytes_recibidos": recibidos,
        "bytes_totales": total,
        "kb_s": round(total / 1024 / segundos, 2),
    }
