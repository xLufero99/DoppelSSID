from types import SimpleNamespace

from core import consumo_propio


class Contadores:
    def __init__(self, valores):
        self.valores = valores
        self.indice = 0

    def __call__(self):
        enviados, recibidos = self.valores[min(self.indice, len(self.valores) - 1)]
        self.indice += 1
        return SimpleNamespace(bytes_sent=enviados, bytes_recv=recibidos)


def test_medir_consumo_propio(monkeypatch):
    monkeypatch.setattr(
        consumo_propio.psutil,
        "net_io_counters",
        Contadores([(100, 200), (1100, 3200)]),
    )
    monkeypatch.setattr(consumo_propio.time, "sleep", lambda segundos: None)

    resultado = consumo_propio.medir_consumo_propio(duracion=10)

    assert resultado == {
        "bytes_enviados": 1000,
        "bytes_recibidos": 3000,
        "bytes_totales": 4000,
        "kb_s": round(4000 / 1024 / 10, 2),
    }


def test_medir_consumo_propio_sin_contadores(monkeypatch):
    monkeypatch.setattr(consumo_propio.psutil, "net_io_counters", lambda: None)
    monkeypatch.setattr(consumo_propio.time, "sleep", lambda segundos: None)

    assert consumo_propio.medir_consumo_propio(duracion=1) == {
        "bytes_enviados": 0,
        "bytes_recibidos": 0,
        "bytes_totales": 0,
        "kb_s": 0.0,
    }
