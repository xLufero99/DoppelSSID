from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from flask import current_app


class CacheConTTL:
    def __init__(self) -> None:
        self.valor: Any = None
        self.creado: float | None = None

    def obtener(self, ttl: float, productor: Callable[[], Any]) -> Any:
        ahora = time.monotonic()
        if (
            self.creado is not None
            and ahora - self.creado < ttl
        ):
            return self.valor
        return self.establecer(productor())

    def establecer(self, valor: Any) -> Any:
        self.valor = valor
        self.creado = time.monotonic()
        return valor

    def invalidar(self) -> None:
        self.valor = None
        self.creado = None


def cache_por_nombre(nombre: str) -> CacheConTTL:
    return current_app.extensions["doppelssid_cache"][nombre]
