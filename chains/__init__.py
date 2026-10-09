"""
Deep analysis chains.

Архитектура:
  - registry.py          — SERVICE_CHAINS + run_chain() + handlers
  - <service>/           — конкретные реализации (ssh/, http/, html/, smb/, telnet/…)
  - models.HostProfile   — после выполнения цепочек результаты доступны как
                           host.services[i].deep  и  host.services[i].deep_tasks

Как добавить новую цепочку:
  1. Создать handler(ctx) -> dict
  2. Зарегистрировать в registry._HANDLERS и SERVICE_CHAINS
  3. (опционально) вынести логику в chains/<service>/module.py
"""

from .registry import (
    SERVICE_CHAINS,
    get_chains_for_service,
    run_chain,
    list_available_chains,
)

__all__ = [
    "SERVICE_CHAINS",
    "get_chains_for_service",
    "run_chain",
    "list_available_chains",
]
