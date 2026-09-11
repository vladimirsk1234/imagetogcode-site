"""LAN TCP sweep for FOCAS port (default 8193)."""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable

_SUBNET_HELP = "subnet must look like '192.168.1' or '192.168.1.0/24'"


def normalize_subnet(subnet: str) -> str:
    """Accept ``192.168.1`` or ``192.168.1.0/24`` (and close variants) → ``192.168.1``."""
    raw = (subnet or "").strip()
    if not raw:
        raise ValueError(_SUBNET_HELP)

    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"{_SUBNET_HELP}, got {subnet!r}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("only IPv4 /24 subnets are supported")
        if network.prefixlen != 24:
            raise ValueError("only /24 subnets are supported")
        return ".".join(str(network.network_address).split(".")[:3])

    prefix = raw.rstrip(".")
    parts = prefix.split(".")
    if len(parts) == 4 and parts[-1] == "0":
        parts = parts[:3]
    if len(parts) != 3 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        raise ValueError(f"{_SUBNET_HELP}, got {subnet!r}")
    return ".".join(str(int(p)) for p in parts)


def to_cidr_hint(subnet: str) -> str:
    """Phone-facing scan hint, e.g. ``192.168.1.0/24``."""
    return f"{normalize_subnet(subnet)}.0/24"


def scan_hint_or_default(subnet: str, default: str = "192.168.1.0/24") -> str:
    try:
        return to_cidr_hint(subnet)
    except ValueError:
        return default


def iter_subnet_hosts(subnet: str, start: int = 1, end: int = 254) -> list[str]:
    prefix = normalize_subnet(subnet)
    if not (1 <= start <= end <= 254):
        raise ValueError("scan range must be within 1..254")
    return [f"{prefix}.{i}" for i in range(start, end + 1)]


def tcp_open(ip: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


async def _async_tcp_open(ip: str, port: int, timeout_s: float, sem: asyncio.Semaphore) -> str | None:
    async with sem:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout_s,
            )
        except (OSError, asyncio.TimeoutError):
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return ip


async def async_scan_open_hosts(
    hosts: Iterable[str],
    port: int,
    timeout_s: float,
    concurrency: int,
) -> list[str]:
    sem = asyncio.Semaphore(max(1, concurrency))
    tasks = [_async_tcp_open(ip, port, timeout_s, sem) for ip in hosts]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip]


def _run_isolated(factory: Callable[[], Awaitable[list[str]]]) -> list[str]:
    """Run ``asyncio.run(factory())`` even when a parent event loop is already active.

    FastAPI handlers are ``async def``, so ``asyncio.run`` on that thread raises
    ``RuntimeError: asyncio.run() cannot be called from a running event loop``.
    A short-lived worker thread has no parent loop, so ``asyncio.run`` is safe.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(factory())).result()


def scan_open_hosts(
    subnet: str,
    port: int,
    *,
    timeout_s: float = 0.25,
    concurrency: int = 64,
    start: int = 1,
    end: int = 254,
) -> list[str]:
    hosts = iter_subnet_hosts(subnet, start, end)
    return _run_isolated(lambda: async_scan_open_hosts(hosts, port, timeout_s, concurrency))
