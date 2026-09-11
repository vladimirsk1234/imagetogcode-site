"""FOCAS Ethernet scanner for the iMage-to-Gcode Bridge (Windows shop PC).

Canonical path in the Bridge repo:
    src/imagegcode_bridge/focas/scanner.py

Shop PCs without ``gh`` access to that private repo can download this file
from the public Pages site and drop it over the installed scanner.

FastAPI / uvicorn already run an event loop. Calling ``asyncio.run`` from a
request handler raises::

    RuntimeError: asyncio.run() cannot be called from a running event loop

``_run_isolated`` hops the call onto a ``ThreadPoolExecutor`` worker so
``asyncio.run`` (and blocking FOCAS / ctypes work) get a fresh loop/thread.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Sequence, TypeVar

__all__ = [
    "DEFAULT_FOCAS_PORT",
    "FocasHit",
    "FocasScanner",
    "probe_host",
    "scan_cidr",
    "scan_hosts",
    "_run_isolated",
]

logger = logging.getLogger(__name__)

DEFAULT_FOCAS_PORT = 8193
DEFAULT_TIMEOUT_S = 1.25
DEFAULT_WORKERS = 64

T = TypeVar("T")

_ISOLATED_POOL = ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="focas-isolated",
)


def _run_isolated(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run *func* even when the caller is already inside FastAPI's event loop.

    If no loop is running, *func* executes on this thread. If a loop is
    running, *func* is submitted to a dedicated ``ThreadPoolExecutor`` so
    ``asyncio.run`` and blocking FOCAS DLL calls are safe.
    """

    def _call() -> T:
        result = func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            return asyncio.run(result)  # type: ignore[return-value]
        return result

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _call()
    return _ISOLATED_POOL.submit(_call).result()


@dataclass(frozen=True)
class FocasHit:
    """One host that accepted a FOCAS TCP handshake on the scan port."""

    host: str
    port: int
    reachable: bool
    latency_ms: float | None = None
    cnc_type: str | None = None
    series: str | None = None
    axes: str | None = None
    via: str = "tcp"
    error: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _tcp_probe(host: str, port: int, timeout_s: float) -> tuple[bool, float | None, str | None]:
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((host, port))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return True, round(elapsed_ms, 2), None
    except OSError as exc:
        return False, None, str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _focas_dll_probe(host: str, port: int, timeout_s: float) -> dict[str, Any] | None:
    """Optional Fwlib32 / Fwlib64 identity read. Missing DLL is not an error."""
    try:
        import ctypes
        import ctypes.wintypes
    except ImportError:
        return None

    dll = None
    for name in ("Fwlib64.dll", "Fwlib32.dll", "fwlib64.dll", "fwlib32.dll"):
        try:
            dll = ctypes.WinDLL(name)
            break
        except OSError:
            continue
    if dll is None:
        return None

    handle = ctypes.c_ushort(0)
    timeout_ms = max(int(timeout_s * 1000), 100)
    try:
        dll.cnc_allclibhndl3.argtypes = [
            ctypes.c_char_p,
            ctypes.c_ushort,
            ctypes.c_long,
            ctypes.POINTER(ctypes.c_ushort),
        ]
        dll.cnc_allclibhndl3.restype = ctypes.c_short
        rc = dll.cnc_allclibhndl3(
            host.encode("ascii", errors="ignore"),
            ctypes.c_ushort(port),
            ctypes.c_long(timeout_ms),
            ctypes.byref(handle),
        )
        if rc != 0 or handle.value == 0:
            return {"via": "fwlib", "error": f"cnc_allclibhndl3 rc={rc}"}

        class ODBSYS(ctypes.Structure):
            _fields_ = [
                ("addinfo", ctypes.c_short),
                ("max_axis", ctypes.c_short),
                ("cnc_type", ctypes.c_char * 2),
                ("mt_type", ctypes.c_char * 2),
                ("series", ctypes.c_char * 4),
                ("version", ctypes.c_char * 4),
                ("axes", ctypes.c_char * 2),
            ]

        info = ODBSYS()
        dll.cnc_sysinfo.argtypes = [ctypes.c_ushort, ctypes.POINTER(ODBSYS)]
        dll.cnc_sysinfo.restype = ctypes.c_short
        src = dll.cnc_sysinfo(handle, ctypes.byref(info))
        return {
            "via": "fwlib",
            "sysinfo_rc": src,
            "cnc_type": info.cnc_type.decode("ascii", errors="ignore").strip() or None,
            "series": info.series.decode("ascii", errors="ignore").strip() or None,
            "axes": info.axes.decode("ascii", errors="ignore").strip() or None,
            "mt_type": info.mt_type.decode("ascii", errors="ignore").strip() or None,
            "version": info.version.decode("ascii", errors="ignore").strip() or None,
        }
    except Exception as exc:  # noqa: BLE001 — shop PCs have mixed FOCAS SDKs
        return {"via": "fwlib", "error": str(exc)}
    finally:
        if dll is not None and handle.value:
            try:
                dll.cnc_freelibhndl.argtypes = [ctypes.c_ushort]
                dll.cnc_freelibhndl.restype = ctypes.c_short
                dll.cnc_freelibhndl(handle)
            except Exception:
                pass


def probe_host(
    host: str,
    port: int = DEFAULT_FOCAS_PORT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    use_dll: bool = True,
) -> FocasHit:
    """Probe one IPv4 host for a FOCAS listener."""
    reachable, latency_ms, error = _tcp_probe(host, port, timeout_s)
    extras: dict[str, Any] = {}
    cnc_type = series = axes = None
    via = "tcp"
    if reachable and use_dll:
        identity = _focas_dll_probe(host, port, timeout_s)
        if identity:
            extras.update(identity)
            via = str(identity.get("via") or via)
            cnc_type = identity.get("cnc_type")
            series = identity.get("series")
            axes = identity.get("axes")
            if identity.get("error") and not cnc_type:
                error = str(identity["error"])
    return FocasHit(
        host=host,
        port=port,
        reachable=reachable,
        latency_ms=latency_ms,
        cnc_type=cnc_type,
        series=series,
        axes=axes,
        via=via,
        error=None if reachable else error,
        extras=extras,
    )


def _iter_hosts(hosts: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in hosts:
        text = str(raw).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _expand_cidr(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        raise ValueError("only IPv4 CIDR is supported")
    if network.num_addresses > 4096:
        raise ValueError(f"CIDR {cidr} is too large ({network.num_addresses} addresses)")
    return [str(ip) for ip in network.hosts()] or [str(network.network_address)]


def scan_hosts(
    hosts: Sequence[str],
    port: int = DEFAULT_FOCAS_PORT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    workers: int = DEFAULT_WORKERS,
    use_dll: bool = True,
    reachable_only: bool = True,
) -> list[FocasHit]:
    """Scan hosts on a worker pool. Safe to call from FastAPI via ``_run_isolated``."""
    targets = _iter_hosts(hosts)
    if not targets:
        return []

    hits: list[FocasHit] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        futures = [
            pool.submit(probe_host, host, port, timeout_s, use_dll) for host in targets
        ]
        for fut in futures:
            hit = fut.result()
            if hit.reachable or not reachable_only:
                hits.append(hit)
    hits.sort(key=lambda item: (ipaddress.ip_address(item.host), item.port))
    return hits


def scan_cidr(
    cidr: str,
    port: int = DEFAULT_FOCAS_PORT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    workers: int = DEFAULT_WORKERS,
    use_dll: bool = True,
    reachable_only: bool = True,
) -> list[FocasHit]:
    return scan_hosts(
        _expand_cidr(cidr),
        port=port,
        timeout_s=timeout_s,
        workers=workers,
        use_dll=use_dll,
        reachable_only=reachable_only,
    )


class FocasScanner:
    """Bridge-facing scanner. All public sync methods are FastAPI-safe."""

    def __init__(
        self,
        port: int = DEFAULT_FOCAS_PORT,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        workers: int = DEFAULT_WORKERS,
        use_dll: bool = True,
    ) -> None:
        self.port = port
        self.timeout_s = timeout_s
        self.workers = workers
        self.use_dll = use_dll

    def probe(self, host: str, port: int | None = None) -> FocasHit:
        return _run_isolated(
            probe_host,
            host,
            port if port is not None else self.port,
            self.timeout_s,
            self.use_dll,
        )

    def scan(self, hosts: Sequence[str], reachable_only: bool = True) -> list[FocasHit]:
        return _run_isolated(
            scan_hosts,
            hosts,
            self.port,
            self.timeout_s,
            self.workers,
            self.use_dll,
            reachable_only,
        )

    def scan_network(self, cidr: str, reachable_only: bool = True) -> list[FocasHit]:
        return _run_isolated(
            scan_cidr,
            cidr,
            self.port,
            self.timeout_s,
            self.workers,
            self.use_dll,
            reachable_only,
        )

    async def aprobe(self, host: str, port: int | None = None) -> FocasHit:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: probe_host(
                host,
                port if port is not None else self.port,
                self.timeout_s,
                self.use_dll,
            ),
        )

    async def ascan(self, hosts: Sequence[str], reachable_only: bool = True) -> list[FocasHit]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: scan_hosts(
                hosts,
                self.port,
                self.timeout_s,
                self.workers,
                self.use_dll,
                reachable_only,
            ),
        )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan a LAN for Fanuc FOCAS listeners")
    parser.add_argument("--cidr", help="IPv4 CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--host", action="append", default=[], help="Single host (repeatable)")
    parser.add_argument("--port", type=int, default=DEFAULT_FOCAS_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--all", action="store_true", help="Include unreachable hosts")
    parser.add_argument("--no-dll", action="store_true", help="Skip Fwlib32 identity probe")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    hosts: list[str] = list(args.host)
    if args.cidr:
        hosts.extend(_expand_cidr(args.cidr))
    if not hosts:
        print("pass --cidr and/or --host", file=sys.stderr)
        return 2

    scanner = FocasScanner(
        port=args.port,
        timeout_s=args.timeout,
        workers=args.workers,
        use_dll=not args.no_dll,
    )
    hits = scanner.scan(hosts, reachable_only=not args.all)
    payload = [hit.to_dict() for hit in hits]
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if not payload:
            print("no FOCAS listeners found")
        for hit in hits:
            mark = "UP" if hit.reachable else "DOWN"
            ident = hit.cnc_type or "-"
            print(f"{hit.host}:{hit.port}\t{mark}\t{ident}\t{hit.latency_ms or '-'} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
