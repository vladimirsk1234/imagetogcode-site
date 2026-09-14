"""Windows-only FOCAS backend. Loads vendor ``Fwlib32.dll`` from ``./lib``.

This module never runs in CI. The ctypes signatures follow the public Fanuc
FOCAS1/2 LAN API (cnc_allclibhndl3 / statinfo / program up-down). Shop PCs
must place the vendor DLL (and its companion FOCAS DLLs) next to the bridge;
we do not ship Fwlib32.dll.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import POINTER, byref, c_char, c_char_p, c_long, c_short, c_ushort, create_string_buffer
from pathlib import Path

from imagegcode_bridge.errors import CncUnavailable
from imagegcode_bridge.focas.base import (
    RUN_ESTOP,
    RUN_HOLD,
    RUN_IDLE,
    RUN_RUNNING,
    RUN_STOP,
    RUN_UNKNOWN,
    ProbeInfo,
)
from imagegcode_bridge.o_number import normalize_o_number
from imagegcode_bridge.settings import DEFAULT_DESTINATION

EW_OK = 0
EW_BUSY = -1
EW_RESET = -2
EW_BUFFER = 10

# cnc_statinfo.run
_RUN_MAP = {
    0: RUN_STOP,  # reset / not running
    1: RUN_STOP,
    2: RUN_HOLD,
    3: RUN_RUNNING,
    4: RUN_RUNNING,  # MSTR
}


class ODBST(ctypes.Structure):
    _fields_ = [
        ("dummy", c_short * 2),
        ("aut", c_short),
        ("manual", c_short),
        ("run", c_short),
        ("edit", c_short),
        ("motion", c_short),
        ("mstb", c_short),
        ("emergency", c_short),
        ("alarm", c_short),
        ("edit_type", c_short),
        ("tmmode", c_short),
        ("wrkmd", c_short),
    ]


class ODBEXEPRG(ctypes.Structure):
    _fields_ = [
        ("name", c_char * 36),
        ("o_number", c_long),
    ]


class PRGDIR2(ctypes.Structure):
    _fields_ = [
        ("number", c_short),
        ("length", c_long),
        ("comment", c_char * 51),
        ("dummy", c_char),
    ]


def _decode(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()


def focas_timeout_seconds(timeout_ms: int) -> int:
    """Convert ``focas_timeout_ms`` to ``cnc_allclibhndl3`` units (seconds).

    Fanuc documents the third argument as seconds. The setting stays in
    milliseconds so existing ``config/default.json`` (2000) keeps an effective
    connect timeout of ~2s.
    """
    return max(1, (int(timeout_ms) + 999) // 1000)


def prepare_focas_dll_search_path(lib_dir: Path) -> None:
    """Make companion Fanuc DLLs findable for ``Fwlib32.dll``.

    ``os.add_dll_directory`` alone is not enough: Fwlib32 dynamically loads
    series DLLs (``fwlib30i.dll``, ``fwlibe1.dll``, …) via the classic PATH
    search. FANUC Machine IO prepends the lib folder to ``PATH`` as well;
    without that, ``cnc_allclibhndl3`` returns ``EW_NODLL`` (-15).
    """
    lib_dir_str = str(Path(lib_dir))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(lib_dir_str)
    current = os.environ.get("PATH", "")
    prefix = lib_dir_str + os.pathsep
    if current != lib_dir_str and not current.startswith(prefix):
        os.environ["PATH"] = prefix + current if current else lib_dir_str


class WindowsFocasBackend:
    name = "windows"

    def __init__(self, dll_path: Path, timeout_ms: int = 2000) -> None:
        if sys.platform != "win32":
            raise CncUnavailable("Real FOCAS (Fwlib32.dll) is Windows-only")
        self.dll_path = Path(dll_path)
        if not self.dll_path.is_file():
            raise CncUnavailable(f"Fwlib32.dll not found at {self.dll_path}")
        self.timeout_ms = timeout_ms
        self._dll = self._load_dll(self.dll_path)
        self._bind()

    @staticmethod
    def _load_dll(path: Path) -> ctypes.WinDLL:
        prepare_focas_dll_search_path(path.parent)
        return ctypes.WinDLL(str(path))

    def _bind(self) -> None:
        d = self._dll
        d.cnc_allclibhndl3.argtypes = [c_char_p, c_ushort, c_long, POINTER(c_ushort)]
        d.cnc_allclibhndl3.restype = c_short
        d.cnc_freelibhndl.argtypes = [c_ushort]
        d.cnc_freelibhndl.restype = c_short
        d.cnc_statinfo.argtypes = [c_ushort, POINTER(ODBST)]
        d.cnc_statinfo.restype = c_short
        d.cnc_exeprgname.argtypes = [c_ushort, POINTER(ODBEXEPRG)]
        d.cnc_exeprgname.restype = c_short
        d.cnc_rdprogdir2.argtypes = [
            c_ushort,
            c_short,
            POINTER(c_short),
            POINTER(c_short),
            POINTER(PRGDIR2),
        ]
        d.cnc_rdprogdir2.restype = c_short
        d.cnc_dwnstart3.argtypes = [c_ushort, c_short]
        d.cnc_dwnstart3.restype = c_short
        d.cnc_download3.argtypes = [c_ushort, POINTER(c_long), c_char_p]
        d.cnc_download3.restype = c_short
        d.cnc_dwnend3.argtypes = [c_ushort]
        d.cnc_dwnend3.restype = c_short
        d.cnc_upstart3.argtypes = [c_ushort, c_short, c_long, c_long]
        d.cnc_upstart3.restype = c_short
        d.cnc_upload3.argtypes = [c_ushort, POINTER(c_long), c_char_p]
        d.cnc_upload3.restype = c_short
        d.cnc_upend3.argtypes = [c_ushort]
        d.cnc_upend3.restype = c_short

    def known_tcp_hosts(self, subnet: str, port: int) -> list[str] | None:
        _ = (subnet, port)
        return None

    def _connect(self, ip: str, port: int) -> int:
        handle = c_ushort(0)
        rc = self._dll.cnc_allclibhndl3(
            ip.encode("ascii"),
            c_ushort(port),
            c_long(focas_timeout_seconds(self.timeout_ms)),
            byref(handle),
        )
        if rc != EW_OK:
            raise CncUnavailable(f"FOCAS connect failed ({ip}:{port}) rc={rc}")
        return int(handle.value)

    def _close(self, handle: int) -> None:
        try:
            self._dll.cnc_freelibhndl(c_ushort(handle))
        except OSError:
            pass

    def probe(self, ip: str, port: int) -> ProbeInfo:
        try:
            handle = self._connect(ip, port)
        except CncUnavailable as exc:
            return ProbeInfo(
                ip=ip,
                port=port,
                tcp_ok=True,
                focas_ok=False,
                message=str(exc.detail if hasattr(exc, "detail") else exc),
            )
        try:
            stat = ODBST()
            rc = self._dll.cnc_statinfo(c_ushort(handle), byref(stat))
            if rc != EW_OK:
                return ProbeInfo(
                    ip=ip,
                    port=port,
                    tcp_ok=True,
                    focas_ok=False,
                    message=f"cnc_statinfo rc={rc}",
                )
            run_state = RUN_ESTOP if stat.emergency else _RUN_MAP.get(int(stat.run), RUN_UNKNOWN)
            program_name = None
            exe = ODBEXEPRG()
            if self._dll.cnc_exeprgname(c_ushort(handle), byref(exe)) == EW_OK:
                if exe.o_number:
                    program_name = normalize_o_number(int(exe.o_number))
                else:
                    name = _decode(exe.name)
                    program_name = name or None
            return ProbeInfo(
                ip=ip,
                port=port,
                tcp_ok=True,
                focas_ok=True,
                message="connected",
                program_name=program_name,
                run_state=run_state,
            )
        finally:
            self._close(handle)

    def ping(self, ip: str, port: int) -> ProbeInfo:
        return self.probe(ip, port)

    def program_exists(self, ip: str, port: int, o_number: str, destination: str) -> bool:
        _ = destination
        target = int(normalize_o_number(o_number)[1:])
        return target in self._list_program_numbers(ip, port)

    def list_o_numbers(self, ip: str, port: int, destination: str) -> list[str]:
        _ = destination
        from imagegcode_bridge.o_number import format_o_number

        return [format_o_number(n) for n in sorted(self._list_program_numbers(ip, port))]

    def _list_program_numbers(self, ip: str, port: int) -> set[int]:
        handle = self._connect(ip, port)
        found: set[int] = set()
        try:
            pn = c_short(0)
            while True:
                num = c_short(10)
                buf = (PRGDIR2 * 10)()
                rc = self._dll.cnc_rdprogdir2(
                    c_ushort(handle),
                    c_short(0),
                    byref(pn),
                    byref(num),
                    buf,
                )
                if rc != EW_OK or num.value <= 0:
                    break
                for i in range(num.value):
                    if buf[i].number:
                        found.add(int(buf[i].number))
                if num.value < 10:
                    break
        finally:
            self._close(handle)
        return found

    def upload(self, ip: str, port: int, nc_text: str, o_number: str, destination: str) -> None:
        _ = (o_number, destination)
        payload = nc_text.encode("ascii", errors="replace")
        handle = self._connect(ip, port)
        try:
            rc = self._dll.cnc_dwnstart3(c_ushort(handle), c_short(0))
            if rc != EW_OK:
                raise CncUnavailable(f"cnc_dwnstart3 rc={rc}")
            offset = 0
            while offset < len(payload):
                chunk = payload[offset : offset + 256]
                n = c_long(len(chunk))
                buf = create_string_buffer(chunk, len(chunk))
                rc = self._dll.cnc_download3(c_ushort(handle), byref(n), buf)
                if rc == EW_BUSY or rc == EW_BUFFER:
                    continue
                if rc != EW_OK:
                    raise CncUnavailable(f"cnc_download3 rc={rc}")
                sent = int(n.value) if n.value > 0 else len(chunk)
                offset += sent
            rc = self._dll.cnc_dwnend3(c_ushort(handle))
            if rc != EW_OK:
                raise CncUnavailable(f"cnc_dwnend3 rc={rc}")
        finally:
            self._close(handle)

    def download(self, ip: str, port: int, o_number: str, destination: str) -> str:
        _ = destination
        number = int(normalize_o_number(o_number)[1:])
        handle = self._connect(ip, port)
        chunks: list[bytes] = []
        try:
            rc = self._dll.cnc_upstart3(c_ushort(handle), c_short(0), c_long(number), c_long(number))
            if rc != EW_OK:
                raise FileNotFoundError(o_number)
            while True:
                n = c_long(256)
                buf = create_string_buffer(256)
                rc = self._dll.cnc_upload3(c_ushort(handle), byref(n), buf)
                if rc == EW_OK and n.value > 0:
                    chunks.append(buf.raw[: int(n.value)])
                    continue
                if rc in (EW_RESET, EW_BUFFER) or n.value == 0:
                    break
                if rc != EW_OK:
                    break
            self._dll.cnc_upend3(c_ushort(handle))
        finally:
            self._close(handle)
        text = b"".join(chunks).decode("ascii", errors="replace")
        if not text.strip():
            raise FileNotFoundError(o_number)
        return text

    def destinations(self, ip: str, port: int) -> list[tuple[str, str, str]]:
        _ = (ip, port)
        return [("memory-path1", "CNC Memory PATH1", DEFAULT_DESTINATION)]
