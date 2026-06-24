#!/usr/bin/env python3
"""Модуль захвата трафика (eBPF / BCC, TC clsact ingress).

Классы: PacketEvent, BpfProgramLoader, RingBufferReader, TrafficCapture.
Демо (печатает пойманные пакеты):
    sudo python3 traffic_capture.py                # tap0..tap3
    sudo python3 traffic_capture.py tap0 tap1      # только указанные
    sudo python3 traffic_capture.py br0            # на мосту
"""
import ctypes as ct
import os
import socket
import struct
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Union

BPF_SRC = Path(__file__).with_name("packet_capture.bpf.c")
DEFAULT_IFACES = ["tap0", "tap1", "tap2", "tap3"]
_PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}


class _PacketEventC(ct.Structure):
    """Зеркало struct packet_event_t из eBPF-программы."""
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("length", ct.c_uint16),
        ("protocol", ct.c_uint8),
        ("tcp_flags", ct.c_uint8),
    ]


def _ipv4(addr: int) -> str:
    # addr — u32 как прочитан из памяти ядра (нативный порядок); упаковка
    # тем же порядком воспроизводит исходные байты адреса -> верный IP.
    return socket.inet_ntoa(struct.pack("=I", addr))


@dataclass
class PacketEvent:
    """Метаданные одного пакета, пришедшие из ядра."""
    ts: float            # секунды (монотонные, bpf_ktime_get_ns)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    tcp_flags: int

    @classmethod
    def from_kernel(cls, e: _PacketEventC) -> "PacketEvent":
        return cls(
            ts=e.ts_ns / 1e9,
            src_ip=_ipv4(e.saddr),
            dst_ip=_ipv4(e.daddr),
            src_port=e.sport,
            dst_port=e.dport,
            protocol=e.protocol,
            length=e.length,
            tcp_flags=e.tcp_flags,
        )

    @property
    def proto_name(self) -> str:
        return _PROTO_NAME.get(self.protocol, str(self.protocol))


class BpfProgramLoader:
    """Компилирует eBPF-программу и цепляет её к интерфейсам через TC clsact (ingress)."""

    def __init__(self, interfaces: Union[str, Sequence[str]] = DEFAULT_IFACES,
                 src_path: Path = BPF_SRC):
        self.interfaces: List[str] = [interfaces] if isinstance(interfaces, str) else list(interfaces)
        self.src_path = Path(src_path)
        self.bpf = None
        self._ipr = None
        self._idxs: List[int] = []

    def load(self):
        from bcc import BPF
        self.bpf = BPF(src_file=str(self.src_path))
        return self.bpf

    def attach(self) -> None:
        from bcc import BPF
        from pyroute2 import IPRoute
        if self.bpf is None:
            self.load()

        fn = self.bpf.load_func("capture", BPF.SCHED_CLS)
        self._ipr = IPRoute()

        for ifname in self.interfaces:
            found = self._ipr.link_lookup(ifname=ifname)
            if not found:
                print(f"[!] интерфейс {ifname} не найден — пропуск")
                continue
            idx = found[0]
            try:
                self._ipr.tc("add", "clsact", idx)      # точка подвеса
            except Exception:
                pass                                    # qdisc уже есть
            self._ipr.tc("add-filter", "bpf", idx, ":1",
                         fd=fn.fd, name=fn.name,
                         parent="ffff:fff2",            # ingress
                         classid=1, direct_action=True)
            self._idxs.append(idx)

        if not self._idxs:
            raise RuntimeError("не удалось подключиться ни к одному интерфейсу")

    def detach(self) -> None:
        if self._ipr is not None:
            for idx in self._idxs:
                try:
                    self._ipr.tc("del", "clsact", idx)
                except Exception:
                    pass
            self._ipr.close()
            self._ipr = None
        self._idxs = []
        self.bpf = None   # BCC освободит ресурсы при сборке мусора

    def ring_buffer(self):
        return self.bpf["events"]


class RingBufferReader:
    """Опрашивает ring buffer и декодирует события в PacketEvent."""

    def __init__(self, bpf, table):
        self._bpf = bpf
        self._table = table
        self._queue: deque = deque()
        self._table.open_ring_buffer(self._on_event)

    def _on_event(self, ctx, data, size) -> None:
        e = ct.cast(data, ct.POINTER(_PacketEventC)).contents
        self._queue.append(PacketEvent.from_kernel(e))

    def poll(self, timeout_ms: int = 200) -> None:
        self._bpf.ring_buffer_poll(timeout_ms)

    def read_events(self, timeout_ms: int = 200) -> Iterator[PacketEvent]:
        self.poll(timeout_ms)
        while self._queue:
            yield self._queue.popleft()


class TrafficCapture:
    """Фасад модуля захвата: запуск eBPF и выдача потока PacketEvent."""

    def __init__(self, interfaces: Union[str, Sequence[str]] = DEFAULT_IFACES,
                 src_path: Path = BPF_SRC):
        self.loader = BpfProgramLoader(interfaces, src_path)
        self.reader: Optional[RingBufferReader] = None

    def start(self) -> None:
        bpf = self.loader.load()
        self.loader.attach()
        self.reader = RingBufferReader(bpf, self.loader.ring_buffer())

    def stop(self) -> None:
        self.loader.detach()
        self.reader = None

    def read_events(self, timeout_ms: int = 200) -> Iterator[PacketEvent]:
        if self.reader is None:
            raise RuntimeError("TrafficCapture не запущен — вызовите start()")
        yield from self.reader.read_events(timeout_ms)


def _demo(interfaces: List[str]) -> None:
    if os.geteuid() != 0:
        sys.exit("Нужны права root (sudo): eBPF/TC.")
    cap = TrafficCapture(interfaces)
    print(f"[*] Захват на {', '.join(interfaces)} ... Ctrl+C для выхода")
    cap.start()
    print(f"{'время':>12}  {'proto':<5} {'источник':<22} ->"
          f" {'назначение':<22} {'len':>5}  флаги")
    try:
        while True:
            for p in cap.read_events():
                src = f"{p.src_ip}:{p.src_port}"
                dst = f"{p.dst_ip}:{p.dst_port}"
                print(f"{p.ts:12.3f}  {p.proto_name:<5} {src:<22} ->"
                      f" {dst:<22} {p.length:>5}  0x{p.tcp_flags:02x}")
    except KeyboardInterrupt:
        print("\n[*] Останов ...")
    finally:
        cap.stop()


if __name__ == "__main__":
    ifaces = sys.argv[1:] or DEFAULT_IFACES
    _demo(ifaces)
