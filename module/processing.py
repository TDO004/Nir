#!/usr/bin/env python3
"""Подсистема обработки трафика.

Превращает поток PacketEvent в потоки (Flow) и считает по ним
вектор признаков (FeatureVector). Классы:
FlowKey, Flow, FlowTable, FeatureVector, FeatureExtractor, FeatureProcessor.
"""
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from traffic_capture import PacketEvent


@dataclass(frozen=True)
class FlowKey:
    """Канонический ключ потока (обе стороны соединения дают один ключ)."""
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: PacketEvent) -> "FlowKey":
        side1 = (pkt.src_ip, pkt.src_port)
        side2 = (pkt.dst_ip, pkt.dst_port)
        lo, hi = sorted((side1, side2))
        return cls(lo[0], lo[1], hi[0], hi[1], pkt.protocol)

    def __str__(self) -> str:
        return f"{self.ip_a}:{self.port_a} <-> {self.ip_b}:{self.port_b} (proto {self.protocol})"


@dataclass
class Flow:
    """Накопленная статистика одного потока."""
    key: FlowKey
    start_ts: float
    last_ts: float
    init_src: Tuple[str, int]            # (ip, port) первого пакета -> прямое направление
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)
    iat: List[float] = field(default_factory=list)   # межпакетные интервалы
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0
    _rst_seen: bool = False
    _fin_count: int = 0

    @classmethod
    def from_packet(cls, pkt: PacketEvent) -> "Flow":
        return cls(key=FlowKey.from_packet(pkt), start_ts=pkt.ts, last_ts=pkt.ts,
                   init_src=(pkt.src_ip, pkt.src_port))

    def add_packet(self, pkt: PacketEvent) -> None:
        forward = (pkt.src_ip, pkt.src_port) == self.init_src
        if pkt.ts > self.last_ts:
            self.iat.append(pkt.ts - self.last_ts)
        self.last_ts = max(self.last_ts, pkt.ts)

        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
            self.fwd_lengths.append(pkt.length)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.length
            self.bwd_lengths.append(pkt.length)

        f = pkt.tcp_flags                 # биты: fin,syn,rst,psh,ack,urg
        self.fin += f & 1
        self.syn += (f >> 1) & 1
        self.rst += (f >> 2) & 1
        self.psh += (f >> 3) & 1
        self.ack += (f >> 4) & 1
        self.urg += (f >> 5) & 1
        if (f >> 2) & 1:
            self._rst_seen = True
        if f & 1:
            self._fin_count += 1

    def duration(self) -> float:
        return self.last_ts - self.start_ts

    def is_expired(self, now: float, timeout: float) -> bool:
        return (now - self.last_ts) >= timeout

    def is_finished(self) -> bool:
        # RST или FIN с обеих сторон -> соединение закрыто
        return self._rst_seen or self._fin_count >= 2


class FlowTable:
    """Таблица активных потоков по каноническому ключу."""

    def __init__(self, timeout: float = 60.0):
        self.flows: Dict[FlowKey, Flow] = {}
        self.timeout = timeout

    def update(self, pkt: PacketEvent) -> Flow:
        key = FlowKey.from_packet(pkt)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow.from_packet(pkt)
            self.flows[key] = flow
        flow.add_packet(pkt)
        return flow

    def remove(self, key: FlowKey) -> None:
        self.flows.pop(key, None)

    def pop_expired(self, now: float) -> List[Flow]:
        expired = [f for f in self.flows.values() if f.is_expired(now, self.timeout)]
        for f in expired:
            self.flows.pop(f.key, None)
        return expired


# Набор признаков (CICFlowMeter-подобный). ВАЖНО: тот же список и порядок
# должны использоваться при обучении модели — см. README.
FEATURE_NAMES: List[str] = [
    "duration", "fwd_packets", "bwd_packets", "total_packets",
    "fwd_bytes", "bwd_bytes",
    "fwd_len_mean", "bwd_len_mean", "fwd_len_max", "bwd_len_max",
    "flow_bytes_per_s", "flow_packets_per_s",
    "iat_mean", "iat_std",
    "syn", "ack", "fin", "rst", "psh",
    "down_up_ratio",
]


@dataclass
class FeatureVector:
    """Цифровой профиль потока — вход модели."""
    flow_key: FlowKey
    values: List[float]
    names: List[str] = field(default_factory=lambda: list(FEATURE_NAMES))

    def to_array(self) -> np.ndarray:
        return np.asarray(self.values, dtype=float).reshape(1, -1)


def _mean(xs: List[float]) -> float:
    return float(sum(xs) / len(xs)) if xs else 0.0


def _max(xs: List[float]) -> float:
    return float(max(xs)) if xs else 0.0


def _std(xs: List[float]) -> float:
    return float(statistics.pstdev(xs)) if len(xs) > 1 else 0.0


class FeatureExtractor:
    """Считает FeatureVector по завершённому/просроченному потоку."""

    def __init__(self):
        self.feature_names = list(FEATURE_NAMES)

    def extract(self, flow: Flow) -> FeatureVector:
        dur = max(flow.duration(), 1e-6)
        total_pkts = flow.fwd_packets + flow.bwd_packets
        total_bytes = flow.fwd_bytes + flow.bwd_bytes
        values = [
            flow.duration(),
            flow.fwd_packets, flow.bwd_packets, total_pkts,
            flow.fwd_bytes, flow.bwd_bytes,
            _mean(flow.fwd_lengths), _mean(flow.bwd_lengths),
            _max(flow.fwd_lengths), _max(flow.bwd_lengths),
            total_bytes / dur, total_pkts / dur,
            _mean(flow.iat), _std(flow.iat),
            flow.syn, flow.ack, flow.fin, flow.rst, flow.psh,
            (flow.bwd_packets / flow.fwd_packets) if flow.fwd_packets else 0.0,
        ]
        return FeatureVector(flow_key=flow.key,
                             values=[float(v) for v in values],
                             names=self.feature_names)


class FeatureProcessor:
    """Фасад обработки: пакет -> поток -> (при готовности) вектор признаков."""

    def __init__(self, flow_timeout: float = 60.0):
        self.flow_table = FlowTable(flow_timeout)
        self.extractor = FeatureExtractor()

    def process(self, pkt: PacketEvent) -> Optional[FeatureVector]:
        flow = self.flow_table.update(pkt)
        if flow.is_finished():
            self.flow_table.remove(flow.key)
            return self.extractor.extract(flow)
        return None

    def flush_expired(self, now: float) -> List[FeatureVector]:
        return [self.extractor.extract(f) for f in self.flow_table.pop_expired(now)]
