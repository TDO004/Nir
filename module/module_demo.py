#!/usr/bin/env python3
"""Запускает захват + формирование признаков и печатает выдаваемые векторы
признаков (FeatureVector) — то, что модуль отдаёт наружу.
Запуск:
    sudo python3 module_demo.py                 # tap0..tap3
    sudo python3 module_demo.py tap0 tap1
"""
import os
import sys
import time

from traffic_capture import TrafficCapture, DEFAULT_IFACES
from processing import FeatureProcessor, FeatureVector


def _print_vector(fv: FeatureVector) -> None:
    pairs = ", ".join(f"{n}={v:.3g}" for n, v in zip(fv.names, fv.values))
    print(f"[ПРИЗНАКИ] {fv.flow_key}\n           {pairs}")


def main(interfaces) -> None:
    if os.geteuid() != 0:
        sys.exit("Нужны права root (sudo): eBPF/TC.")

    capture = TrafficCapture(interfaces)
    processor = FeatureProcessor(flow_timeout=60.0)

    print(f"[*] Модуль захвата и обработки на {', '.join(interfaces)} ... Ctrl+C для выхода")
    capture.start()
    last_flush = time.monotonic()
    try:
        while True:
            # пакеты -> потоки -> готовые векторы признаков
            for pkt in capture.read_events(timeout_ms=200):
                fv = processor.process(pkt)
                if fv is not None:
                    _print_vector(fv)
            # периодическая выгрузка потоков, протухших по таймауту
            now = time.monotonic()
            if now - last_flush >= 5.0:
                for fv in processor.flush_expired(now):
                    _print_vector(fv)
                last_flush = now
    except KeyboardInterrupt:
        print("\n[*] Останов ...")
    finally:
        capture.stop()


if __name__ == "__main__":
    main(sys.argv[1:] or list(DEFAULT_IFACES))
