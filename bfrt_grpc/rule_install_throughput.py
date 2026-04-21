#!/usr/bin/env python3
"""
Pure Python BFRT rule-install throughput benchmark.

Tune batch size for `entry_add_batch` and report best value.
"""

import argparse
import csv
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List

from bfrt_controller import Bfrt_GRPC_Client, flow_key, int_to_ip, unpack_flow_key, gc


@dataclass
class TrialResult:
    batch_size: int
    round_idx: int
    target_rules: int
    installed_rules: int
    dropped_rules: int
    elapsed_sec: float
    throughput_rps: float
    batch_fail_count: int


def clear_table_state(controller: Bfrt_GRPC_Client, settle_sec: float = 0.05) -> None:
    """Force clear active table state between benchmark trials."""
    controller.clear_service_table()
    if settle_sec > 0:
        time.sleep(settle_sec)


def entry_add_batch_strict(controller: Bfrt_GRPC_Client, keys_batch: List[int]) -> int:
    """
    Strict batch add: single BFRT batch call, no per-entry fallback.
    Return number of installed rules for this batch (0 if batch failed).
    """
    if not keys_batch:
        return 0

    keys_batch = [k for k in keys_batch if k not in controller.installed_flows]
    if not keys_batch:
        return 0

    key_list = []
    data_list = []
    for k in keys_batch:
        ip_int, port, proto = unpack_flow_key(k)
        service_key = controller.service_table.make_key(
            [
                gc.KeyTuple("meta.internal_ip", int_to_ip(ip_int)),
                gc.KeyTuple("meta.internal_port", port),
                gc.KeyTuple("meta.ip_protocol", proto),
            ]
        )
        key_list.append(service_key)
        data_list.append(
            controller.service_table.make_data(
                [gc.DataTuple("$ENTRY_TTL", controller.entry_ttl)],
                "Ingress.drop",
            )
        )

    controller.service_table.entry_add(controller.target, key_list, data_list)
    for k in keys_batch:
        controller.installed_flows.add(k)
    return len(keys_batch)


def parse_batch_sizes(raw: str) -> List[int]:
    values = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item)
        if value <= 0:
            raise ValueError(f"batch size must be > 0, got {value}")
        values.append(value)
    if not values:
        raise ValueError("empty batch size list")
    # Deduplicate while preserving order.
    uniq = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        uniq.append(value)
    return uniq


def generate_flow_keys(total_rules: int, seed: int) -> List[int]:
    """
    Build deterministic unique 5-tuples encoded as flow_key(ip, port, proto).
    ip space: 10.0.0.1~10.255.255.255 (up to 16,777,215 unique).
    """
    max_rules = (1 << 24) - 1
    if total_rules > max_rules:
        raise ValueError(f"total_rules must be <= {max_rules}")

    rng = random.Random(seed)
    keys = []
    for i in range(total_rules):
        ip_host = i + 1
        ip_int = (10 << 24) | ip_host
        port = 1024 + (i % (65535 - 1024))
        proto = 6 if (i % 2 == 0) else 17
        keys.append(flow_key(ip_int, port, proto))
    rng.shuffle(keys)
    return keys


def run_one_trial(controller: Bfrt_GRPC_Client, keys: List[int], batch_size: int) -> TrialResult:
    # Always clear before every trial to avoid cross-round residue.
    clear_table_state(controller)

    start = time.perf_counter()
    installed = 0
    batch_fail = 0
    for i in range(0, len(keys), batch_size):
        chunk = keys[i : i + batch_size]
        try:
            installed += entry_add_batch_strict(controller, chunk)
        except Exception:
            batch_fail += 1
    elapsed = time.perf_counter() - start
    throughput = installed / elapsed if elapsed > 0 else 0.0
    dropped = len(keys) - installed
    # Also clear after trial so next round starts from a known clean state.
    clear_table_state(controller)
    return TrialResult(
        batch_size=batch_size,
        round_idx=0,
        target_rules=len(keys),
        installed_rules=installed,
        dropped_rules=dropped,
        elapsed_sec=elapsed,
        throughput_rps=throughput,
        batch_fail_count=batch_fail,
    )


def save_csv(csv_path: str, rows: List[TrialResult]) -> None:
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "timestamp",
                "batch_size",
                "round",
                "target_rules",
                "installed_rules",
                "dropped_rules",
                "elapsed_sec",
                "throughput_rules_per_sec",
                "batch_fail_count",
            ]
        )
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for row in rows:
            writer.writerow(
                [
                    now,
                    row.batch_size,
                    row.round_idx,
                    row.target_rules,
                    row.installed_rules,
                    row.dropped_rules,
                    f"{row.elapsed_sec:.6f}",
                    f"{row.throughput_rps:.2f}",
                    row.batch_fail_count,
                ]
            )


def main():
    parser = argparse.ArgumentParser(
        description="Measure BFRT rule install throughput and tune best batch size."
    )
    parser.add_argument(
        "--grpc-addr",
        default="192.168.24.69:50052",
        help="BFRT gRPC address",
    )
    parser.add_argument(
        "--total-rules",
        type=int,
        default=50000,
        help="Rules installed per round",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Benchmark rounds per batch size",
    )
    parser.add_argument(
        "--batch-sizes",
        default="64,128,256,512,1024,2048",
        help="Comma-separated candidate batch sizes",
    )
    parser.add_argument(
        "--entry-ttl",
        type=int,
        default=5000,
        help="Entry TTL in ms for installed rules",
    )
    parser.add_argument(
        "--clean-batch-size",
        type=int,
        default=1000,
        help="Idle clean batch size for client init",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260421,
        help="Shuffle seed for test rule order",
    )
    parser.add_argument(
        "--csv",
        default="log/runs/latest/rule_install_throughput.csv",
        help="Result CSV path",
    )
    args = parser.parse_args()

    if args.total_rules <= 0:
        raise ValueError("--total-rules must be > 0")
    if args.rounds <= 0:
        raise ValueError("--rounds must be > 0")

    batch_sizes = parse_batch_sizes(args.batch_sizes)
    all_keys = generate_flow_keys(args.total_rules, args.seed)

    print("=== BFRT rule install throughput benchmark ===")
    print(f"grpc_addr      : {args.grpc_addr}")
    print(f"total_rules    : {args.total_rules}")
    print(f"rounds         : {args.rounds}")
    print(f"batch_sizes    : {batch_sizes}")
    print(f"csv            : {args.csv}")
    print("")

    controller = Bfrt_GRPC_Client(
        grpc_addr=args.grpc_addr,
        entry_ttl=args.entry_ttl,
        clean_batch_size=args.clean_batch_size,
    )

    trial_rows: List[TrialResult] = []
    avg_by_batch = {}

    try:
        # Ensure clean state before starting the first batch-size test.
        clear_table_state(controller)
        for batch in batch_sizes:
            print(f"[batch={batch}]")
            throughputs = []
            for r in range(1, args.rounds + 1):
                result = run_one_trial(controller, all_keys, batch)
                result.round_idx = r
                trial_rows.append(result)
                throughputs.append(result.throughput_rps)
                ok_ratio = (result.installed_rules / result.target_rules) * 100.0
                print(
                    f"  round {r}: installed={result.installed_rules}/{result.target_rules} "
                    f"({ok_ratio:.2f}%), elapsed={result.elapsed_sec:.4f}s, "
                    f"throughput={result.throughput_rps:.2f} rules/s, "
                    f"batch_fail={result.batch_fail_count}, dropped={result.dropped_rules}"
                )
                time.sleep(0.1)
            avg_tp = sum(throughputs) / len(throughputs)
            avg_by_batch[batch] = avg_tp
            print(f"  avg throughput: {avg_tp:.2f} rules/s")
            print("")
    finally:
        # Restore a clean table state for post-benchmark controller usage.
        try:
            controller.clear_service_table()
        except Exception:
            pass

    best_batch = max(avg_by_batch, key=avg_by_batch.get)
    best_tp = avg_by_batch[best_batch]

    save_csv(args.csv, trial_rows)

    print("=== Tuning result ===")
    for batch in batch_sizes:
        mark = " <-- best" if batch == best_batch else ""
        print(f"batch={batch:>4}: avg={avg_by_batch[batch]:.2f} rules/s{mark}")
    print("")
    print(f"Best batch size: {best_batch}")
    print(f"Best avg throughput: {best_tp:.2f} rules/s")
    print(f"CSV saved to: {args.csv}")


if __name__ == "__main__":
    main()
