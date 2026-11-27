import statistics
import time
from typing import Dict, List

from backend.crypto.container import VaultContainer
from backend.crypto.engine import DecryptionError

REAL_PW, DECOY_PW, WRONG_PW = "real_pw", "decoy_pw", "wrong_pw"
MAX_SKEW = 0.10  # medians must be within 10%


def _percentile(sorted_ms: List[float], q: float) -> float:
    idx = min(len(sorted_ms) - 1, max(0, round(q * (len(sorted_ms) - 1))))
    return sorted_ms[idx]


def benchmark_unlock_timing(n: int = 30, container: VaultContainer | None = None) -> Dict[str, object]:
    """Warm-up, then n alternating real / decoy / wrong-password unlocks of a synthetic container."""
    c = container or VaultContainer()
    blob = c.build(REAL_PW, b"real", duress_password=DECOY_PW, decoy_data=b"decoy")

    def unlock_ms(password: str) -> float:
        t0 = time.perf_counter()
        try:
            c.unlock(password, blob)
        except DecryptionError:
            pass
        return (time.perf_counter() - t0) * 1000

    kinds = [("real", REAL_PW), ("decoy", DECOY_PW), ("wrong", WRONG_PW)]
    for _ in range(3):  # warm-up: CPU frequency ramp and allocator settle
        for _, pw in kinds:
            unlock_ms(pw)

    samples: Dict[str, List[float]] = {k: [] for k, _ in kinds}
    for i in range(n):
        # Alternate, rotating which kind goes first, so drift hits all three equally
        for kind, pw in kinds[i % 3 :] + kinds[: i % 3]:
            samples[kind].append(unlock_ms(pw))

    stats = {}
    for kind, ms in samples.items():
        s = sorted(ms)
        stats[kind] = {
            "median_ms": round(statistics.median(s), 3),
            "p10_ms": round(_percentile(s, 0.10), 3),
            "p90_ms": round(_percentile(s, 0.90), 3),
            "samples_ms": [round(x, 3) for x in ms],
        }

    real_med = max(stats["real"]["median_ms"], 1e-6)
    decoy_ratio = round(stats["decoy"]["median_ms"] / real_med, 3)
    wrong_ratio = round(stats["wrong"]["median_ms"] / real_med, 3)
    return {
        "trials": n,
        **stats,
        "decoy_vs_real_ratio": decoy_ratio,
        "wrong_vs_real_ratio": wrong_ratio,
        "constant_time_pass": abs(decoy_ratio - 1) <= MAX_SKEW and abs(wrong_ratio - 1) <= MAX_SKEW,
    }
