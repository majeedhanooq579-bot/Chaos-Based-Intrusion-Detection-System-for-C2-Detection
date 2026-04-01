"""
State-Sponsored C2 Detection via Chaotic Analysis
==================================================
JAIN Deemed-to-be University | Dept. of CSE | Cyber Law Survey 2025-2026
Authors: Devadeth Sunil, Abdul Hanooq Majeed, Belljer BL, Aravind P

This module implements chaos-based detection techniques for identifying
stealthy Command-and-Control (C2) beaconing patterns used by APTs.
"""

import numpy as np
import math
from typing import List, Tuple


# ─────────────────────────────────────────────
# 1. SIGNAL GENERATION
# ─────────────────────────────────────────────

def generate_periodic_signal(n: int = 100, interval: float = 5.0) -> np.ndarray:
    """
    Simulate fixed-interval beaconing (basic malware).
    Returns inter-arrival times with near-zero variance.
    """
    return np.full(n, interval, dtype=float)


def generate_jittered_signal(n: int = 100, base: float = 5.0, jitter: float = 0.5) -> np.ndarray:
    """
    Simulate jittered beaconing (APT-style evasion).
    Small random variations around a mean interval.
    """
    return np.abs(np.random.normal(loc=base, scale=jitter, size=n))


def generate_chaotic_signal(n: int = 100) -> np.ndarray:
    """
    Simulate fully chaotic beaconing (state-sponsored APTs).
    Uses logistic map to generate chaotic inter-arrival times.
    r=3.99 puts the logistic map into full chaos.
    """
    r = 3.99
    x = [0.5]
    for _ in range(n - 1):
        x.append(r * x[-1] * (1 - x[-1]))
    # Scale to seconds (1–10s range)
    return np.array(x) * 9 + 1


# ─────────────────────────────────────────────
# 2. MATHEMATICAL METRICS
# ─────────────────────────────────────────────

def compute_shannon_entropy(signal: np.ndarray, bins: int = 10) -> float:
    """
    Compute Shannon Entropy H(X) = -Σ p(x) log₂ p(x)

    Higher entropy → greater randomness → likely stealthy/obfuscated C2.
    Low entropy → predictable, periodic behavior.

    Args:
        signal: Array of inter-arrival times
        bins:   Number of histogram bins for probability estimation

    Returns:
        Shannon entropy value (bits)
    """
    counts, _ = np.histogram(signal, bins=bins)
    probs = counts / counts.sum()
    probs = probs[probs > 0]  # Avoid log(0)
    return float(-np.sum(probs * np.log2(probs)))


def compute_lyapunov_exponent(signal: np.ndarray) -> float:
    """
    Estimate the Lyapunov Exponent λ using the Rosenstein method
    (simplified 1D approximation for time-series).

    λ = lim(t→∞) (1/t) ln |δX(t)/δX(0)|

    Interpretation:
        λ > 0 → Chaotic (sensitive to initial conditions) — APT indicator
        λ ≈ 0 → Periodic (stable, predictable)
        λ < 0 → Converging (damped)

    Args:
        signal: Array of inter-arrival times

    Returns:
        Estimated Lyapunov exponent
    """
    n = len(signal)
    if n < 2:
        return 0.0

    divergences = []
    for i in range(n - 1):
        delta_0 = abs(signal[i + 1] - signal[i]) + 1e-10  # Avoid log(0)
        delta_t = abs(signal[min(i + 2, n - 1)] - signal[i]) + 1e-10
        divergences.append(math.log(delta_t / delta_0))

    return float(np.mean(divergences))


def compute_variance(signal: np.ndarray) -> float:
    """
    Compute variance of inter-arrival times.

    High variance → jitter or chaotic behavior.
    Low variance → stable, periodic beaconing.
    """
    return float(np.var(signal))


# ─────────────────────────────────────────────
# 3. OBJECTIVE FUNCTION
# ─────────────────────────────────────────────

def compute_objective_function(
    lam: float,
    entropy: float,
    periodicity_score: float,
    alpha: float = 0.4,
    beta: float = 0.4,
    gamma: float = 0.2
) -> float:
    """
    Multi-metric anomaly score: F = α·λ + β·H − γ·P

    Higher F → greater likelihood of malicious/anomalous activity.

    Args:
        lam:               Lyapunov exponent
        entropy:           Shannon entropy
        periodicity_score: Score for how periodic the signal is (0=random, 1=periodic)
        alpha, beta, gamma: Weighting coefficients

    Returns:
        Anomaly score F
    """
    return alpha * lam + beta * entropy - gamma * periodicity_score


def compute_periodicity_score(signal: np.ndarray) -> float:
    """
    Estimate periodicity as inverse of normalized standard deviation.
    Score near 1 → very periodic; near 0 → chaotic/random.
    """
    mean = np.mean(signal)
    if mean == 0:
        return 0.0
    cv = np.std(signal) / mean  # Coefficient of variation
    return float(1.0 / (1.0 + cv))


# ─────────────────────────────────────────────
# 4. BUTTERFLY OPTIMIZATION ALGORITHM (BOA)
# ─────────────────────────────────────────────

class ButterflyOptimizer:
    """
    Simplified Butterfly Optimization Algorithm (BOA) for
    adaptive threshold tuning in C2 anomaly detection.

    Based on: Arora & Singh, Soft Computing, 2019.

    Fragrance model: f_i = c × I^a
    where I = stimulus intensity (fitness value).
    """

    def __init__(
        self,
        n_butterflies: int = 20,
        n_iterations: int = 50,
        c: float = 0.01,
        a: float = 0.1,
        p: float = 0.8,
    ):
        self.n = n_butterflies
        self.iterations = n_iterations
        self.c = c       # Sensory modality constant
        self.a = a       # Power exponent
        self.p = p       # Switch probability (global vs local search)

    def fragrance(self, fitness: float) -> float:
        """Compute perceived fragrance from fitness value."""
        return self.c * (abs(fitness) ** self.a)

    def optimize(
        self,
        signal: np.ndarray,
        threshold_range: Tuple[float, float] = (0.5, 5.0)
    ) -> float:
        """
        Find the optimal detection threshold for a given signal
        by maximizing separation between anomalous and normal traffic.

        Args:
            signal:          Inter-arrival time series
            threshold_range: (min, max) bounds for threshold search

        Returns:
            Optimal threshold value
        """
        low, high = threshold_range
        # Initialize butterfly positions (candidate thresholds)
        positions = np.random.uniform(low, high, self.n)
        best_pos = positions[0]
        best_fitness = -np.inf

        entropy = compute_shannon_entropy(signal)

        for _ in range(self.iterations):
            fitnesses = []
            for pos in positions:
                # Fitness: reward thresholds that correctly flag chaotic signals
                detected = float(entropy > pos)
                fitness = detected * entropy - abs(pos - entropy)
                fitnesses.append(fitness)

                if fitness > best_fitness:
                    best_fitness = fitness
                    best_pos = pos

            # Update positions
            fragrances = [self.fragrance(f) for f in fitnesses]
            new_positions = []
            for i, pos in enumerate(positions):
                r = np.random.random()
                if r < self.p:
                    # Global search: move toward best
                    step = (np.random.random() ** 2) * best_pos - pos
                    new_pos = pos + step * fragrances[i]
                else:
                    # Local search: move toward random neighbor
                    j, k = np.random.choice(self.n, 2, replace=False)
                    step = (np.random.random() ** 2) * positions[j] - positions[k]
                    new_pos = pos + step * fragrances[i]
                new_positions.append(np.clip(new_pos, low, high))
            positions = np.array(new_positions)

        return float(best_pos)


# ─────────────────────────────────────────────
# 5. CLASSIFIER
# ─────────────────────────────────────────────

def classify_signal(signal: np.ndarray, entropy_threshold: float = 1.0) -> dict:
    """
    Classify a beaconing signal as Periodic, Jittered, or Chaotic
    using entropy, variance, and Lyapunov exponent.

    Args:
        signal:            Inter-arrival time series
        entropy_threshold: Threshold above which signal is flagged as anomalous

    Returns:
        Dictionary with metrics and classification label
    """
    variance = compute_variance(signal)
    entropy = compute_shannon_entropy(signal)
    lyapunov = compute_lyapunov_exponent(signal)
    periodicity = compute_periodicity_score(signal)
    anomaly_score = compute_objective_function(lyapunov, entropy, periodicity)

    if variance < 0.01 and entropy < 0.5:
        label = "Periodic"
        threat_level = "LOW"
    elif variance < 1.0 and entropy < entropy_threshold:
        label = "Jittered"
        threat_level = "HIGH"
    else:
        label = "Chaotic"
        threat_level = "VERY HIGH"

    return {
        "variance": round(variance, 4),
        "entropy": round(entropy, 4),
        "lyapunov": round(lyapunov, 4),
        "periodicity_score": round(periodicity, 4),
        "anomaly_score_F": round(anomaly_score, 4),
        "classification": label,
        "threat_level": threat_level,
    }


# ─────────────────────────────────────────────
# 6. MAIN DEMO
# ─────────────────────────────────────────────

def run_experiment():
    """
    Reproduce the experimental results from Section 9 of the survey.
    Generates periodic, jittered, and chaotic signals and classifies them.
    """
    print("=" * 60)
    print("C2 Detection via Chaotic Analysis — Experiment Demo")
    print("JAIN University | Cyber Law Survey 2025-2026")
    print("=" * 60)

    np.random.seed(42)

    signals = {
        "Periodic": generate_periodic_signal(),
        "Jittered": generate_jittered_signal(),
        "Chaotic":  generate_chaotic_signal(),
    }

    # Tune threshold using BOA on the jittered signal
    boa = ButterflyOptimizer()
    opt_threshold = boa.optimize(signals["Jittered"])
    print(f"\n[BOA] Optimal entropy threshold: {opt_threshold:.4f}\n")

    print(f"{'Signal Type':<12} {'Variance':>10} {'Entropy':>10} {'Lyapunov':>10} {'F-Score':>10} {'Label':<12} {'Threat'}")
    print("-" * 80)

    for name, signal in signals.items():
        result = classify_signal(signal, entropy_threshold=opt_threshold)
        print(
            f"{name:<12} "
            f"{result['variance']:>10.4f} "
            f"{result['entropy']:>10.4f} "
            f"{result['lyapunov']:>10.4f} "
            f"{result['anomaly_score_F']:>10.4f} "
            f"{result['classification']:<12} "
            f"{result['threat_level']}"
        )

    print("\n[Done] See survey Section 9 for full analysis.")


if __name__ == "__main__":
    run_experiment()
