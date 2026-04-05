"""
IDS (Intrusion Detection System) Integration
=============================================
JAIN Deemed-to-be University | Dept. of CSE | Cyber Law Survey 2025-2026
Authors: Devadeth Sunil, Abdul Hanooq Majeed, Belljer BL, Aravind P

This module extends the chaos-based C2 detection with a simple
Intrusion Detection System (IDS) that raises alerts and logs suspicious traffic.
"""

import numpy as np
import math
import datetime
import json
import os
from c2_detection import (
    generate_periodic_signal,
    generate_jittered_signal,
    generate_chaotic_signal,
    classify_signal,
    ButterflyOptimizer,
)


# ─────────────────────────────────────────────
# IDS ALERT LEVELS
# ─────────────────────────────────────────────

ALERT_LEVELS = {
    "LOW":       "INFO",
    "HIGH":      "WARNING",
    "VERY HIGH": "CRITICAL"
}


# ─────────────────────────────────────────────
# IDS ENGINE
# ─────────────────────────────────────────────

class IntrusionDetectionSystem:
    """
    A simple IDS that:
    - Monitors simulated network traffic (inter-arrival times)
    - Uses chaos-based metrics to classify beaconing behavior
    - Raises alerts for suspicious/malicious traffic
    - Logs all events to a file (ids_alerts.log)
    - Maintains a blocklist of flagged sources
    """

    def __init__(self, log_file: str = "ids_alerts.log"):
        self.log_file = log_file
        self.blocklist = set()       # Flagged IP addresses
        self.alert_count = 0
        self.total_inspected = 0

        # Initialize log file
        with open(self.log_file, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("IDS LOG — Chaos-Based C2 Detection System\n")
            f.write(f"Session started: {datetime.datetime.now()}\n")
            f.write("=" * 70 + "\n\n")

        print("=" * 60)
        print("  IDS — Chaos-Based C2 Intrusion Detection System")
        print("  JAIN University | Cyber Law Survey 2025-2026")
        print("=" * 60)
        print(f"  Log file: {os.path.abspath(self.log_file)}")
        print("=" * 60 + "\n")

    def _log(self, message: str):
        """Write a message to the log file."""
        with open(self.log_file, "a") as f:
            f.write(message + "\n")

    def _raise_alert(self, source_ip: str, result: dict):
        """Generate and display an IDS alert."""
        level = ALERT_LEVELS.get(result["threat_level"], "INFO")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "alert_level": level,
            "classification": result["classification"],
            "threat_level": result["threat_level"],
            "metrics": {
                "entropy": result["entropy"],
                "variance": result["variance"],
                "lyapunov": result["lyapunov"],
                "anomaly_score_F": result["anomaly_score_F"],
            },
            "action": "BLOCK" if level == "CRITICAL" else "MONITOR"
        }

        # Console output
        border = "🔴" if level == "CRITICAL" else "🟡" if level == "WARNING" else "🟢"
        print(f"{border} [{timestamp}] ALERT LEVEL: {level}")
        print(f"   Source IP    : {source_ip}")
        print(f"   Classification: {result['classification']} | Threat: {result['threat_level']}")
        print(f"   Entropy={result['entropy']}  Variance={result['variance']}  Lyapunov={result['lyapunov']}")
        print(f"   Anomaly Score F={result['anomaly_score_F']}")
        print(f"   Action       : {alert['action']}")
        print()

        # Log to file
        self._log(json.dumps(alert, indent=2))
        self._log("")

        return alert

    def inspect(self, source_ip: str, signal: np.ndarray, entropy_threshold: float = 1.5):
        """
        Inspect a traffic stream from a given source IP.

        Args:
            source_ip:         Simulated source IP address
            signal:            Inter-arrival time series (network beacon intervals)
            entropy_threshold: Threshold above which traffic is flagged
        """
        self.total_inspected += 1
        result = classify_signal(signal, entropy_threshold=entropy_threshold)
        alert = self._raise_alert(source_ip, result)

        # Block if critical
        if alert["action"] == "BLOCK":
            self.blocklist.add(source_ip)
            self.alert_count += 1
            print(f"  ⛔ IP {source_ip} added to BLOCKLIST\n")
            self._log(f">> BLOCKLIST UPDATE: {source_ip} blocked at {datetime.datetime.now()}\n")

        return alert

    def show_summary(self):
        """Print a summary of IDS session results."""
        print("=" * 60)
        print("  IDS SESSION SUMMARY")
        print("=" * 60)
        print(f"  Total streams inspected : {self.total_inspected}")
        print(f"  Critical alerts raised  : {self.alert_count}")
        print(f"  IPs in blocklist        : {len(self.blocklist)}")
        if self.blocklist:
            print(f"  Blocked IPs             : {', '.join(self.blocklist)}")
        print(f"  Full log saved to       : {os.path.abspath(self.log_file)}")
        print("=" * 60)

        summary = {
            "total_inspected": self.total_inspected,
            "critical_alerts": self.alert_count,
            "blocklist": list(self.blocklist)
        }
        self._log("\n== SESSION SUMMARY ==")
        self._log(json.dumps(summary, indent=2))


# ─────────────────────────────────────────────
# MAIN — SIMULATE NETWORK TRAFFIC & RUN IDS
# ─────────────────────────────────────────────

def run_ids():
    """
    Simulate traffic from 3 different sources and run IDS inspection.
    Each source represents a different type of C2 beaconing behavior.
    """
    np.random.seed(42)

    # Tune threshold using BOA
    boa = ButterflyOptimizer()
    sample_signal = generate_jittered_signal()
    threshold = boa.optimize(sample_signal)
    print(f"[BOA] Optimized entropy threshold: {threshold:.4f}\n")

    # Simulated traffic sources
    traffic = [
        ("192.168.1.10", generate_periodic_signal(),  "Normal workstation (periodic)"),
        ("10.0.0.45",    generate_jittered_signal(),   "Suspicious host (jittered APT)"),
        ("172.16.0.99",  generate_chaotic_signal(),    "State-sponsored C2 (chaotic)"),
    ]

    # Start IDS
    ids = IntrusionDetectionSystem()

    for ip, signal, description in traffic:
        print(f"── Inspecting: {description} [{ip}]")
        ids.inspect(ip, signal, entropy_threshold=threshold)

    ids.show_summary()


if __name__ == "__main__":
    run_ids()
