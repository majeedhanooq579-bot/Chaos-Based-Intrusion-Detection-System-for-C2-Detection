# State-Sponsored C2 Detection via Chaotic Analysis

> **JAIN Deemed-to-be University | Dept. of CSE | Cyber Law Survey 2025–2026**  
> Authors: Devadeth Sunil · Abdul Hanooq Majeed · Belljer BL · Aravind P

---

## 📄 Overview

This repository contains the **source code implementation** accompanying the survey paper:

> *"State-Sponsored C2 Detection via Chaotic Analysis: A Comprehensive Survey"*

Advanced Persistent Threats (APTs) use stealthy **Command-and-Control (C2)** channels with highly jittered, non-periodic beaconing to evade detection. This project implements chaos-based detection techniques **integrated with an Intrusion Detection System (IDS)** that automatically alerts and blocks malicious sources.

---

## 📁 Repository Structure

```
Chaos-Based-Intrusion-Detection-System-for-C2-Detection/
│
├── C2-detection.py       # Core chaos-based detection algorithms
├── ids_integration.py    # IDS engine — alerts, blocking, logging
├── README.md             # This file
├── requirements.txt      # Python dependencies
└── Survey paper.pdf      # Full survey paper
```

---

## ⚙️ How It Works

```
Network Traffic (beacon intervals)
        ↓
C2-detection.py
  → Shannon Entropy
  → Lyapunov Exponent
  → BOA Threshold Tuning
  → Anomaly Score F = α·λ + β·H − γ·P
        ↓
ids_integration.py (IDS Engine)
  → 🟢 LOW      → MONITOR
  → 🟡 HIGH     → WARNING
  → 🔴 VERY HIGH → BLOCK IP ⛔ + Log Alert
```

---

## 🔬 Taxonomy of C2 Beaconing

| Category | Pattern | Math Property | Detection Difficulty | Example |
|----------|---------|---------------|---------------------|---------|
| Periodic | Fixed interval | λ ≈ 0 | Low | Basic malware |
| Randomized | Pseudorandom | Medium entropy | Medium | Commodity malware |
| Jittered | Slight variation | λ > 0 (low) | High | APTs |
| Chaotic | Nonlinear | High λ, high H | Very High | State-sponsored |

---

## 🛡️ IDS Features

- **Real-time monitoring** of network traffic streams
- **Chaos-based classification** — Periodic / Jittered / Chaotic
- **Three alert levels** — INFO / WARNING / CRITICAL
- **Automatic IP blocking** when anomaly score exceeds BOA-optimized threshold
- **Alert logging** — all events saved to `ids_alerts.log`

---

## ⚙️ Setup & Usage

### 1. Clone the repository
```bash
git clone https://github.com/majeedhanooq579-bot/Chaos-Based-Intrusion-Detection-System-for-C2-Detection.git
cd Chaos-Based-Intrusion-Detection-System-for-C2-Detection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run core detection only
```bash
python C2-detection.py
```

### 4. Run with IDS
```bash
python ids_integration.py
```

### Expected IDS Output
```
[BOA] Optimized entropy threshold: 3.0007

🟢 192.168.1.10 → Periodic   → MONITOR
🔴 10.0.0.45    → Chaotic    → BLOCK ⛔
🔴 172.16.0.99  → Chaotic    → BLOCK ⛔

IDS SESSION SUMMARY
Total streams inspected : 3
Critical alerts raised  : 2
IPs in blocklist        : 2
```

---

## 🧮 Key Algorithms

### Shannon Entropy
```
H(X) = -Σ p(x) log₂ p(x)
```

### Lyapunov Exponent
```
λ = lim(t→∞) (1/t) ln |δX(t)/δX(0)|
```

### Objective Function
```
F = α·λ + β·H − γ·P
```

### BOA Fragrance Model
```
f_i = c × I^a
```

---

## 📚 References

- MITRE ATT&CK Framework — Command and Control Techniques, 2023
- ENISA — Advanced Persistent Threats: Overview, 2021
- A. Arora & S. Singh — Butterfly Optimization Algorithm, Soft Computing, 2019
- J. Yu — Entropy-based anomaly detection, IEEE Access, 2018
- Future Generation Computer Systems — Identifying APTs via Chaotic Network Analysis, 2024

---

## ⚖️ Legal-Technical Mapping

| Technology | Legal Relevance | Gap |
|-----------|----------------|-----|
| Chaos Detection | Strong attribution evidence | Not standardized in courts |
| IDS Alerts | Digital forensics evidence | Admissibility varies by jurisdiction |
| Traffic Analysis | GDPR compliance | Privacy vs security conflict |
| APT Attribution | Cyber warfare laws | Lack of global consensus |

---

## 📜 License

This project is for **academic purposes only** as part of the Cyber Law Survey at JAIN Deemed-to-be University, 2025–2026.
