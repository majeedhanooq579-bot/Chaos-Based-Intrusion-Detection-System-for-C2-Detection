# State-Sponsored C2 Detection via Chaotic Analysis

> **JAIN Deemed-to-be University | Dept. of CSE | Cyber Law Survey 2025–2026**  
> Authors: Devadeth Sunil · Abdul Hanooq Majeed · Belljer BL · Aravind P

---

## 📄 Overview

This repository contains the **source code implementation** accompanying the survey paper:

> *"State-Sponsored C2 Detection via Chaotic Analysis: A Comprehensive Survey"*

Advanced Persistent Threats (APTs) use stealthy **Command-and-Control (C2)** channels with highly jittered, non-periodic beaconing to evade detection. This project implements chaos-based detection techniques including:

- **Lyapunov Exponent** — measures divergence/chaos in beacon intervals
- **Shannon Entropy** — quantifies randomness in inter-arrival times
- **Butterfly Optimization Algorithm (BOA)** — adaptively tunes detection thresholds
- **Multi-metric Objective Function** `F = α·λ + β·H − γ·P`

---

## 📁 Repository Structure

```
c2-detection-chaotic-analysis/
│
├── c2_detection.py       # Main source code (all algorithms)
├── README.md             # This file
├── requirements.txt      # Python dependencies
│
├── docs/
│   ├── survey_paper.pdf  # Full survey paper
│   └── presentation.pptx # Presentation slides
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

## ⚙️ Setup & Usage

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/c2-detection-chaotic-analysis.git
cd c2-detection-chaotic-analysis
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the experiment
```bash
python c2_detection.py
```

### Expected Output
```
============================================================
C2 Detection via Chaotic Analysis — Experiment Demo
JAIN University | Cyber Law Survey 2025-2026
============================================================

[BOA] Optimal entropy threshold: 2.XXXX

Signal Type   Variance    Entropy   Lyapunov     F-Score  Label        Threat
--------------------------------------------------------------------------------
Periodic        0.0000     0.0000     0.0000      0.0000  Periodic     LOW
Jittered        0.2500     2.0900     X.XXXX      X.XXXX  Jittered     HIGH
Chaotic         6.7200     2.1800     X.XXXX      X.XXXX  Chaotic      VERY HIGH
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
where λ = Lyapunov, H = Entropy, P = Periodicity score

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
| Traffic Analysis | GDPR compliance | Privacy vs security conflict |
| APT Attribution | Cyber warfare laws | Lack of global consensus |

---

## 📜 License

This project is for **academic purposes only** as part of the Cyber Law Survey at JAIN Deemed-to-be University, 2025–2026.
