# HAL Methodology: Pythagorean Comma Dissonance Detection
## Hallucination Assessment Layer — Technical Specification
### HyperDAG Protocol | Version 1.0 | April 2026

> **Historical snapshot (April 2026).** This is the original HAL methodology write-up. Its status note, the results in section 6 and the roadmap in section 7 were written on or about 2026-04-21. They are **not current**, were not re-measured for this notice, and the roadmap dates were never tracked here. Nothing in this document describes the prover in this repository. How the pieces fit, and where current figures live: [BUILDERS.md](https://github.com/DealAppSeo/hyperdag-protocol/blob/main/BUILDERS.md).

---

## A Note to the Community

This document describes an approach to AI hallucination detection
grounded in mathematical constants rather than learned thresholds.
We believe that trust in AI systems — particularly in high-stakes
domains like financial decision-making — must be earned through
verifiable, reproducible methodology, not claimed through marketing.

We welcome rigorous critique, alternative approaches, and
contributions of any kind. If you think we are wrong about
something, please open an issue and tell us why. We would rather
be corrected publicly than confidently incorrect privately.

Ideas for or against this approach are equally welcome.
Suggestions and contributions are always appreciated.

---

## Abstract

We present a method for AI hallucination detection grounded in the
Pythagorean Comma — the mathematical gap (531441/524288 ≈ 1.01364)
that emerges when twelve perfect musical fifths fail to close into
seven exact octaves. We map AI decision quality signals to positions
on a chromatic circle and accumulate dissonance against this
mathematical constant. When dissonance exceeds the threshold
derived from the Pythagorean Comma gap, the system issues a veto.

**Status on 2026-04-21 (historical, not current):** Baseline established. Zero false positive vetoes
across 316 production decisions. The veto threshold has not yet
fired — the 5-signal calibration work described here is the active
development frontier. We publish the baseline honestly.

---

## Technical Stack

**Core infrastructure:**
- Rust — performance-critical services, ZKP proof generation
- Plonky3 — STARK-based zero-knowledge proofs (BabyBear field,
  Poseidon2 hash, no trusted setup required)
- TypeScript/Node.js — API layer, agent runtime
- Python — ANFIS training, signal processing (py-brain)

**Privacy architecture:**
ZKP (zero-knowledge proofs) are the cryptographic bridge
between human custodians and AI agents. A custodian's identity
is never publicly revealed — only a ZKP proof of their
accountability tier is on-chain. Identity is disclosed only
under defined conditions (see docs/CUSTODIAN_ACCOUNTABILITY.md).

**Why Rust + Plonky3:**
Plonky3 STARKs provide post-quantum security with no trusted
setup. The proving system runs in Rust for the performance
required to generate proofs at production decision latency.
The zkp-postcard service (hyperdag-core/services/zkp-postcard)
implements this in production.

---

## 1. The Problem We Are Solving

AI agents operating in the agentic economy will make consequential
decisions: financial recommendations, legal analysis, compliance
assessments, underwriting judgments, health and wellness
diagnosis and analysis. The infrastructure for IDENTITY
of AI agents is emerging (on-chain registration, ERC standards).
The infrastructure for TRUST — verifiable behavioral reputation
that cannot be transferred or gamed — does not yet exist at scale.

RepID is our attempt to build that layer (for AI agents, and humans
who wish to participate and contribute to the ecosystem, and/or own
and train agents — thus being responsible for, but also reaping the
benefits of their agents' performance — as their custodians).
HAL (Hallucination Assessment Layer) is the detection mechanism
that makes RepID honest: it catches when an agent is overreaching
its evidence, operating outside its domain, or claiming certainty
it hasn't earned.

An AI hallucination is when an AI system states something
confidently, as if true, that is not true. HAL is built to detect
that specific failure mode.

We are not claiming to have solved this. We are publishing our
working approach and asking the community to help improve it.

A note on custodian accountability: ZKP proofs link every
agent to a verified human custodian without revealing that
custodian publicly. When harm occurs, the ZKP proof is the
key to accountability. See docs/CUSTODIAN_ACCOUNTABILITY.md
for the full disclosure framework.

---

## 2. The Five HAL Signals

Standard LLM confidence scores collapse to one dimension: how
certain is the model about its output? A hallucinating model is
often highly confident. We decompose decision quality into five
independently observable signals:

| Signal | Musical Position | What It Measures |
|--------|-----------------|-----------------|
| harm_probability | Root (C) | Overconfidence density + risk keyword weight |
| epistemic_uncertainty | Second (D) | Hedge term analysis vs. stated certainty |
| evidence_quality | Third (E) | Specificity, citations, temporal grounding |
| scope_appropriateness | Fifth (G) | Domain ontology Jaccard similarity |
| certainty_at_claim | Octave (C') | Agent-stated certainty |

The five signals map to the first five positions of the Circle of
Fifths (C→G→D→A→E), creating a natural harmonic structure that
allows dissonance accumulation to be measured mathematically.

---

## 3. The HAL Formula

```
dissonance = (0.4 × harm_probability
            + 0.3 × epistemic_uncertainty
            + 0.2 × (1 − evidence_quality)
            + 0.1 × (1 − scope_appropriateness))
           × (531441 / 524288)
```

The Pythagorean Comma multiplier serves as the dissonance
accumulator. The weighted sum is multiplied by this irrational
ratio; when multiple signals align in a hallucination pattern,
the result crosses the veto threshold.

**Current thresholds (hand-tuned, pre-calibration):**
- General veto: ≥ 0.25
- BFT consensus veto: ≥ 0.0195 (Pythagorean Comma gap itself)
- Constitutional block: ≥ 0.48

**Note on current weights (0.4/0.3/0.2/0.1):** These are
hand-tuned initial values. The LASSO calibration described in
Section 7 will replace these with empirically derived weights.
We are publishing the hand-tuned baseline transparently.

---

## 4. The Generalized Comma Formula

After LASSO pruning to N rules (constrained to N ∈ {5, 7, 12}
to preserve irrational gap properties):

```
C(N) = (3/2)^N / 2^k
where k = floor(N × log₂(3/2) + 0.5)
```

Values for the constrained set:
| N | C(N) | |Δ(N)| | Use case |
|---|------|---------|---------|
| 5 | ≈0.9492 | ≈0.0508 | BFT sensitivity |
| 7 | ≈1.0679 | ≈0.0679 | Balanced threshold |
| 12 | ≈1.0136 | ≈0.0136 | Classical comma (full circle) |

**Open question for community:** Is the constraint to N ∈ {5,7,12}
mathematically necessary, or are there other values of N that
preserve operationally useful irrational gaps? See Issue #3.

---

## 5. CommaANFIS Architecture

Five-layer Takagi-Sugeno Adaptive Neuro-Fuzzy Inference System
with the following design choices:

- **Membership center placement:** Phyllotaxis (golden angle 137.508°)
  for maximal non-overlapping coverage of signal space
- **Center scaling:** Golden ratio φ^(r mod 5)
- **Spread scaling:** φ^(−r mod 5) (inverse golden ratio)
- **Rule count:** N ∈ {5, 7, 12} (comma-preserving constraint)
- **Training:** LASSO regularized hybrid learning (LSE for
  consequents, backprop for membership function parameters)

**Hypothesis (unvalidated):** Phyllotaxis placement reduces blind
spots by 15-25% vs uniform grid partitioning. We have no empirical
data for this yet. This is an open research question. See Issue #2.

TypeScript implementation: `repid-engine/src/services/anfis-comma.ts`
Python training: `py-brain` Railway service (ANFIS + LASSO)

---

## 6. Baseline Results — April 21, 2026

*Snapshot of 2026-04-21 (33 agents, 316 scored decisions at that date). Not current; not re-measured here.*

| Metric | Value | Notes |
|--------|-------|-------|
| Total decisions scored | 316 | Production, 33 agents |
| Total system vetoes | 361 | Across all layers |
| ZKP vetoes (trinity_hallucination_logs) | 298 | Active since March 12, 2026 (Agent: NEXUS) |
| CLAIM_REJECTED verdicts | 3 | Full 8-layer pipeline (April 17, 2026) |
| Agent-layer catches (repid_score_events) | 60 | |
| False positive vetoes | 0 | Conservative threshold working |
| Mean HAL score (caught hallucinations) | 0.1154 | |
| Mean HAL score (safe decisions) | 0.1306 | |
| Distribution overlap | ~85% | Root cause: signals not independent |

**Honest interpretation:** The caught and safe score distributions
overlap significantly because all 5 HAL signals currently derive
from certainty_at_claim (1 degree of freedom). The 5-signal
extractor (Section 5) restores independent degrees of freedom.
LASSO calibration on 100+ events with independent signals is the
next milestone.

The zero false positive rate is meaningful: the system has never
incorrectly blocked a legitimate decision. The zero true positive
rate reflects an uncalibrated threshold, not a broken system.

---

## 7. Calibration Roadmap

*Plan as of April 2026. This repository does not track whether these targets were met.*

**Phase 1 (Current):** Baseline established. 5-signal extractor deployed.

**Phase 2 (Target: 7-10 days):** Collect 100+ score events with
all 5 signals independently populated. Run LASSO on clean dataset.
Expected: empirically derived signal weights replacing hand-tuned 0.4/0.3/0.2/0.1.

**Phase 3 (Target: 14 days):** CommaANFIS wired as authoritative
HAL Layer 0. First real HAL veto fired in production.

**Phase 4 (Target: 30 days):** TruthfulQA post-calibration F1
published at trustrepid.dev/hal. Results honest regardless of value.

---

## 8. Open Questions for the Community

We do not have answers to these. We would genuinely welcome input:

1. **Optimal LASSO λ:** What regularization parameter minimizes
   overfitting on a small (100-event) training set for the 5-signal case?

2. **Phyllotaxis validation:** Does golden-angle rule placement
   measurably outperform uniform grid partitioning? (See Issue #2)

3. **N constraint justification:** Are N ∈ {5,7,12} the only
   values that produce operationally useful comma gaps? (See Issue #3)

4. **External benchmarks:** Beyond TruthfulQA, what labeled
   hallucination datasets exist for domain-specific claims
   (financial, legal, compliance)? We have found none.

5. **Ethics and measurement:** Can a mathematical system correctly
   measure ethical behavior, or does it only approximate it?
   We believe measurement ≠ definition — see RepID ethics layer
   documentation.

---

## 9. How to Reproduce

```bash
# Score a decision through HAL
curl -X POST https://repid-engine-production.up.railway.app/api/v1/hal/signals \
  -H "Content-Type: application/json" \
  -d '{"text": "your claim here", "domain": "finance", "certainty": 0.85}'

# Run the benchmark
cd repid-engine && node scripts/run-truthfulqa.js

# View live results
open https://trustrepid.dev/hal
```

All benchmark code is open source. The labeled test prompts
(26 prompts, 50% hallucination rate) are in the public Supabase
project. TruthfulQA dataset: github.com/sylinrl/TruthfulQA

---

## 10. Patent Disclosure

A provisional patent application (P-029) has been filed covering
the novel combination of:
- Fuzzy inference system with Circle of Fifths signal mapping
- Pythagorean Comma ratio as dissonance threshold
- STARK verifiability of the inference computation

We are disclosing this transparently. The open-source implementation
will remain open regardless of patent status. The patent covers
the specific combination, not the underlying mathematical constants
or the ANFIS architecture independently.

---

## Contributing

This is an open protocol for the agentic economy. We are not
the only people thinking about AI trust and reputation. We are
probably not even thinking about it in the best way.

If you disagree with our approach — please tell us. Open an issue.
If you have a better method — please share it.
If you want to implement this in your own agent stack — please do.

Contributions of any kind are welcome and appreciated.
This work is better with more perspectives, not fewer.

[Open an issue →](https://github.com/DealAppSeo/hyperdag-core/issues)
[Read the RepID system →](https://repid.dev/why)
[View live benchmark →](https://trustrepid.dev/hal)

---

*"Act justly, love mercy, walk humbly." — Micah 6:8*
*"Whatever is true, honest, just, pure, lovely, of good report." — Philippians 4:8*
*"Do to others as you would have them do to you." — Matthew 7:12*

These three principles are the constitutional foundation of the
RepID ethics layer. They are not here for decoration.
