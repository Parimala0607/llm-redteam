"""
metrics.py — pure-stdlib classification & agreement metrics for judge validation.

No numpy / sklearn dependency (keeps the project dependency-free, matching the
rest of the tool). Positive class is ALWAYS "vulnerable" — i.e. the thing we are
trying to detect. A false positive = judge cried "vulnerable" on a safe response;
a false negative = judge missed a real vulnerability.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple, Dict


# ── Confusion matrix + P/R/F1 ─────────────────────────────────────────────────

@dataclass
class BinaryReport:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def fpr(self) -> float:
        """False positive rate — how often safe responses get flagged."""
        d = self.fp + self.tn
        return self.fp / d if d else 0.0


def binary_report(human: List[bool], judge: List[bool]) -> BinaryReport:
    """`human`/`judge` are lists of bool where True == 'vulnerable'."""
    assert len(human) == len(judge), "label lists must be the same length"
    r = BinaryReport()
    for h, j in zip(human, judge):
        if h and j:
            r.tp += 1
        elif not h and j:
            r.fp += 1
        elif h and not j:
            r.fn += 1
        else:
            r.tn += 1
    return r


# ── Cohen's kappa (inter-rater agreement) ─────────────────────────────────────

def cohens_kappa(a: List[bool], b: List[bool]) -> float:
    """
    Agreement between two binary raters corrected for chance.
    1.0 = perfect, 0.0 = chance-level, <0 = worse than chance.
    """
    assert len(a) == len(b)
    n = len(a)
    if n == 0:
        return 0.0
    agree = sum(1 for x, y in zip(a, b) if x == y)
    po = agree / n
    pa_yes = sum(a) / n
    pb_yes = sum(b) / n
    pe = pa_yes * pb_yes + (1 - pa_yes) * (1 - pb_yes)
    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1 - pe)


def kappa_label(k: float) -> str:
    """Landis & Koch interpretation bands."""
    if k < 0:    return "poor (worse than chance)"
    if k < 0.20: return "slight"
    if k < 0.40: return "fair"
    if k < 0.60: return "moderate"
    if k < 0.80: return "substantial"
    return "almost perfect"


# ── Score calibration (the judge emits a 0..1 score, not just a bool) ─────────

@dataclass
class CalibrationBin:
    lo: float
    hi: float
    count: int = 0
    mean_score: float = 0.0       # mean judge score in this bin
    observed_vuln: float = 0.0    # fraction actually vulnerable per humans


def calibration(human: List[bool], scores: List[float], n_bins: int = 5
                ) -> Tuple[List[CalibrationBin], float]:
    """
    Buckets judge scores and compares mean predicted score against the observed
    fraction of human-confirmed vulnerabilities. Returns (bins, ECE).

    ECE (Expected Calibration Error) = weighted mean |mean_score - observed|.
    Low ECE means the judge's score behaves like a probability.
    """
    assert len(human) == len(scores)
    edges = [i / n_bins for i in range(n_bins + 1)]
    bins = [CalibrationBin(edges[i], edges[i + 1]) for i in range(n_bins)]

    for h, s in zip(human, scores):
        idx = min(int(s * n_bins), n_bins - 1)
        b = bins[idx]
        b.count += 1
        b.mean_score += s
        b.observed_vuln += (1.0 if h else 0.0)

    n = len(human)
    ece = 0.0
    for b in bins:
        if b.count:
            b.mean_score /= b.count
            b.observed_vuln /= b.count
            ece += (b.count / n) * abs(b.mean_score - b.observed_vuln)
    return bins, ece


# ── ROC AUC via Mann–Whitney U (rank-based, handles ties) ─────────────────────

def roc_auc(human: List[bool], scores: List[float]) -> float:
    """
    Probability that a randomly chosen vulnerable item is scored higher than a
    randomly chosen safe item. 0.5 = random, 1.0 = perfect separation.
    Tie-aware (average ranks).
    """
    pos = [s for h, s in zip(human, scores) if h]
    neg = [s for h, s in zip(human, scores) if not h]
    n_pos, n_neg = len(pos), len(neg)
    if n_pos == 0 or n_neg == 0:
        return float("nan")

    # average-rank assignment across the pooled sample
    pooled = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg],
                    key=lambda x: x[0])
    ranks = [0.0] * len(pooled)
    i = 0
    while i < len(pooled):
        j = i
        while j + 1 < len(pooled) and pooled[j + 1][0] == pooled[i][0]:
            j += 1
        avg_rank = (i + j) / 2 + 1  # ranks are 1-indexed
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1

    sum_pos_ranks = sum(r for r, (_, lbl) in zip(ranks, pooled) if lbl == 1)
    u = sum_pos_ranks - n_pos * (n_pos + 1) / 2
    return u / (n_pos * n_neg)
