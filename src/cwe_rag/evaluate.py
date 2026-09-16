"""Seed-only detection metrics.

Do not treat these numbers as a published benchmark. They only describe
how the deterministic pipeline scores the eight hand-written seed cases.
"""

from __future__ import annotations

from dataclasses import dataclass

from cwe_rag.pipeline import detect
from cwe_rag.seed_cases import SEED_CASES, SeedCase


@dataclass(frozen=True)
class SeedMetrics:
    precision: float
    recall: float
    f1: float
    n_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    cwe_id_accuracy: float
    note: str = (
        "seed-only: P/R/F1 on the eight bundled snippets, not a benchmark"
    )


def _is_true_positive(case: SeedCase, vulnerable: bool, cwe_id: str | None) -> bool:
    return case.vulnerable and vulnerable and case.cwe_id == cwe_id


def evaluate_seed(cases: tuple[SeedCase, ...] = SEED_CASES) -> SeedMetrics:
    tp = fp = fn = 0
    id_correct = 0
    for case in cases:
        result = detect(case.code)
        predicted_vuln = result.vulnerable
        predicted_id = result.cwe_id
        if case.vulnerable and predicted_vuln:
            if case.cwe_id == predicted_id:
                tp += 1
            else:
                # Wrong CWE on a vulnerable sample is a miss for this slice.
                fn += 1
        elif (not case.vulnerable) and predicted_vuln:
            fp += 1
        elif case.vulnerable and not predicted_vuln:
            fn += 1
        if predicted_id == case.cwe_id:
            id_correct += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return SeedMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        n_cases=len(cases),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        cwe_id_accuracy=id_correct / len(cases) if cases else 0.0,
    )
