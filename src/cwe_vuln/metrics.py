"""Binary precision / recall / F1 helpers for the Assignment 1 baseline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    support: int

    def as_dict(self) -> dict[str, int | float]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "support": self.support,
        }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def binary_metrics(y_true: list[bool], y_pred: list[bool]) -> BinaryMetrics:
    """Vulnerable=True vs not_vulnerable=False confusion counts and scores."""
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must be the same length")

    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred, strict=True):
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif not truth and not pred:
            tn += 1
        else:
            fn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    return BinaryMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        support=len(y_true),
    )
