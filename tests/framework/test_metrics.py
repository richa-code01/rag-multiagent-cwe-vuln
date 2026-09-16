from cwe_vuln.models import binary_metrics


def test_perfect_confusion_matrix() -> None:
    scores = binary_metrics([True, False], [True, False])
    assert scores.tp == 1
    assert scores.fp == 0
    assert scores.tn == 1
    assert scores.fn == 0
    assert scores.precision == 1.0
    assert scores.recall == 1.0
    assert scores.f1 == 1.0
    assert scores.support == 2


def test_balanced_errors() -> None:
    # one TP, one FP, one FN
    scores = binary_metrics([True, False, True], [True, True, False])
    assert (scores.tp, scores.fp, scores.fn, scores.tn) == (1, 1, 1, 0)
    assert scores.precision == 0.5
    assert scores.recall == 0.5
    assert scores.f1 == 0.5


def test_zero_positive_predictions_are_zero_precision() -> None:
    scores = binary_metrics([True, False], [False, False])
    assert scores.tp == 0
    assert scores.fp == 0
    assert scores.fn == 1
    assert scores.precision == 0.0
    assert scores.recall == 0.0
    assert scores.f1 == 0.0
