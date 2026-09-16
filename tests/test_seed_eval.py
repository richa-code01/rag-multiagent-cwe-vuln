from cwe_rag.evaluate import evaluate_seed


def test_seed_metrics_are_perfect_and_labeled_seed_only() -> None:
    metrics = evaluate_seed()
    assert metrics.n_cases == 8
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0
    assert metrics.cwe_id_accuracy == 1.0
    assert "seed-only" in metrics.note
