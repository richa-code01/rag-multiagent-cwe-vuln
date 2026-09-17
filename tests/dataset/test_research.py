from cwe_vuln.dataset import (
    RESEARCH_TEST_UNIT_IDS,
    TEST_UNIT_IDS,
    TRAIN_UNIT_IDS,
    load_research_corpus,
    load_seed,
)
from cwe_vuln.sast import detect


def test_assignment_seed_is_still_eight_four() -> None:
    units = load_seed()
    assert len(units) == 12
    assert len(load_seed(split="train")) == 8
    assert len(load_seed(split="test")) == 4
    assert tuple(unit.unit_id for unit in load_seed(split="train")) == TRAIN_UNIT_IDS
    assert tuple(unit.unit_id for unit in load_seed(split="test")) == TEST_UNIT_IDS


def test_research_corpus_is_thirty_six_with_held_out_test() -> None:
    all_units = load_research_corpus()
    held = load_research_corpus(split="research_test")
    seed = load_research_corpus(split="seed")
    assert len(all_units) == 36
    assert len(held) == 24
    assert len(seed) == 12
    assert tuple(unit.unit_id for unit in held) == RESEARCH_TEST_UNIT_IDS
    assert {unit.trap_type for unit in held} == {"fp_trap", "fn_trap"}


def test_fp_traps_trigger_regex_and_fn_traps_do_not() -> None:
    held = load_research_corpus(split="research_test")
    fps = [unit for unit in held if unit.trap_type == "fp_trap"]
    fns = [unit for unit in held if unit.trap_type == "fn_trap"]
    assert len(fps) == 12
    assert len(fns) == 12
    for unit in fps:
        assert unit.label == "not_vulnerable"
        assert detect(unit).is_vulnerable
    for unit in fns:
        assert unit.label == "vulnerable"
        assert not detect(unit).is_vulnerable
