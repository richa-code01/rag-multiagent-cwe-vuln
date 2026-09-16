from cwe_vuln.dataset import (
    EXPECTED_CWES,
    TEST_UNIT_IDS,
    TRAIN_UNIT_IDS,
    load_seed,
)


def test_split_is_eight_train_four_test() -> None:
    units = load_seed()
    train = [unit for unit in units if unit.split == "train"]
    test = [unit for unit in units if unit.split == "test"]
    assert len(units) == 12
    assert len(train) == 8
    assert len(test) == 4
    assert tuple(unit.unit_id for unit in train) == TRAIN_UNIT_IDS
    assert tuple(unit.unit_id for unit in test) == TEST_UNIT_IDS


def test_seed_covers_required_cwes_and_files() -> None:
    units = load_seed()
    cwes = {unit.cwe_id for unit in units}
    assert cwes == set(EXPECTED_CWES)
    for unit in units:
        assert unit.source.strip()
        assert unit.path.startswith("data/seed/java/")
        assert unit.path.endswith(".java")
        assert unit.label in {"vulnerable", "not_vulnerable"}


def test_train_and_test_each_mix_labels() -> None:
    units = load_seed()
    train_labels = {unit.label for unit in units if unit.split == "train"}
    test_labels = {unit.label for unit in units if unit.split == "test"}
    assert train_labels == {"vulnerable", "not_vulnerable"}
    assert test_labels == {"vulnerable", "not_vulnerable"}


def test_load_seed_split_filter() -> None:
    train = load_seed(split="train")
    test = load_seed(split="test")
    assert len(train) == 8
    assert len(test) == 4
    assert all(unit.split == "train" for unit in train)
    assert all(unit.split == "test" for unit in test)
