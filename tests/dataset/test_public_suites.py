from pathlib import Path

from cwe_vuln.dataset.findsecbugs import load_findsecbugs_units
from cwe_vuln.dataset.owasp import load_owasp_units
from cwe_vuln.dataset.securibench import load_securibench_units
from cwe_vuln.dataset.vul4j import load_vul4j_units
from cwe_vuln.dataset.cvefixes import load_cvefixes_units
from cwe_vuln.framework.eval import main as eval_main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_owasp_csv_maps_cwe_and_labels() -> None:
    units = load_owasp_units(tree=FIXTURES / "owasp")
    by_id = {unit.unit_id: unit for unit in units}
    assert by_id["owasp_BenchmarkTestTinyBad"].label == "vulnerable"
    assert by_id["owasp_BenchmarkTestTinyBad"].cwe_id == "CWE-89"
    assert by_id["owasp_BenchmarkTestTinyGood"].label == "not_vulnerable"
    assert by_id["owasp_BenchmarkTestTinyXss"].cwe_id == "CWE-79"
    assert all(unit.corpus == "owasp-benchmark" for unit in units)


def test_securibench_vuln_count_and_no_silent_cwe() -> None:
    units = load_securibench_units(tree=FIXTURES / "securibench" / "src" / "securibench" / "micro")
    labels = {unit.unit_id: unit for unit in units}
    assert labels["sbmicro_BasicTinyXss"].cwe_id == "CWE-79"
    assert labels["sbmicro_BasicTinyXss"].label == "vulnerable"
    assert labels["sbmicro_BasicTinySafe"].cwe_id == "CWE-89"
    assert labels["sbmicro_BasicTinySafe"].label == "not_vulnerable"


def test_findsecbugs_folder_map_and_safe_filename() -> None:
    units = load_findsecbugs_units(tree=FIXTURES / "findsecbugs")
    by_cwe = {unit.cwe_id: unit for unit in units}
    assert any(unit.cwe_id == "CWE-89" and unit.label == "vulnerable" for unit in units)
    assert any(unit.cwe_id == "CWE-79" and unit.label == "not_vulnerable" for unit in units)
    assert any(unit.cwe_id == "CWE-502" for unit in units)
    assert "CWE-78" not in by_cwe


def test_vul4j_and_cvefixes_fixtures_pair_vuln_fixed() -> None:
    vul = load_vul4j_units(tree=FIXTURES / "vul4j", fetch_patches=False)
    assert {unit.label for unit in vul} == {"vulnerable", "not_vulnerable"}
    assert all(unit.cwe_id == "CWE-79" for unit in vul)
    cve = load_cvefixes_units(tree=FIXTURES / "cvefixes", fetch_patches=False)
    assert {unit.label for unit in cve} == {"vulnerable", "not_vulnerable"}
    assert all(unit.cwe_id == "CWE-89" for unit in cve)


def test_owasp_sast_cli_on_fixture(tmp_path) -> None:
    code = eval_main(
        [
            "--suite",
            "owasp-benchmark",
            "--suite-tree",
            str(FIXTURES / "owasp"),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert (tmp_path / "sast_regex_owasp_benchmark.json").is_file()
