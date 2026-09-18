"""Sanitizer guarantees: no gold tokens reach the prompt; line numbers preserved."""

from pathlib import Path

from cwe_vuln.dataset import load_juliet_units, load_research_corpus, load_seed
from cwe_vuln.dataset.sanitize import find_gold_tokens, opaque_unit_id, sanitize_unit
from cwe_vuln.reasoner.prompts import render_prompt
from cwe_vuln.sast import extract_evidence

JULIET_LIKE = """package testcases.CWE89_SQL_Injection;

import java.sql.Statement;

public class CWE89_SQL_Injection__connect_tcp_01 {
    public void bad() throws Throwable {
        String data = "name";  /* POTENTIAL FLAW: user input */
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE name=" + data);
    }

    public void good1() throws Throwable {
        /* FIX: use a PreparedStatement */
        String data = "name";
    }
}
"""


def _juliet_like_unit():
    from cwe_vuln.dataset.seed import SeedUnit

    return SeedUnit(
        unit_id="juliet_CWE89_SQL_Injection__connect_tcp_01__file_bad",
        cwe_id="CWE-89",
        path="data/benchmarks/juliet-java/src/testcases/CWE89_SQL_Injection/x.java",
        split="juliet",
        label="vulnerable",
        notes="juliet file_bad role=primary",
        source=JULIET_LIKE,
        trap_type="juliet",
        corpus="juliet",
    )


def test_opaque_id_hides_gold() -> None:
    prompt_id = opaque_unit_id("juliet_CWE89_SQL_Injection__connect_tcp_01__method_bad")
    assert prompt_id.startswith("unit_")
    assert find_gold_tokens(prompt_id) == []
    assert "89" not in prompt_id
    assert opaque_unit_id("java_cwe89_sqli_concat") == opaque_unit_id("java_cwe89_sqli_concat")


def test_sanitize_strips_juliet_gold_signals() -> None:
    unit = _juliet_like_unit()
    clean = sanitize_unit(unit)
    assert clean.unit_id != unit.unit_id
    assert clean.path == "Snippet.java"
    assert clean.notes == ""
    lowered = clean.source.lower()
    for token in ("flaw", "fix:", "bad", "good", "cwe89", "testcases.cwe"):
        assert token not in lowered, token
    # Line numbers preserved despite blanked comments and renames.
    assert len(clean.source.splitlines()) == len(unit.source.splitlines())
    # The sink line survives sanitization.
    assert "executeQuery" in clean.source


def test_sanitize_blanks_authored_javadoc_label_leak() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe798_env_config")
    assert "not_vulnerable" in unit.source  # the leak exists in the raw file
    clean = sanitize_unit(unit)
    assert "not_vulnerable" not in clean.source
    assert "CWE-798" not in clean.source
    assert "Cwe798" not in clean.source
    assert len(clean.source.splitlines()) == len(unit.source.splitlines())


def test_prompt_render_clean_on_seed_and_research() -> None:
    units = load_seed() + load_research_corpus(split="research_test")
    for unit in units:
        clean = sanitize_unit(unit)
        evidence = extract_evidence(clean)
        rendered = render_prompt(clean, evidence, [])
        assert find_gold_tokens(rendered.text) == [], f"{unit.unit_id}: {find_gold_tokens(rendered.text)}"
        # Gold CWE must not appear in the sanitized source itself. (SAST evidence
        # may legitimately name a CWE — that is detector output, not gold.)
        assert unit.cwe_id not in clean.source, unit.unit_id
        assert "Cwe" not in clean.source and "CWE" not in clean.source


def test_prompt_render_clean_on_juliet_fixture() -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "juliet"
    units = load_juliet_units(tree=fixture)
    assert units, "fixture should produce Juliet units"
    for unit in units:
        clean = sanitize_unit(unit)
        evidence = extract_evidence(clean)
        rendered = render_prompt(clean, evidence, [])
        assert find_gold_tokens(rendered.text) == [], unit.unit_id
        assert unit.cwe_id not in clean.source, unit.unit_id


def test_long_source_is_windowed_with_absolute_line_numbers() -> None:
    from cwe_vuln.dataset.seed import SeedUnit

    pad = ["int filler%04d = 0;" % n for n in range(1, 401)]
    sink = '        stmt.executeQuery("SELECT * FROM t WHERE x=" + value);'
    lines = ["package x;", "public class Big {", "  void run(String value) {"] + pad + [sink, "  }", "}"]
    source = "\n".join(lines)
    unit = SeedUnit(
        unit_id="big_unit",
        cwe_id="CWE-89",
        path="Big.java",
        split="juliet",
        label="vulnerable",
        notes="",
        source=source,
    )
    clean = sanitize_unit(unit)
    rendered = render_prompt(clean, [], [], max_chars=2000)
    assert rendered.truncated
    assert rendered.slice_strategy == "sink_window"
    sink_line = next(n for n, line in enumerate(clean.source.splitlines(), 1) if "executeQuery" in line)
    assert rendered.window_start <= sink_line <= rendered.window_end
    # Absolute line prefixes are present and match the original numbering.
    assert f"{sink_line:>4}| " in rendered.text
