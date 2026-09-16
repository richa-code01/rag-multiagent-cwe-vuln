"""Wire SAST → retrieve → reason → validate. Cost policy lives only here; no regex rules."""

from __future__ import annotations

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.pipeline import PipelineResult
from cwe_vuln.orchestrator.ports import EvidenceExtractor, UnitReasoner, UnitRetriever, UnitValidator
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever
from cwe_vuln.sast import RegexEvidenceExtractor
from cwe_vuln.validator import ResultValidator


class Pipeline:
    def __init__(
        self,
        extractor: EvidenceExtractor,
        retriever: UnitRetriever,
        reasoner: UnitReasoner,
        validator: UnitValidator,
    ) -> None:
        self.extractor = extractor
        self.retriever = retriever
        self.reasoner = reasoner
        self.validator = validator

    @classmethod
    def default(cls) -> Pipeline:
        return cls(
            extractor=RegexEvidenceExtractor(),
            retriever=HybridRetriever.load(),
            reasoner=TemplateReasoner(),
            validator=ResultValidator(),
        )

    def run(self, unit: SeedUnit) -> PipelineResult:
        evidence = self.extractor.extract(unit)
        # SAST-first: skip LLM whenever evidence is enough or no key is configured.
        if evidence and not settings.llm_api_key():
            path = "sast_first_skip_llm"
        elif not evidence and not settings.llm_api_key():
            path = "hybrid_retrieve_skip_llm"
        elif evidence:
            path = "sast_first_skip_llm_even_with_key"
        else:
            path = "hybrid_retrieve_llm_unimplemented_template"
        hits = self.retriever.rank_for_unit(unit)
        result = self.reasoner.compose(unit, evidence, hits)
        report = self.validator.check(result, unit, evidence)
        return PipelineResult(
            unit_id=unit.unit_id,
            path=path,
            evidence=tuple(evidence),
            hits=tuple(hits),
            result=result,
            report=report,
        )
