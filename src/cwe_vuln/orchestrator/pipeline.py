"""Wire SAST → retrieve → reason → validate. Cost policy lives only here; no regex or prompts."""

from __future__ import annotations

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.pipeline import PipelineResult
from cwe_vuln.orchestrator.ports import EvidenceExtractor, UnitReasoner, UnitRetriever, UnitValidator
from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner
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
        llm_reasoner: UnitReasoner | None = None,
        skip_llm_when_sast_hits: bool | None = None,
        use_llm_if_available: bool | None = None,
    ) -> None:
        self.extractor = extractor
        self.retriever = retriever
        self.reasoner = reasoner
        self.validator = validator
        self.llm_reasoner = llm_reasoner
        self.skip_llm_when_sast_hits = (
            settings.skip_llm_when_sast_hits if skip_llm_when_sast_hits is None else skip_llm_when_sast_hits
        )
        self.use_llm_if_available = (
            settings.use_llm_if_available if use_llm_if_available is None else use_llm_if_available
        )

    @classmethod
    def default(cls) -> Pipeline:
        template = TemplateReasoner()
        llm = LLMReasoner.from_env() if settings.use_llm_if_available else None
        return cls(
            extractor=RegexEvidenceExtractor(),
            retriever=HybridRetriever.load(),
            reasoner=template,
            validator=ResultValidator(),
            llm_reasoner=llm,
        )

    def run(self, unit: SeedUnit) -> PipelineResult:
        evidence = self.extractor.extract(unit)
        hits = self.retriever.rank_for_unit(unit)
        path, active = self._route(bool(evidence))
        result = active.reason(unit, evidence, hits)
        backend = getattr(active, "last_backend", None) or (
            "llm" if active is self.llm_reasoner else "template"
        )
        report = self.validator.check(result, unit, evidence)
        embedder = getattr(self.retriever, "embedder_name", "unknown")
        return PipelineResult(
            unit_id=unit.unit_id,
            path=path,
            evidence=tuple(evidence),
            hits=tuple(hits),
            result=result,
            report=report,
            reasoner=backend,
            embedder=embedder,
        )

    def _route(self, has_evidence: bool) -> tuple[str, UnitReasoner]:
        can_llm = (
            self.llm_reasoner is not None
            and self.use_llm_if_available
            and bool(settings.llm_api_key())
        )
        if has_evidence:
            if can_llm and not self.skip_llm_when_sast_hits and self.llm_reasoner is not None:
                return "sast_then_llm", self.llm_reasoner
            return "sast_first_skip_llm", self.reasoner
        if can_llm and self.llm_reasoner is not None:
            return "hybrid_retrieve_then_llm", self.llm_reasoner
        return "hybrid_retrieve_skip_llm", self.reasoner
