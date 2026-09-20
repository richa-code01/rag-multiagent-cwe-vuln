"""Provider-agnostic LLM errors. The reasoner never imports SDK exception types."""


class LLMError(RuntimeError):
    """Base for live-LLM failures that should not become a template answer."""


class RateLimitError(LLMError):
    """Quota / 429. The trial runner backs off; the reasoner re-raises this."""

    def __init__(self, message: str, *, status_code: int = 429) -> None:
        super().__init__(message)
        self.status_code = status_code
