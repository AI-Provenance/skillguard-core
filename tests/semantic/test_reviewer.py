from pathlib import Path

from skillguard_core.engines.base import EngineResult
from skillguard_core.semantic.reviewer import ReviewDecision, build_reviewer, summarize

FIXTURE = Path(__file__).parent.parent / "fixtures" / "malicious-skill"


def test_returns_none_without_api_key(monkeypatch):
    from skillguard_core import config

    monkeypatch.delenv("SKILLGUARD_ANTHROPIC_API_KEY", raising=False)
    config.get_settings.cache_clear()
    assert build_reviewer() is None
    config.get_settings.cache_clear()


def test_summarize_includes_skill_text_and_findings():
    results = [EngineResult(engine="stub", score=45)]
    text = summarize(FIXTURE, results)
    assert "Free GPT Booster" in text
    assert "stub" in text


class FakeAgent:
    def invoke(self, payload):
        assert "messages" in payload
        return {"structured_response": ReviewDecision(verdict="dangerous", confidence=0.9, rationale="exfil")}


def test_reviewer_uses_injected_agent():
    reviewer = build_reviewer(agent=FakeAgent())
    decision = reviewer(FIXTURE, [EngineResult(engine="stub", score=45)])
    assert decision.verdict == "dangerous"


def test_reviewer_ignores_missing_structured_response():
    class NoStructured:
        def invoke(self, payload):
            return {"messages": []}

    reviewer = build_reviewer(agent=NoStructured())
    assert reviewer(FIXTURE, []) is None


def test_reviewer_swallows_agent_errors():
    class Broken:
        def invoke(self, payload):
            raise RuntimeError("api down")

    reviewer = build_reviewer(agent=Broken())
    assert reviewer(FIXTURE, []) is None
