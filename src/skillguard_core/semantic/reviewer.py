import json
import logging
from pathlib import Path
from typing import Literal

from deepagents import (
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from langchain.chat_models import init_chat_model
from pydantic import BaseModel, Field

from skillguard_core.config import get_settings
from skillguard_core.engines.base import EngineResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security reviewer for AI agent skills. You receive the skill's "
    "SKILL.md content and static-analysis findings. Decide whether the skill is "
    "safe, caution-worthy, or dangerous to install. Judge intent: benign utility, "
    "suspicious-but-ambiguous, or malicious (exfiltration, credential theft, "
    "prompt injection, remote code execution). Be conservative: only mark safe "
    "when you have high confidence. Do not use any tools; answer immediately."
)

JSON_FORMAT_INSTRUCTION = (
    "\n\nRespond with a JSON object matching this schema. "
    'Return ONLY the JSON, no other text:\n'
    '{"verdict": "<safe|caution|dangerous>", "confidence": <0.0-1.0>, "rationale": "<brief explanation>"}'
)


class ReviewDecision(BaseModel):
    verdict: Literal["safe", "caution", "dangerous"] = Field(description="Final install verdict")
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(max_length=1000)


def summarize(path: Path, results: list[EngineResult]) -> str:
    skill_md = path / "SKILL.md"
    text = skill_md.read_text(errors="replace")[:20_000] if skill_md.exists() else ""
    lines = [f"SKILL.md content:\n{text}\n", "Static analysis findings:"]
    for result in results:
        if result.error:
            lines.append(f"- {result.engine}: ERROR {result.error}")
            continue
        if result.findings:
            for f in result.findings:
                lines.append(f"- {result.engine}/{f.rule_id} [{f.severity}] {f.title} ({f.file_path})")
        else:
            lines.append(f"- {result.engine}: score={result.score}, no findings")
    return "\n".join(lines)


def _parse_json_response(content: str) -> ReviewDecision | None:
    text = content.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:]) if lines[0].startswith("```") else text
        text = text.removesuffix("```")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        for line in reversed(text.split("\n")):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return None
    try:
        return ReviewDecision(**data)
    except Exception:  # noqa: BLE001
        return None


def build_reviewer(model: str | None = None, agent=None):
    settings = get_settings()
    if agent is None:
        api_key = settings.anthropic_api_key or settings.llm_api_key
        if not api_key:
            return None

        model_name = model or settings.semantic_model
        if settings.llm_base_url:
            chat_model = init_chat_model(
                model=model_name,
                base_url=settings.llm_base_url,
                api_key=api_key,
                temperature=0,
            )
            agent = create_deep_agent(
                model=chat_model,
                system_prompt=SYSTEM_PROMPT + JSON_FORMAT_INSTRUCTION,
            )

            def review(path: Path, results: list[EngineResult]) -> ReviewDecision | None:
                try:
                    state = agent.invoke({"messages": [{"role": "user", "content": summarize(path, results)}]})
                except Exception as exc:  # noqa: BLE001
                    logger.warning("LLM review failed: %s", exc)
                    return None
                messages = state.get("messages", [])
                if not messages:
                    return None
                content = str(messages[-1].content) if hasattr(messages[-1], "content") else str(messages[-1])
                return _parse_json_response(content)

            return review
        else:
            model_key = f"anthropic:{model_name}"
            register_harness_profile(
                model_key,
                HarnessProfile(
                    general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
                    excluded_tools=frozenset({"ls", "read_file", "write_file", "edit_file", "delete", "glob", "grep"}),
                ),
            )
            agent = create_deep_agent(
                model=model_key,
                system_prompt=SYSTEM_PROMPT,
                response_format=ReviewDecision,
            )

    def review(path: Path, results: list[EngineResult]) -> ReviewDecision | None:
        try:
            state = agent.invoke({"messages": [{"role": "user", "content": summarize(path, results)}]})
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM review failed: %s", exc)
            return None
        decision = state.get("structured_response")
        return decision if isinstance(decision, ReviewDecision) else None

    return review
