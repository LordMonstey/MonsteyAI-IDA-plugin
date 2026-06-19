"""Qt workers for non-IDA blocking operations."""

from __future__ import annotations

from dataclasses import replace
import copy
import time
from typing import Any, Dict

from .compat.qt import QtCore, signal
from .analysis_policy import agent_policy, model_policy, subagent_budget
from .config import PluginConfig
from .enrichment import enrich_analysis_with_local_cues
from .evidence_pack import apply_agent_claim_updates, build_claim_board, build_evidence_pack
from .external_evidence import apply_external_evidence_to_analysis
from .llm import OpenAICompatClient
from .prompts import (
    build_action_messages,
    build_analysis_messages,
    build_json_repair_messages,
    build_pseudocode_diff_messages,
    build_xref_explorer_messages,
)
from .pseudodiff import local_pseudocode_diff, render_local_pseudocode_diff_text
from .schemas import extract_json_object, normalize_analysis, parse_json_object
from .toolchain import toolchain_scout_context, toolchain_status
from .trainer_intel import build_trainer_intel


REQUIRED_FUNCTION_QUESTIONS = [
    "Lets call it and see the returns",
    "Lets hook it and modify something",
]


def ensure_function_questions(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    if not context.get("has_function"):
        return analysis
    current = analysis.get("next_questions")
    if not isinstance(current, list):
        current = []
    normalized = [str(item) for item in current]
    out = []
    for question in REQUIRED_FUNCTION_QUESTIONS:
        out.append(question)
    for question in normalized:
        if question not in out:
            out.append(question)
    analysis["next_questions"] = out
    return analysis


def ensure_user_context_alignment(analysis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    analyst_context = context.get("analyst_context") or {}
    if not analyst_context.get("present"):
        return analysis
    alignment = analysis.get("user_context_alignment")
    if not isinstance(alignment, dict):
        alignment = {}
    alignment.setdefault("used", False)
    alignment.setdefault("verdict", "weak")
    alignment.setdefault("supports_user_hint", [])
    alignment.setdefault("contradicts_user_hint", [])
    alignment.setdefault("notes", "")
    if not alignment.get("used") and not alignment.get("notes"):
        alignment["notes"] = "The model did not explicitly compare the analyst hint; rerun with narrower context or stronger evidence."
    analysis["user_context_alignment"] = alignment
    return analysis


def _useful_text(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and text.lower() not in ("-", "unknown", "none", "n/a", "null"))


def _count_items(value: Any) -> int:
    if isinstance(value, list):
        return len([item for item in value if _useful_text(item)])
    if _useful_text(value):
        return 1
    return 0


def _append_unique(base: Any, extra: Any, limit: int = 16) -> list:
    out = list(base) if isinstance(base, list) else ([] if not _useful_text(base) else [str(base)])
    seen = {str(item).strip().lower() for item in out}
    candidates = extra if isinstance(extra, list) else ([] if not _useful_text(extra) else [extra])
    for item in candidates:
        key = str(item).strip().lower()
        if not key or key in seen:
            continue
        out.append(item)
        seen.add(key)
        if len(out) >= limit:
            break
    return out


def _analysis_quality_score(analysis: Dict[str, Any]) -> float:
    """Heuristic guardrail so Council cannot dilute a sharper solo pass."""
    score = 0.0
    summary = str(analysis.get("summary") or "").strip()
    if _useful_text(summary):
        score += min(len(summary) / 90.0, 3.0)
    score += min(_count_items(analysis.get("behavior")), 8) * 1.4
    score += min(_count_items(analysis.get("dataflow")), 8) * 1.5
    score += min(_count_items(analysis.get("structure_offsets")), 10) * 1.5
    score += min(_count_items(analysis.get("evidence")), 10) * 1.0
    score += min(_count_items(analysis.get("semantic_cues_used")), 8) * 1.0
    score += min(_count_items(analysis.get("comments")), 6) * 0.6

    algorithm = analysis.get("algorithm") or {}
    if isinstance(algorithm, dict):
        if _useful_text(algorithm.get("kind")):
            score += 1.0
        if _useful_text(algorithm.get("description")):
            score += min(len(str(algorithm.get("description"))) / 120.0, 2.0)

    trainer = analysis.get("trainer_assessment") or {}
    if isinstance(trainer, dict):
        for key in ("usefulness", "category", "usefulness_reason", "best_hook_strategy", "modification_surface"):
            if _useful_text(trainer.get(key)):
                score += 1.0
        for key in (
            "what_happens_if_hooked",
            "values_to_log_first",
            "candidate_trainer_features",
            "recommended_experiments",
            "not_useful_for",
            "stability_notes",
        ):
            score += min(_count_items(trainer.get(key)), 5) * 1.2

    bitstream = analysis.get("bitstream_deserialization") or {}
    if isinstance(bitstream, dict):
        if str(bitstream.get("likelihood") or "").lower() in ("medium", "high"):
            score += 1.0
        for key in ("reader_calls", "output_layout", "dirty_masks", "sanity_checks", "bitwise_checks", "string_anchors"):
            score += min(_count_items(bitstream.get(key)), 5) * 0.8

    alignment = analysis.get("user_context_alignment") or {}
    if isinstance(alignment, dict):
        if alignment.get("used"):
            score += 1.0
        if _useful_text(alignment.get("notes")):
            score += 0.8
        score += min(_count_items(alignment.get("supports_user_hint")), 4) * 0.6
        score += min(_count_items(alignment.get("contradicts_user_hint")), 4) * 0.6

    try:
        score += max(0.0, min(1.0, float(analysis.get("confidence") or 0.0))) * 2.0
    except Exception:
        pass
    if _useful_text(analysis.get("suggested_function_name")):
        score += 1.0
    if summary == "-" or not summary:
        score -= 3.0
    return score


def _has_trainer_meat(analysis: Dict[str, Any]) -> bool:
    trainer = analysis.get("trainer_assessment") or {}
    if not isinstance(trainer, dict):
        return False
    return (
        _count_items(trainer.get("what_happens_if_hooked"))
        + _count_items(trainer.get("values_to_log_first"))
        + _count_items(trainer.get("candidate_trainer_features"))
        + _count_items(trainer.get("recommended_experiments"))
    ) >= 3


def _merge_trainer_assessment(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base) if isinstance(base, dict) else {}
    extra = extra if isinstance(extra, dict) else {}
    for key in ("usefulness", "category", "usefulness_reason", "best_hook_strategy", "modification_surface"):
        if not _useful_text(out.get(key)) and _useful_text(extra.get(key)):
            out[key] = extra.get(key)
    for key in (
        "what_happens_if_hooked",
        "values_to_log_first",
        "candidate_trainer_features",
        "recommended_experiments",
        "not_useful_for",
        "stability_notes",
    ):
        out[key] = _append_unique(out.get(key), extra.get(key), limit=12)
    return out


def merge_council_advice(
    analyst_analysis: Dict[str, Any],
    synthesis_analysis: Dict[str, Any],
    multi_agent: Dict[str, Any],
) -> Dict[str, Any]:
    analyst_score = _analysis_quality_score(analyst_analysis)
    synthesis_score = _analysis_quality_score(synthesis_analysis)
    margin = max(5.0, analyst_score * 0.18)
    synthesis_is_better = (
        synthesis_score >= analyst_score + margin
        and _count_items(synthesis_analysis.get("behavior")) >= max(2, _count_items(analyst_analysis.get("behavior")) // 2)
        and _has_trainer_meat(synthesis_analysis)
    )

    if synthesis_is_better:
        out = copy.deepcopy(synthesis_analysis)
        final_source = "synthesizer"
        reason = "synthesis had stronger detail/evidence score and preserved trainer assessment"
    else:
        out = copy.deepcopy(analyst_analysis)
        final_source = "analyst"
        reason = "analyst kept as source of truth; council advice merged without overwriting core mechanics"
        for key, limit in (
            ("evidence", 18),
            ("risks", 12),
            ("behavior", 14),
            ("game_relevance", 12),
            ("engine_hints", 10),
            ("dataflow", 14),
            ("structure_offsets", 16),
            ("comments", 12),
            ("semantic_cues_used", 12),
            ("next_questions", 10),
        ):
            out[key] = _append_unique(out.get(key), synthesis_analysis.get(key), limit=limit)
        if not _useful_text(out.get("suggested_function_name")) and _useful_text(synthesis_analysis.get("suggested_function_name")):
            out["suggested_function_name"] = synthesis_analysis.get("suggested_function_name")
        out["trainer_assessment"] = _merge_trainer_assessment(
            out.get("trainer_assessment") or {},
            synthesis_analysis.get("trainer_assessment") or {},
        )
        base_algorithm = out.get("algorithm") or {}
        synth_algorithm = synthesis_analysis.get("algorithm") or {}
        if isinstance(base_algorithm, dict) and isinstance(synth_algorithm, dict):
            if not _useful_text(base_algorithm.get("description")) and _useful_text(synth_algorithm.get("description")):
                out["algorithm"] = dict(synth_algorithm)
        try:
            out["confidence"] = max(
                float(out.get("confidence") or 0.0),
                min(float(synthesis_analysis.get("confidence") or 0.0), float(out.get("confidence") or 0.0) + 0.08),
            )
        except Exception:
            pass

    out["council_decision"] = {
        "policy": "solo_anchored",
        "final_source": final_source,
        "reason": reason,
        "analyst_score": round(analyst_score, 2),
        "synthesis_score": round(synthesis_score, 2),
    }
    if isinstance(multi_agent, dict):
        multi_agent["policy"] = (
            "Solo-anchored council: the primary analyst is the source of truth; "
            "XREF/critic/synthesis may add evidence but cannot dilute core mechanics without a stronger score."
        )
    return out


class LLMWorker(QtCore.QThread):
    succeeded = signal(dict, str)
    failed = signal(str)
    progress = signal(str)

    def __init__(self, cfg: Any, context: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.context = context

    def _progress(self, message: str) -> None:
        try:
            self.progress.emit(str(message))
        except Exception:
            pass

    def _finalize_analysis(
        self,
        analysis: Dict[str, Any],
        runtime: Dict[str, Any],
        evidence_pack: Dict[str, Any] = None,
        claim_board: Dict[str, Any] = None,
        multi_agent: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        self._progress("applying mandatory function questions and analyst-hint alignment")
        analysis = ensure_function_questions(analysis, self.context)
        analysis = ensure_user_context_alignment(analysis, self.context)
        self._progress("enriching result with local IDA semantic cues")
        analysis = enrich_analysis_with_local_cues(analysis, self.context)
        self._progress("merging static external evidence sources")
        analysis = apply_external_evidence_to_analysis(analysis, self.context)
        self._progress("building trainer radar, candidates, structure hypotheses and experiments")
        analysis = build_trainer_intel(analysis, self.context)
        analysis = ensure_function_questions(analysis, self.context)
        if evidence_pack:
            analysis["evidence_pack"] = evidence_pack
        if claim_board:
            analysis["claim_board"] = claim_board
        if multi_agent:
            analysis["multi_agent"] = multi_agent
        analysis["runtime_timing"] = runtime
        return analysis

    def _analysis_from_raw(
        self,
        client: OpenAICompatClient,
        raw: str,
        parse_error_prefix: str,
        max_tokens: int,
        analysis_timeout: int,
        use_json_mode: bool,
        allow_repair: bool = True,
    ) -> tuple:
        repair_seconds = 0.0
        try:
            analysis = extract_json_object(raw)
            self._progress("%s JSON parsed successfully" % parse_error_prefix)
            return analysis, raw, repair_seconds, ""
        except Exception as parse_exc:
            if not allow_repair:
                self._progress("%s JSON parse failed near timeout; skipping repair and using local fallback: %s" % (parse_error_prefix, str(parse_exc)[:180]))
                fallback = normalize_analysis({
                    "mode": self.context.get("mode") or "local_fallback",
                    "summary": "The model responded near the timeout with malformed JSON, so Monstey skipped slow repair and used local semantic-cue fallback.",
                    "confidence": 0.25,
                    "evidence": [],
                    "risks": [
                        "LLM JSON parse failed near timeout: %s" % str(parse_exc)[:240],
                        "This avoids getting stuck in a second repair request. Rerun in Single or increase Analysis timeout for full model synthesis.",
                    ],
                    "next_questions": [],
                })
                return fallback, raw + "\n\n[Monstey local fallback: skipped repair near timeout]\n" + str(parse_exc), repair_seconds, str(parse_exc)
            try:
                self._progress("%s JSON parse failed; sending strict repair request: %s" % (parse_error_prefix, str(parse_exc)[:180]))
                repair_messages = build_json_repair_messages(raw, str(parse_exc))
                t = time.perf_counter()
                repaired = client.chat(
                    repair_messages,
                    max_tokens=min(2600, max(1600, max_tokens)),
                    json_mode=use_json_mode,
                    timeout=max(30, min(analysis_timeout, 60)),
                )
                repair_seconds = round(time.perf_counter() - t, 3)
                analysis = extract_json_object(repaired)
                self._progress("%s JSON repair succeeded in %.2fs" % (parse_error_prefix, repair_seconds))
                return analysis, repaired, repair_seconds, ""
            except Exception as repair_exc:
                self._progress("%s JSON repair failed: %s" % (parse_error_prefix, str(repair_exc)[:180]))
                fallback = normalize_analysis({
                    "mode": self.context.get("mode") or "local_fallback",
                    "summary": "The LLM returned malformed or truncated JSON, so Monstey used the local IDA semantic-cue fallback instead.",
                    "confidence": 0.25,
                    "evidence": [],
                    "risks": [
                        "LLM JSON parse failed: %s" % str(parse_exc)[:240],
                        "JSON repair failed: %s" % str(repair_exc)[:240],
                        "Rerun in Balanced, Deep, or Single mode if you need a full model-written explanation.",
                    ],
                    "next_questions": [],
                })
                return fallback, raw + "\n\n[Monstey local fallback]\n" + str(repair_exc), repair_seconds, str(repair_exc)

    def run(self):
        try:
            t0 = time.perf_counter()
            policy = agent_policy(self.cfg, self.context)
            requested_agent_mode = policy.get("requested") or "Single"
            agent_mode = policy.get("effective") or requested_agent_mode
            active_cfg = self.cfg
            if agent_mode == "Council" and getattr(self.cfg, "provider", "local") == "gemini":
                active_cfg = replace(self.cfg, provider="local") if isinstance(self.cfg, PluginConfig) else self.cfg
                self._progress("Council excludes Gemini because hosted credits/quota may be unavailable; forcing local OpenAI-compatible provider.")
            model_route = model_policy(active_cfg, self.context)
            if model_route.get("reason") and isinstance(active_cfg, PluginConfig):
                active_cfg = replace(active_cfg, model=str(model_route.get("effective") or active_cfg.model))
                self._progress(model_route.get("reason"))
            provider = active_cfg.active_provider_label() if hasattr(active_cfg, "active_provider_label") else getattr(active_cfg, "provider", "LLM")
            model = active_cfg.active_model() if hasattr(active_cfg, "active_model") else getattr(active_cfg, "model", "")
            self._progress("worker started: provider=%s, model=%s, agent_mode=%s" % (provider, model, agent_mode))
            if policy.get("reason"):
                self._progress(policy.get("reason"))
            client = OpenAICompatClient(active_cfg)

            xref_agent_seconds = 0.0
            xref_agent_error = ""
            evidence_pack = {}
            claim_board = {}
            if agent_mode == "Single":
                agent_policy_text = "Single pass: the primary analyst receives compact IDA context and produces the final analysis."
            elif agent_mode == "Duo":
                agent_policy_text = "Duo: local Evidence Pack and Claim Board are built before the solo analyst; no extra LLM agents rewrite the result."
            else:
                agent_policy_text = (
                    "Context Council: context scouts enrich XREF/caller/callee/string evidence before the solo analyst. "
                    "The analyst remains the source of truth; no critic or synthesizer rewrites the final answer."
                )
            multi_agent = {
                "mode": agent_mode,
                "requested_mode": requested_agent_mode,
                "council_mode": "context_only" if agent_mode == "Council" else "none",
                "speed_policy": policy,
                "model_policy": model_route,
                "agents": [],
                "policy": agent_policy_text,
            }
            if policy.get("reason"):
                multi_agent["agents"].append({
                    "name": "speed_guard",
                    "status": "ok",
                    "summary": policy.get("reason"),
                })
            if agent_mode in ("Duo", "Council"):
                self._progress("building shared Evidence Pack and Claim Board")
                evidence_pack = build_evidence_pack(self.context)
                claim_board = build_claim_board(evidence_pack)
                self.context["evidence_pack"] = evidence_pack
                self.context["claim_board"] = claim_board
                multi_agent["agents"].append({
                    "name": "local_scout",
                    "status": "ok",
                    "summary": "Evidence Pack %s built with %d facts and %d initial claims."
                    % (
                        evidence_pack.get("id"),
                        len(evidence_pack.get("facts") or []),
                        len(evidence_pack.get("initial_claims") or []),
                    ),
                })
                self._progress(
                    "Evidence Pack %s ready: %d facts, %d claims"
                    % (
                        evidence_pack.get("id"),
                        len(evidence_pack.get("facts") or []),
                        len(evidence_pack.get("initial_claims") or []),
                    )
                )
                if agent_mode == "Council":
                    multi_agent["agents"].append({
                        "name": "context_council_policy",
                        "status": "ok",
                        "summary": "Extra agents are restricted to external context collection; final analysis stays with the primary analyst.",
                    })
                    self._progress("Context Council enabled: scouts prepare external context; solo analyst keeps final authority.")
                    try:
                        budget_xref = subagent_budget(active_cfg, self.context, "xref")
                        self._progress(
                            "xref_context_scout: connecting callers/callees/data refs before analyst pass "
                            "(budget %ds/%d tokens)"
                            % (budget_xref["timeout"], budget_xref["max_tokens"])
                        )
                        xref_messages = build_xref_explorer_messages(self.context, evidence_pack, claim_board)
                        t = time.perf_counter()
                        xref_raw = client.chat(
                            xref_messages,
                            max_tokens=budget_xref["max_tokens"],
                            json_mode=getattr(active_cfg, "provider", "local") != "gemini",
                            timeout=budget_xref["timeout"],
                        )
                        xref_agent_seconds = round(time.perf_counter() - t, 3)
                        xref_output = parse_json_object(xref_raw)
                        claim_board = apply_agent_claim_updates(claim_board, "xref_context_scout", xref_output)
                        self.context["claim_board"] = claim_board
                        multi_agent["agents"].append({
                            "name": "xref_context_scout",
                            "status": "ok",
                            "summary": str(xref_output.get("summary") or "XREF context connected.")[:360],
                        })
                        self._progress("xref_context_scout: completed in %.2fs" % xref_agent_seconds)
                    except Exception as exc:
                        xref_agent_error = str(exc)
                        multi_agent["agents"].append({
                            "name": "xref_context_scout",
                            "status": "error",
                            "summary": str(exc)[:260],
                        })
                        self._progress("xref_context_scout: failed, continuing without XREF agent: %s" % str(exc)[:180])

            self._progress("building analysis messages from compact context")
            messages = build_analysis_messages(self.context, active_cfg.engine_profile)
            budget = active_cfg.depth_budget() if hasattr(active_cfg, "depth_budget") else {}
            max_tokens = int(budget.get("max_analysis_tokens", getattr(active_cfg, "max_analysis_tokens", 1600)))
            analysis_timeout = int(getattr(active_cfg, "analysis_timeout_seconds", 75))
            use_json_mode = getattr(active_cfg, "provider", "local") != "gemini"

            t = time.perf_counter()
            try:
                self._progress(
                    "analyst: sending chat/completions request: max_tokens=%d, timeout=%ds, json_mode=%s"
                    % (max_tokens, analysis_timeout, "on" if use_json_mode else "off")
                )
                raw = client.chat(messages, max_tokens=max_tokens, json_mode=use_json_mode, timeout=analysis_timeout)
                llm_seconds = round(time.perf_counter() - t, 3)
                llm_error = ""
                self._progress("analyst: LLM response received in %.2fs; parsing JSON" % llm_seconds)
            except Exception as llm_exc:
                llm_seconds = round(time.perf_counter() - t, 3)
                llm_error = str(llm_exc)
                raw = ""
                self._progress("analyst: request failed after %.2fs; switching to local fallback: %s" % (llm_seconds, llm_error[:180]))

            repair_seconds = 0.0
            critic_seconds = 0.0
            synthesis_seconds = 0.0
            critic_error = ""
            synthesis_error = ""
            parse_error = ""
            if llm_error:
                analysis = normalize_analysis({
                    "mode": self.context.get("mode") or "local_fallback",
                    "summary": "The hosted/local model did not complete in time, so Monstey used the local IDA semantic-cue fallback.",
                    "confidence": 0.25,
                    "evidence": [],
                    "risks": [
                        "LLM call failed or timed out after %.1fs: %s" % (llm_seconds, llm_error[:260]),
                        "Use Quick Local Pass for instant triage or rerun in Single/Balanced/Deep when the provider is responsive.",
                    ],
                    "next_questions": [],
                })
                raw = "[Monstey local fallback after LLM error]\n" + llm_error
                multi_agent["agents"].append({"name": "analyst", "status": "error", "summary": llm_error[:260]})
            else:
                allow_repair = llm_seconds < max(12, float(analysis_timeout) * 0.72)
                analysis, raw, repair_seconds, parse_error = self._analysis_from_raw(
                    client, raw, "analyst", max_tokens, analysis_timeout, use_json_mode, allow_repair=allow_repair
                )
                multi_agent["agents"].append({
                    "name": "analyst",
                    "status": "fallback" if parse_error else "ok",
                    "summary": "Primary analysis completed in %.2fs." % llm_seconds,
                })
                if parse_error:
                    multi_agent["agents"][-1]["summary"] += " JSON parse fallback: %s" % str(parse_error)[:180]
            if evidence_pack:
                claim_board.setdefault("agent_notes", []).append({
                    "agent": "analyst",
                    "summary": str(analysis.get("summary") or "")[:700],
                })
                analysis["evidence_pack"] = evidence_pack
                analysis["claim_board"] = claim_board
                analysis["multi_agent"] = multi_agent

            if agent_mode == "Council":
                self._progress("Context Council: post-analysis critic/synthesizer disabled; keeping solo analyst result.")
                status = "fallback" if (llm_error or parse_error) else "ok"
                reason = "analyst fallback kept" if (llm_error or parse_error) else "primary analyst kept as final source"
                multi_agent["agents"].append({
                    "name": "context_council_finalizer",
                    "status": status,
                    "summary": "No critic/synthesizer pass was run; %s after context scouts enriched the Claim Board." % reason,
                })
                analysis["council_decision"] = {
                    "policy": "context_only",
                    "final_source": "analyst" if not (llm_error or parse_error) else "local_fallback",
                    "reason": "Council agents prepare XREF/external context only and cannot overwrite the analyst's mechanics.",
                    "xref_agent_seconds": xref_agent_seconds,
                    "xref_agent_error": xref_agent_error,
                }

            runtime = {
                "llm_seconds": llm_seconds,
                "llm_error": llm_error,
                "json_repair_seconds": repair_seconds,
                "critic_seconds": critic_seconds,
                "critic_error": critic_error,
                "synthesis_seconds": synthesis_seconds,
                "synthesis_error": synthesis_error,
                "xref_agent_seconds": xref_agent_seconds,
                "xref_agent_error": xref_agent_error,
                "worker_total_seconds": round(time.perf_counter() - t0, 3),
                "max_analysis_tokens": max_tokens,
                "analysis_depth": getattr(self.cfg, "analysis_depth", ""),
                "effective_provider": getattr(active_cfg, "provider", getattr(self.cfg, "provider", "")),
                "effective_model": model,
                "agent_mode": agent_mode,
                "requested_agent_mode": requested_agent_mode,
                "council_mode": "context_only" if agent_mode == "Council" else "none",
                "agent_policy": policy,
                "analysis_timeout_seconds": analysis_timeout,
            }
            analysis = self._finalize_analysis(analysis, runtime, evidence_pack, claim_board, multi_agent)
            self._progress("analysis worker done in %.2fs" % round(time.perf_counter() - t0, 3))
            self.succeeded.emit(analysis, raw)
        except Exception as exc:
            self._progress("worker fatal error: %s" % str(exc)[:240])
            self.failed.emit(str(exc))


class TestLLMWorker(QtCore.QThread):
    succeeded = signal(str)
    failed = signal(str)

    def __init__(self, cfg: Any, parent=None):
        super().__init__(parent)
        self.cfg = cfg

    def run(self):
        try:
            client = OpenAICompatClient(self.cfg)
            self.succeeded.emit(client.test())
        except Exception as exc:
            self.failed.emit(str(exc))


class ActionWorker(QtCore.QThread):
    succeeded = signal(str)
    failed = signal(str)
    progress = signal(str)

    def __init__(self, cfg: Any, context: Dict[str, Any], analysis: Dict[str, Any], action_kind: str, user_goal: str, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.context = context
        self.analysis = analysis
        self.action_kind = action_kind
        self.user_goal = user_goal

    def _progress(self, message: str) -> None:
        try:
            self.progress.emit(str(message))
        except Exception:
            pass

    def run(self):
        try:
            provider = self.cfg.active_provider_label() if hasattr(self.cfg, "active_provider_label") else getattr(self.cfg, "provider", "LLM")
            model = self.cfg.active_model() if hasattr(self.cfg, "active_model") else getattr(self.cfg, "model", "")
            self._progress("Action Lab worker started: provider=%s, model=%s, action=%s" % (provider, model, self.action_kind))
            client = OpenAICompatClient(self.cfg)
            self._progress("building call/hook prompt with current analysis and user goal")
            messages = build_action_messages(self.context, self.analysis, self.action_kind, self.user_goal)
            t = time.perf_counter()
            self._progress("sending Action Lab request")
            raw = client.chat(messages, max_tokens=3600)
            self._progress("Action Lab response received in %.2fs" % round(time.perf_counter() - t, 3))
            self.succeeded.emit(raw)
        except Exception as exc:
            self._progress("Action Lab failed: %s" % str(exc)[:240])
            self.failed.emit(str(exc))


class PseudoDiffWorker(QtCore.QThread):
    succeeded = signal(dict, str)
    failed = signal(str)
    progress = signal(str)

    def __init__(self, cfg: Any, old_text: str, new_text: str, user_goal: str, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.old_text = old_text
        self.new_text = new_text
        self.user_goal = user_goal

    def _progress(self, message: str) -> None:
        try:
            self.progress.emit(str(message))
        except Exception:
            pass

    def run(self):
        try:
            provider = self.cfg.active_provider_label() if hasattr(self.cfg, "active_provider_label") else getattr(self.cfg, "provider", "LLM")
            model = self.cfg.active_model() if hasattr(self.cfg, "active_model") else getattr(self.cfg, "model", "")
            self._progress("Pseudo Diff worker started: provider=%s, model=%s" % (provider, model))
            local = local_pseudocode_diff(self.old_text, self.new_text)
            fallback_text = render_local_pseudocode_diff_text(local)
            old_len = len(str(self.old_text or "").strip())
            new_len = len(str(self.new_text or "").strip())
            if old_len < 16 or new_len < 16:
                self._progress("not enough pseudocode for AI comparison; returning local diff")
                self.succeeded.emit(local, fallback_text)
                return
            messages = build_pseudocode_diff_messages(self.old_text, self.new_text, local, self.user_goal)
            client = OpenAICompatClient(self.cfg)
            timeout = max(20, min(int(getattr(self.cfg, "analysis_timeout_seconds", 45)), 120))
            max_tokens = max(1200, min(int(getattr(self.cfg, "max_analysis_tokens", 1800)) + 700, 3000))
            self._progress("sending pseudocode diff request: max_tokens=%d, timeout=%ds" % (max_tokens, timeout))
            t = time.perf_counter()
            try:
                raw = client.chat(messages, max_tokens=max_tokens, json_mode=False, timeout=timeout)
                self._progress("Pseudo Diff AI response received in %.2fs" % round(time.perf_counter() - t, 3))
                self.succeeded.emit(local, str(raw or "").strip() or fallback_text)
            except Exception as exc:
                self._progress("Pseudo Diff AI failed; returning local diff: %s" % str(exc)[:220])
                text = fallback_text + "\n\nAI note:\n- Provider failed or timed out: %s" % str(exc)[:400]
                self.succeeded.emit(local, text)
        except Exception as exc:
            self.failed.emit(str(exc))


class ToolchainWorker(QtCore.QThread):
    succeeded = signal(dict, str)
    failed = signal(str)
    progress = signal(str)

    def __init__(self, command: str, context: Dict[str, Any] = None, scout: str = "all", timeout: int = 45, parent=None):
        super().__init__(parent)
        self.command = str(command or "check")
        self.context = context if isinstance(context, dict) else {}
        self.scout = str(scout or "all")
        self.timeout = int(timeout or 45)

    def _progress(self, message: str) -> None:
        try:
            self.progress.emit(str(message))
        except Exception:
            pass

    def run(self):
        try:
            if self.command == "check":
                self._progress("toolchain sidecar: checking optional libraries")
                data = toolchain_status(timeout=max(8, min(self.timeout, 30)))
            else:
                self._progress("toolchain sidecar: running %s scout" % self.scout)
                data = toolchain_scout_context(self.context, scout=self.scout, timeout=max(10, self.timeout))
            text = str(data.get("evidence_text") or "").strip()
            self._progress("toolchain sidecar: completed with %s row(s)" % data.get("row_count", "-"))
            self.succeeded.emit(data, text)
        except Exception as exc:
            self._progress("toolchain sidecar failed: %s" % str(exc)[:240])
            self.failed.emit(str(exc))
