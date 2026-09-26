"""In-memory analysis scheduler for native message views; no Frida or GUI imports.

Host contract:
    scheduler = NativeAnalysis(on_result)
    scheduler.on_snapshot({"conversation": stable_peer_id, "messages": [
        {"id": view_id, "generation": binding_generation, "who": "her",
         "text": "...", "name": optional_group_sender, "targetEligible": True,
         "logicalId": optional_stable_model_message_id}]})
    scheduler.tick()  # Call regularly on the same host thread as on_snapshot.

Messages are chronological. Conversation must be an opaque, stable peer identifier,
not a potentially duplicated display name. The host must increment generation when
a native view is rebound. on_result(id, generation, text) runs ONLY from these host
calls; the host must recheck its native binding before dispatching to its GUI thread.

Only the latest three eligible remote messages are candidates. targetEligible
defaults to True; explicit False retains the message only as context. The adapter
must preserve its target/context batch across annotation-only layout changes.
Each request ends at its own target and contains at most twelve messages. Full peer/context fingerprints key an
in-memory LRU; neither conversation text nor API bodies are logged or written.
When logicalId is supplied, its first stable context is retained in a separate
64-entry LRU keyed by peer, logical identity, role and exact original text. A
same-message view rebind can reuse its pending request and deliver to the new
id/generation. Without logicalId, the original strict view-binding behavior applies.

A 45-second deadline invalidates results. Python cannot stop an arbitrary injected
analyze_fn: an expired worker retains the sole execution slot until it returns.
The default engine has a 40-second SDK timeout. This prevents overlapping requests
even if an underlying transport fails to honor its timeout.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import queue
import sys
import threading
import time
from typing import Any, Callable


RELATIONSHIP = "通用沟通：朋友、同事、客户等；根据上下文判断，不预设亲密关系"
MAX_CONTEXT = 12
MAX_CANDIDATES = 3
CACHE_LIMIT = 64
DEADLINE_SECONDS = 45
RETRY_SECONDS = 8
MAX_ATTEMPTS = 2


def engine_root():
    root = Path(__file__).resolve().parent
    packaged = root / 'engine'
    return packaged if (packaged / 'core' / 'engine.py').is_file() else root.parent / 'jev-chat-windows-v019'


def _default_analyze(messages, **options):
    """Reuse the installed source engine and its existing environment-key reader."""
    source = str(engine_root())
    if source not in sys.path:
        sys.path.insert(0, source)
    from app import settings
    from core.engine import analyze
    # Reuse the existing Windows User-environment fallback; do not implement or
    # persist a second key store in this adapter.
    if not settings.has_jev_key():
        raise ValueError("No local Jev key configured")
    return analyze(messages, **options)


def _text(value: Any, limit: int, fallback: str = "") -> str:
    if not isinstance(value, str):
        return fallback
    value = " ".join(value.replace("\x00", "").split())
    if not value or value.casefold() in {"nan", "inf", "+inf", "-inf", "infinity", "null", "none"}:
        return fallback
    return value if len(value) <= limit else value[:limit - 1] + "…"


def _number(value: Any, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except (OverflowError, ValueError):
        return None
    return value if math.isfinite(value) and 0 <= value <= maximum else None


def format_analysis(result: dict) -> str:
    """Bounded plain text; never invent a probability for missing/invalid data."""
    if not isinstance(result, dict) or result.get("available") is not True:
        raise ValueError("No usable analysis")
    title = _text(result.get("question_title"), 60, "对方这句话可能意味着什么？")
    options = []
    raw_options = result.get("options")
    if isinstance(raw_options, (list, tuple)):
        for entry in raw_options:
            if not isinstance(entry, dict):
                continue
            probability = _number(entry.get("probability"), 1)
            label = _text(entry.get("label"), 90)
            if probability is not None and label:
                options.append((probability, label))
    options.sort(key=lambda item: item[0], reverse=True)
    lines = ["Jev｜" + title]
    for probability, label in options[:2]:
        lines.append(f"• {label}：{probability * 100:.1f}%")
    if not options:
        lines.append("• 解读概率：信息不足")
    elif len(options) == 1:
        lines.append("• 其他解读：暂无有效概率")
    risk = _number(result.get("risk_score"), 10)
    lines.append("风险：" + (f"{risk:.1f}/10" if risk is not None else "暂无法判断"))
    action = _text(result.get("action"), 105, "补充必要背景后再决定下一步")
    lines.append("行动：" + action)
    lines.append("概率为模型判断，仅供参考")
    return "\n".join(lines)[:420]


@dataclass(eq=False)
class _Candidate:
    id: str | int
    generation: str | int
    fingerprint: str
    turns: tuple
    logical_key: str | None = None
    attempts: int = 0
    retry_at: float = 0
    delivered: bool = False

    @property
    def binding(self):
        return self.id, self.generation, self.fingerprint


@dataclass
class _Job:
    serial: int
    candidate: _Candidate
    deadline: float
    expired: bool = False


class NativeAnalysis:
    """One worker, host-thread delivery, bounded per-view retries and shared cache.

    submit accepts a zero-argument callable and must execute it at most once;
    if it raises, it must not have scheduled the callable.
    It can append that callable to a list in deterministic tests. analyze_fn has
    the core.engine.analyze signature. clock must be monotonic and thread-safe.
    on_result should enqueue a native GUI operation, never assume callback thread
    is WeChat's GUI thread. close()/set_enabled(False) invalidate pending delivery.
    """

    def __init__(self, on_result: Callable, *, analyze_fn=None, submit=None,
                 clock=time.monotonic, context=MAX_CONTEXT):
        if isinstance(context, bool) or not isinstance(context, int) or context < 1:
            raise ValueError("context must be a positive integer")
        self.on_result = on_result
        self.analyze_fn = analyze_fn or _default_analyze
        self.submit = submit or self._submit_thread
        self.clock = clock
        self.context = min(context, MAX_CONTEXT)
        self.cache: OrderedDict[str, str] = OrderedDict()
        self._frozen_contexts: OrderedDict[str, tuple] = OrderedDict()
        self.conversation = None
        self.candidates: list[_Candidate] = []
        self.active: _Job | None = None
        self.enabled = True
        self.closed = False
        self._serial = 0
        self._completed = queue.SimpleQueue()
        self._count_lock = threading.Lock()
        self._requests_started = 0
        self._requests_completed = 0

    @staticmethod
    def _submit_thread(work):
        threading.Thread(target=work, name="JevNativeAnalysis", daemon=True).start()

    @property
    def busy(self) -> bool:
        """Includes expired/stale workers until their execution actually finishes."""
        return self.active is not None

    @property
    def request_counts(self) -> dict[str, int]:
        """Actual analyze_fn executions, including failures/late returns, excluding cache hits.

        These are local request-attempt counters, not a provider billing receipt.
        Returning a copy prevents the host from changing coordinator counters.
        """
        with self._count_lock:
            return {"requestsStarted": self._requests_started,
                    "requestsCompleted": self._requests_completed}

    def set_enabled(self, enabled: bool):
        self.enabled = bool(enabled) and not self.closed
        if not self.enabled:
            self.candidates = []
            self.conversation = None

    def close(self):
        self.closed = True
        self.set_enabled(False)
        self.cache.clear()
        self._frozen_contexts.clear()

    def on_snapshot(self, snapshot: dict):
        if self.closed or not self.enabled:
            return
        conversation = snapshot.get("conversation")
        if not isinstance(conversation, str) or not conversation.strip():
            # No stable peer identifier: invalidate old bindings and fail closed.
            self.conversation = None
            self.candidates = []
            self.tick()
            return
        messages = snapshot.get("messages", [])
        if not isinstance(messages, list):
            raise ValueError("messages must be a chronological list")
        cleaned = []
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("Invalid message")
            who, text = message.get("who"), message.get("text")
            if who not in ("her", "me") or not isinstance(text, str):
                raise ValueError("Invalid message role or text")
            if not text.strip():
                continue
            identifier, generation = message.get("id"), message.get("generation")
            if any(isinstance(value, bool) or not isinstance(value, (str, int))
                   for value in (identifier, generation)):
                raise ValueError("Each message requires an id and generation")
            name = message.get("name")
            if name is not None and not isinstance(name, str):
                raise ValueError("Invalid sender name")
            eligible = message.get("targetEligible", True)
            if not isinstance(eligible, bool):
                raise ValueError("targetEligible must be a boolean")
            logical_id = message.get("logicalId")
            if logical_id is not None and (isinstance(logical_id, bool)
                    or not isinstance(logical_id, (str, int)) or logical_id == ""):
                raise ValueError("logicalId must be a stable nonempty string or integer")
            # Copy snapshot values; the producer may mutate its dictionaries later.
            cleaned.append((identifier, generation, who, text, name, eligible, logical_id))
        previous = {candidate.binding: candidate for candidate in self.candidates}
        if conversation != self.conversation:
            previous.clear()
        previous_logical = {candidate.logical_key: candidate for candidate in previous.values()
                            if candidate.logical_key is not None}
        self.conversation = conversation
        frozen = {}
        for index, message in enumerate(cleaned):
            if message[6] is None or message[2] != "her" or not message[5]:
                continue
            identity = (conversation, message[6], message[2], message[3])
            logical_key = hashlib.sha256(json.dumps(identity, ensure_ascii=False,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
            if logical_key not in self._frozen_contexts:
                self._frozen_contexts[logical_key] = tuple(tuple(item[2:5]) for item in
                    cleaned[max(0, index - self.context + 1):index + 1])
            self._frozen_contexts.move_to_end(logical_key)
            frozen[index] = logical_key, self._frozen_contexts[logical_key]
            while len(self._frozen_contexts) > CACHE_LIMIT:
                self._frozen_contexts.popitem(last=False)
        indices = [i for i, message in enumerate(cleaned)
                   if message[2] == "her" and message[5]][-MAX_CANDIDATES:]
        candidates = []
        for index in reversed(indices):
            identifier, generation, *_ = cleaned[index]
            logical_key = None
            if index in frozen:
                logical_key, turns = frozen[index]
            else:
                turns = tuple(tuple(item[2:5]) for item in cleaned[max(0, index - self.context + 1):index + 1])
            payload = (conversation, RELATIONSHIP, "typesafe", "jev-latest", turns)
            if logical_key is not None:
                payload += (logical_key,)
            fingerprint = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                                    separators=(",", ":")).encode("utf-8")).hexdigest()
            binding = identifier, generation, fingerprint
            candidate = previous.get(binding)
            if candidate is None and logical_key is not None:
                prior = previous_logical.get(logical_key)
                if prior is not None and prior.fingerprint == fingerprint:
                    # Same peer, immutable message identity/text and frozen context:
                    # keep one in-flight job, but never deliver to the retired view.
                    candidate = prior
                    candidate.id, candidate.generation = identifier, generation
                    candidate.delivered = False
            if candidate is None:
                candidate = _Candidate(identifier, generation, fingerprint, turns, logical_key)
            candidates.append(candidate)
        self.candidates = candidates
        self.tick()

    def _current(self, candidate):
        return self.enabled and not self.closed and any(item is candidate for item in self.candidates)

    def _fail(self, candidate, when):
        if self._current(candidate):
            candidate.retry_at = when + RETRY_SECONDS

    def _deliver(self, candidate, text):
        if self._current(candidate) and not candidate.delivered:
            self.on_result(candidate.id, candidate.generation, text)
            candidate.delivered = True

    def tick(self):
        """Drain completion, expire old work, deliver cache, then start one request."""
        while True:
            try:
                serial, completed_at, formatted = self._completed.get_nowait()
            except queue.Empty:
                break
            job = self.active
            if job is None or serial != job.serial:
                continue
            self.active = None
            if not self._current(job.candidate) or job.expired:
                continue
            if completed_at >= job.deadline:
                self._fail(job.candidate, job.deadline)
                continue
            if formatted is None:
                self._fail(job.candidate, completed_at)
                continue
            self.cache[job.candidate.fingerprint] = formatted
            self.cache.move_to_end(job.candidate.fingerprint)
            while len(self.cache) > CACHE_LIMIT:
                self.cache.popitem(last=False)
            self._deliver(job.candidate, formatted)
        now = self.clock()
        if self.active is not None and not self.active.expired and now >= self.active.deadline:
            self.active.expired = True
            self._fail(self.active.candidate, self.active.deadline)
        if not self.enabled or self.closed:
            return
        for candidate in self.candidates:
            if not candidate.delivered and candidate.fingerprint in self.cache:
                self.cache.move_to_end(candidate.fingerprint)
                self._deliver(candidate, self.cache[candidate.fingerprint])
        if self.active is not None:
            return
        chosen = next((candidate for candidate in self.candidates
                       if not candidate.delivered and candidate.attempts < MAX_ATTEMPTS
                       and now >= candidate.retry_at), None)
        if chosen is None:
            return
        self._serial += 1
        job = _Job(self._serial, chosen, now + DEADLINE_SECONDS)
        self.active = job
        chosen.attempts += 1
        options = dict(relationship=RELATIONSHIP, context=self.context, timeout=40,
                       analysis_only=True, jev_provider="typesafe", jev_model="jev-latest")

        def work():
            formatted = None
            with self._count_lock:
                self._requests_started += 1
            try:
                # Retain only bounded display text after analysis; no API body in queue/cache.
                result = self.analyze_fn(list(chosen.turns), **options)
                formatted = format_analysis(result)
            except Exception:
                # Do not retain/log exceptions that may contain request bodies or keys.
                pass
            finally:
                with self._count_lock:
                    self._requests_completed += 1
            self._completed.put((job.serial, self.clock(), formatted))

        try:
            self.submit(work)
        except Exception:
            self.active = None
            self._fail(chosen, self.clock())
