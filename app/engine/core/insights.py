"""Read-only Jev conversation insights; all displayed prose comes from bounded labels.

One System One request judges one explicit remote message and its preceding context.
There is no reply generation, input injection, credential access, or persistent history.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from .jev_client import ask
from .questions import build_state


_COMMON = (
    "Judge `analysis_target.text`, using `chat.messages` as its preceding conversation context. "
    "This is general communication among friends, colleagues, or customers unless the supplied "
    "relationship says otherwise. Interpret observable wording and context, not private mental states. "
    "Do not assume sarcasm, coercion, conflict, romance, or an unstated obligation. "
    "Ordinary literal communication is a valid outcome. Missing context should increase uncertainty. "
    "A softened tone, '不急' (no rush), or '你先忙' (finish your work first) does not cancel an earlier request "
    "or an agreed arrangement. Previously confirmed tasks remain in effect unless explicitly cancelled or changed. "
)

# Each entry is (UI label, independent criterion description). These are hypotheses,
# not free-form model explanations or claims that we know the speaker's thoughts.
_GENERAL = {
    "literal": ("字面信息或问题，没有明显潜台词", "Straightforward information or a question; no evidence of an indirect demand."),
    "request": ("可能期待具体行动或答复", "A concrete action or substantive response is requested or reasonably implied."),
    "negotiate": ("可能在征询意见或协商安排", "The sender is inviting input or negotiating an arrangement, with alternatives still open."),
    "concern": ("可能在表达顾虑或不满", "The actual wording and context express a specific concern or dissatisfaction."),
    "social": ("可能只是寒暄、确认或收尾", "Friendly conversation, acknowledgment, thanks, or a completed exchange with no further demand."),
    "unknown": ("信息不足，暂不能判断", "The available context cannot distinguish the alternatives, or none fits."),
}

_SCOPE = {
    "understated": ("表述轻描淡写，实际范围可能不小", "The sender calls the work small or simple but describes a broad product, multiple substantial capabilities, or an integration with undefined effort; clarify scope rather than accepting the minimizing wording as an effort estimate."),
    "literal": ("可能确实是一项顺手的小事", "A small, clear request fits the existing arrangement, with no evidence of extra scope."),
    "added_scope": ("可能增加原先未约定的工作", "The request adds a deliverable or changes agreed scope; actual effort needs confirmation."),
    "feasibility": ("可能先在询问能否做到", "The sender is exploring feasibility rather than issuing a settled instruction."),
    "social": ("可能只是提议，没有要求承诺", "A casual suggestion with no evidence that the recipient must accept it."),
    "unknown": ("范围或背景不足，暂不能判断", "There is insufficient evidence to determine the request's scope or implied expectation."),
}

_DEADLINE = {
    "literal": ("可能只是确认时间安排", "A neutral question or reminder about a time, without a new delivery obligation."),
    "deadline": ("可能期待在指定时间前完成", "The sender clearly asks for completion or a deliverable by the stated time."),
    "progress": ("可能在询问进度或可行时间", "The sender is checking progress or availability and has not fixed a new commitment."),
    "flexible": ("可能仍有协商时间的空间", "The wording explicitly leaves timing open to discussion or alternatives."),
    "unknown": ("交付要求或时间背景不足", "It is unclear what must happen at the stated time or whether it is a deadline."),
}

_MEETING = {
    "literal": ("可能是正常的事务沟通", "A routine meeting or conversation request; no evidence of a problem or confrontation."),
    "progress": ("可能要对齐进度或下一步", "The supplied context points to a progress check or practical coordination."),
    "issue": ("可能要讨论已提到的问题", "A specific issue already mentioned in the thread is the likely topic."),
    "open_topic": ("议题还没有说明，需要确认", "A meeting is requested but its topic is not stated; there is no basis to infer a negative outcome."),
    "unknown": ("上下文不足，暂不能判断", "The available messages do not support a useful interpretation."),
}

_DISCRETION = {
    "literal": ("可能确实让你自主安排", "The sender genuinely leaves the choice to the recipient, with no contradictory constraint in context."),
    "bounded": ("可能只在既定范围内授权", "Earlier requirements or constraints still apply even though details are delegated."),
    "preference": ("可能没有强烈偏好", "The sender expresses flexibility about a low-stakes choice rather than assigning responsibility."),
    "clarify": ("责任或验收标准还需要明确", "Delegation leaves a consequential responsibility or acceptance criterion unspecified."),
    "unknown": ("授权边界不清，暂不能判断", "The context does not establish whether this is delegation, preference, or something else."),
}

_DEFER = {
    "literal": ("原安排可能仍有效，只是不催促", "An earlier request or agreed task remains active; the latest message merely reduces pressure or allows the recipient to finish other work first."),
    "timing_open": ("可能需要再确认具体处理时间", "An earlier request remains active but its actual timing has been left open or changed without a settled replacement."),
    "cancelled": ("此前要求可能已经明确取消", "The conversation explicitly withdraws the earlier request or says it no longer needs doing; politeness or no-rush wording alone does not qualify."),
    "social": ("可能只是客套，没有未完成安排", "The available conversation shows no outstanding request; this is a courteous closing or ordinary well-wishing."),
    "unknown": ("前文不足，无法确认是否有待办安排", "The context does not establish whether an earlier request exists or remains active."),
}

_INTENTS = {
    "inform": ("告知信息", "Provide information without requesting further action."),
    "ask": ("询问事实或意见", "Ask for facts, an explanation, or an opinion."),
    "request": ("提出任务或请求", "Ask the recipient for a concrete action or deliverable."),
    "negotiate": ("协商安排或边界", "Discuss alternatives, responsibilities, scope, or timing."),
    "concern": ("表达具体顾虑", "Express an observable concern, disagreement, or dissatisfaction."),
    "social": ("寒暄、确认或收尾", "Friendly chat, acknowledgment, thanks, or closing the exchange."),
    "unknown": ("暂无法判断", "The current message and context do not support a category."),
}

_IMPACTS = {
    "routine": ("暂未看到需要改变安排的依据", "No material change to the recipient's plan or commitment is supported by the message."),
    "scope": ("是否接受额外范围需要确认", "The recipient must consider additional or changed scope before accepting it."),
    "timing": ("时间安排或完成期限需要确认", "The recipient needs to check feasibility or coordinate timing before committing."),
    "responsibility": ("责任与验收边界需要明确", "The recipient needs clarity about responsibility or what counts as completion."),
    "facts": ("关键事实不全，直接决定可能误解", "A missing fact or ambiguous reference prevents a well-grounded decision."),
    "disagreement": ("已有分歧需要先对齐", "An explicitly expressed disagreement needs acknowledgment and clarification before proceeding."),
    "unknown": ("信息不足，暂不能判断决策影响", "There is not enough context to identify a material implication."),
}

_ACTIONS = {
    "answer": ("核对已有事实后回应对方的具体问题", "Answer a clear question using facts already known; do not invent missing information."),
    "clarify": ("先问清具体指代、目标或期望", "Ask for clarification of the ambiguous reference, goal, or expectation."),
    "verify": ("先核对前文或相关资料，再作判断", "Check prior messages or relevant facts before taking a position."),
    "scope": ("先确认新增范围与验收标准，再评估是否承接", "Clarify the added scope and acceptance criteria before accepting extra work."),
    "timing": ("先核对可行时间，再确认期限或提出替代安排", "Check availability and feasibility, then confirm timing or propose an alternative without overpromising."),
    "responsibility": ("先确认谁负责、你能决定哪些事项", "Clarify responsibility and authority before acting on unclear delegation."),
    "agenda": ("先确认要讨论的事项与需要准备的材料", "Confirm the meeting topic and required preparation when these are missing."),
    "acknowledge": ("先回应已表达的顾虑，再核对事实与下一步", "Acknowledge an explicit concern, then clarify facts and next steps without admitting an unestablished fault."),
    "brief": ("简短确认即可，暂不增加新的承诺", "A brief acknowledgment is sufficient; do not add new commitments."),
    "wait": ("本轮可不补充回复，继续按已确认的安排处理", "No additional reply is needed in this conversational turn. Continue any previously confirmed tasks or arrangements; this option never cancels an outstanding request merely because the sender says no rush or finish your work first."),
    "unknown": ("补充必要背景后再决定下一步", "The available context does not support any other action; seek relevant context."),
}

# Current official Score API accepts at most ten levels. Display maps the returned
# 0..9 weighted score to 0..10; it is a rubric score, not a probability of harm.
_RISK_LEVELS = [
    "Routine clear exchange or friendly closure; no apparent disagreement, consequential ambiguity, or unmet obligation.",
    "Small harmless ambiguity or reminder; ordinary clarification is sufficient and no dissatisfaction is expressed.",
    "A concrete minor expectation needs clarification; cooperation remains clear and no conflict is expressed.",
    "Scope, timing, or responsibility is materially unclear; agreeing immediately could create an unintended commitment.",
    "A specific disagreement or dissatisfaction is expressed, but both sides are still discussing a resolution constructively.",
    "A known disputed expectation remains unresolved and the wording applies explicit pressure to accept or respond.",
    "Repeated unresolved disagreement or direct blame is escalating the exchange; a hasty response could worsen it.",
    "An explicit warning of a concrete consequence is tied to an unresolved disagreement or commitment.",
    "An active ultimatum or serious threat to end cooperation remains in force; no resolution is established.",
    "The exchange contains an active severe confrontation or an explicit breakdown of cooperation, not merely a short or ambiguous message.",
]


def _template(text: str) -> tuple[str, dict]:
    if re.search(r"不急|不着急|你先忙|忙完再|慢慢来", text):
        return "这句缓和语气的话，是否改变了先前安排？", _DEFER
    if re.search(r"小需求|小功能|很简单|简单点|简单做|顺便|加一个|加一下|增加.*功能|改一下", text):
        return "这项看似简单的请求，可能意味着什么？", _SCOPE
    if re.search(r"你看着安排|你看着办|自己安排|你决定|都行|随便", text):
        return "这句让你安排的话，可能留下哪些边界？", _DISCRETION
    if re.search(r"办公室|来一趟|聊一下|聊聊|谈一下", text):
        return "这次沟通邀请，可能想讨论什么？", _MEETING
    if re.search(r"明天|今晚|下班前|今天|尽快|马上|截止|deadline", text, re.IGNORECASE):
        return "这句时间要求，可能期待你做什么？", _DEADLINE
    return "结合前文，对方这句话可能表达什么？", _GENERAL


def _choice(instructions: str, entries: dict) -> dict:
    return {"type": "choice", "instructions": _COMMON + instructions,
            "criteria": {key: description for key, (_, description) in entries.items()}}


def _number(value, minimum: float = 0, maximum: float = 1) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and minimum <= number <= maximum else None


def _distribution(answer, entries: dict) -> dict[str, float]:
    if not isinstance(answer, dict) or answer.get("type") != "choice":
        return {}
    raw = answer.get("probabilities")
    if not isinstance(raw, dict) or not raw or any(key not in entries for key in raw):
        return {}
    values = {key: _number(value) for key, value in raw.items()}
    if any(value is None for value in values.values()):
        return {}
    # Preserve returned probabilities without normalization or invented missing values.
    if not math.isclose(sum(values.values()), 1.0, abs_tol=0.02):
        return {}
    return values


def _selected(answer, entries: dict) -> tuple[str, float | None]:
    if not isinstance(answer, dict) or answer.get("type") != "choice":
        return entries["unknown"][0], None
    selected = answer.get("choice")
    if not isinstance(selected, str) or selected not in entries:
        return entries["unknown"][0], None
    distribution = _distribution(answer, entries)
    return entries[selected][0], distribution.get(selected)


def _empty(reason: str) -> dict:
    return {"analysis_only": True, "available": False, "candidates": [], "answers": {},
            "usage": {}, "quote": "", "question_title": "暂时没有可分析的对方消息",
            "options": [], "intent": "暂无法判断", "impact": reason, "risk_score": None,
            "action": "选择包含对方文字消息的会话后再分析", "model": None,
            "judgment_note": "模型判断，仅供参考"}


def analyze_insights(messages, relationship, timeout=30, context=10, reply_to=None,
                     jev_provider="typesafe", jev_model=None) -> dict:
    """Return one bounded insight card; missing/invalid fields never become invented probabilities."""
    if not messages:
        return _empty("还没有可用的聊天上下文")
    if isinstance(context, bool) or not isinstance(context, int) or context < 1:
        raise ValueError("context must be a positive integer")
    cleaned = []
    for item in messages:
        if isinstance(item, dict):
            who, text, name = item.get("from"), item.get("text"), item.get("name")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            who, text = item[:2]
            name = item[2] if len(item) >= 3 else None
        else:
            raise ValueError("Invalid message format")
        if who not in ("her", "me") or not isinstance(text, str):
            raise ValueError("Messages require her/me sender and text")
        if not text.strip():
            continue
        message = {"from": who, "text": text.strip()[:1200]}
        if isinstance(name, str) and name.strip():
            message["name"] = name.strip()[:80]
        cleaned.append(message)
    indices = [i for i, message in enumerate(cleaned)
               if message["from"] == "her" and (not reply_to or message.get("name") == reply_to)]
    if not indices:
        return _empty("未找到指定对象的文字消息" if reply_to else "可见上下文只有自己的消息")
    target_index = indices[-1]
    target = cleaned[target_index]
    recent = cleaned[max(0, target_index - min(context, 25) + 1):target_index + 1]
    state = build_state(recent, relationship or "通用沟通，关系未指定", keep=len(recent), reply_to=reply_to)
    state["analysis_target"] = dict(target)
    title, interpretations = _template(target["text"])
    questions = {
        "interpretation": _choice("Which possible interpretation best fits the target message?", interpretations),
        "intent": _choice("Which observable communication purpose best fits the target message?", _INTENTS),
        "impact": _choice("What is the main supported implication for the recipient's next decision?", _IMPACTS),
        "action": _choice("Which single practical next step should the human consider, without acting automatically?", _ACTIONS),
        "risk": {"type": "score", "instructions": _COMMON + (
            "Rate the current communication situation against the described levels of misunderstanding, "
            "unintended commitment, or escalating disagreement. A deadline or a brief message alone is not danger. "
            "Use the current resolved situation rather than treating past conflict as still active."),
            "criteria": _RISK_LEVELS},
    }
    response = ask(state, questions, timeout=timeout, provider=jev_provider, model=jev_model)
    response = response if isinstance(response, dict) else {}
    answers = response.get("answers")
    answers = answers if isinstance(answers, dict) else {}
    probabilities = _distribution(answers.get("interpretation"), interpretations)
    options = [{"label": interpretations[key][0], "probability": value}
               for key, value in sorted(probabilities.items(), key=lambda pair: pair[1], reverse=True)[:3]]
    intent, intent_probability = _selected(answers.get("intent"), _INTENTS)
    impact, impact_probability = _selected(answers.get("impact"), _IMPACTS)
    action, action_probability = _selected(answers.get("action"), _ACTIONS)
    risk = answers.get("risk")
    raw_score = _number(risk.get("score"), 0, 9) if isinstance(risk, dict) and risk.get("type") == "score" else None
    return {
        "analysis_only": True, "available": bool(options or any(value is not None for value in (
            intent_probability, impact_probability, action_probability, raw_score))),
        "candidates": [], "answers": answers,
        "usage": response.get("usage") if isinstance(response.get("usage"), dict) else {},
        "message_id": hashlib.sha256(json.dumps(state, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
        "quote": target["text"][:180] + ("…" if len(target["text"]) > 180 else ""),
        "question_title": title, "options": options,
        "intent": intent, "intent_probability": intent_probability,
        "impact": impact, "impact_probability": impact_probability,
        "risk_score": round(raw_score * 10 / 9, 1) if raw_score is not None else None,
        "risk_scale": "0–10 沟通风险程度；不是风险发生概率",
        "action": action, "action_probability": action_probability,
        "model": response.get("model") if isinstance(response.get("model"), str) else None,
        "judgment_note": "可能的解读与建议；概率是模型判断",
    }
