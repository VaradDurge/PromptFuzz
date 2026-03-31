"""Data models for multi-turn attack chains."""

from __future__ import annotations

from dataclasses import dataclass

from promptfuzz.attacks.loader import DetectionConfig


@dataclass(frozen=True)
class ChainTurn:
    """A single turn within a multi-turn attack chain.

    Attributes:
        turn_id: Unique identifier within the chain (e.g. "t0", "t1_alt").
        prompt: Prompt template. May contain ``{prev_response}``, which is
            replaced at runtime with a truncated excerpt of the previous
            turn's model output.
        detection: Reuses the existing DetectionConfig dataclass from
            loader.py — zero duplication.
        on_comply: turn_id to follow when Analyzer flags the response as
            vulnerable (model complied), or ``"end"`` to stop the chain.
        on_refuse: turn_id to follow when Analyzer says not vulnerable
            (model refused/deflected), or ``"end"`` to stop the chain.
    """

    turn_id: str
    prompt: str
    detection: DetectionConfig
    on_comply: str
    on_refuse: str


@dataclass(frozen=True)
class AttackChain:
    """A complete multi-turn attack chain definition.

    Attributes:
        id: Unique chain identifier (e.g. "CH-JB-001").
        name: Human-readable name.
        category: One of the VALID_CATEGORIES from loader.py.
        severity: Worst-case severity if the full escalation path succeeds.
        description: What adversarial behaviour this chain tests.
        turns: Ordered sequence of ChainTurn objects. The first element
            is always the chain entry point. Stored as a tuple so that
            the frozen dataclass is truly immutable (a list field would
            still be mutable despite the frozen flag).
        tags: Classification tags. Tuple for the same reason as turns.
        remediation: How to fix the vulnerability if found.
    """

    id: str
    name: str
    category: str
    severity: str
    description: str
    turns: tuple[ChainTurn, ...]
    tags: tuple[str, ...]
    remediation: str


@dataclass
class TurnResult:
    """Result of executing one turn within a chain.

    Not frozen — built incrementally during async execution.

    Attributes:
        turn: The ChainTurn definition that was executed.
        rendered_prompt: Prompt after ``{prev_response}`` substitution.
        response: Raw model response text, or None on error/timeout.
        error: Error message if the turn failed, or None.
        is_vulnerable: Whether the Analyzer flagged this turn.
        confidence: Analyzer confidence score (0.0–1.0).
        evidence: Analyzer evidence string.
        elapsed_ms: Wall-clock time for this turn's HTTP call.
        branch_taken: Which path was followed after this turn:
            ``"comply"``, ``"refuse"``, ``"end"``, or ``"error"``.
    """

    turn: ChainTurn
    rendered_prompt: str
    response: str | None
    error: str | None
    is_vulnerable: bool
    confidence: float
    evidence: str
    elapsed_ms: float
    branch_taken: str


@dataclass
class ChainResult:
    """Aggregated result of executing one complete attack chain.

    Not frozen — accumulates TurnResults during execution.

    Attributes:
        chain: The AttackChain definition.
        turn_results: Ordered list of TurnResults for the path actually
            executed through the DAG (not all turns, only those visited).
        is_vulnerable: True if ANY turn in the executed path was flagged.
        final_severity: The chain's declared severity (set by the chain
            author based on the worst possible outcome; not recomputed
            per-turn).
        total_elapsed_ms: Sum of all turn elapsed times.
    """

    chain: AttackChain
    turn_results: list[TurnResult]
    is_vulnerable: bool
    final_severity: str
    total_elapsed_ms: float
