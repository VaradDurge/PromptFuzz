"""Chain loader — reads, validates, and provides access to multi-turn
attack chain JSON files."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from promptfuzz.attacks.chain_models import AttackChain, ChainTurn
from promptfuzz.attacks.loader import (
    VALID_CATEGORIES,
    VALID_DETECTION_METHODS,
    VALID_SEVERITIES,
    VALID_SUCCESS_IF,
    DetectionConfig,
)

CHAINS_DIR = Path(__file__).parent / "chains"
MAX_TURNS = 6
MIN_TURNS = 2

_console = Console(stderr=True)


class ChainLoader:
    """Loads and validates multi-turn attack chain JSON files.

    Chain files are discovered by globbing ``attacks/chains/*.json``.
    Unlike the single-shot AttackLoader, which uses a fixed filename
    dict, ChainLoader uses glob discovery so contributors can drop new
    chain files without registering them anywhere.
    """

    def load_all(self) -> list[AttackChain]:
        """Load all chain files from the chains/ directory.

        Returns:
            List of validated AttackChain objects across all files.
        """
        if not CHAINS_DIR.exists():
            return []
        chains: list[AttackChain] = []
        for path in sorted(CHAINS_DIR.glob("*.json")):
            chains.extend(self._load_file(path))
        return chains

    def load_categories(
        self, categories: list[str]
    ) -> list[AttackChain]:
        """Load chains whose category matches any of the given values.

        Args:
            categories: Category strings to include.

        Returns:
            Filtered list of AttackChain objects.
        """
        return [
            c for c in self.load_all() if c.category in categories
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_file(self, path: Path) -> list[AttackChain]:
        """Parse one JSON file into AttackChain objects."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] Cannot read {path}: {exc}"
            )
            return []

        try:
            data: list[dict] = json.loads(raw)
        except json.JSONDecodeError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] Invalid JSON in "
                f"{path.name}: {exc}"
            )
            return []

        chains: list[AttackChain] = []
        for entry in data:
            try:
                chains.append(self._validate_chain(entry))
            except (KeyError, ValueError, TypeError) as exc:
                chain_id = entry.get("id", "<unknown>")
                _console.print(
                    f"[bold yellow]Warning:[/bold yellow] Skipping invalid "
                    f"chain {chain_id} in {path.name}: {exc}"
                )
        return chains

    def _validate_chain(self, data: dict) -> AttackChain:
        """Validate a raw dict against the chain schema.

        Checks performed:
        1. All required top-level fields are present.
        2. category and severity use the canonical values.
        3. Turn count is within [MIN_TURNS, MAX_TURNS].
        4. Each turn has a valid DetectionConfig (reuses constants
           from loader.py).
        5. on_comply / on_refuse reference valid turn_ids or "end".
        6. Every turn is reachable from the first turn (BFS check).

        Args:
            data: Raw dict parsed from JSON.

        Returns:
            Validated AttackChain instance.

        Raises:
            KeyError: Missing required field.
            ValueError: Invalid field value or unreachable turn.
            TypeError: Wrong field type.
        """
        required = {
            "id", "name", "category", "severity",
            "description", "turns", "tags", "remediation",
        }
        missing = required - data.keys()
        if missing:
            raise KeyError(f"Missing required fields: {missing}")

        if data["category"] not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{data['category']}'. "
                f"Must be one of {sorted(VALID_CATEGORIES)}"
            )
        if data["severity"] not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{data['severity']}'. "
                f"Must be one of {sorted(VALID_SEVERITIES)}"
            )
        if not isinstance(data["turns"], list):
            raise TypeError("'turns' must be a list")

        n = len(data["turns"])
        if n < MIN_TURNS:
            raise ValueError(
                f"Chain needs >= {MIN_TURNS} turns, got {n}"
            )
        if n > MAX_TURNS:
            raise ValueError(
                f"Chain must have <= {MAX_TURNS} turns, got {n}"
            )

        # Parse and deduplicate turn_ids
        turns: list[ChainTurn] = []
        seen_ids: set[str] = set()
        for raw_turn in data["turns"]:
            turn = self._validate_turn(raw_turn)
            if turn.turn_id in seen_ids:
                raise ValueError(
                    f"Duplicate turn_id '{turn.turn_id}'"
                )
            seen_ids.add(turn.turn_id)
            turns.append(turn)

        # Validate all on_comply / on_refuse references
        valid_refs = seen_ids | {"end"}
        for t in turns:
            if t.on_comply not in valid_refs:
                raise ValueError(
                    f"Turn '{t.turn_id}' on_comply references "
                    f"unknown id '{t.on_comply}'"
                )
            if t.on_refuse not in valid_refs:
                raise ValueError(
                    f"Turn '{t.turn_id}' on_refuse references "
                    f"unknown id '{t.on_refuse}'"
                )

        # BFS reachability check from the entry point (first turn)
        turn_map = {t.turn_id: t for t in turns}
        reachable: set[str] = set()
        queue = [turns[0].turn_id]
        while queue:
            tid = queue.pop(0)
            if tid in reachable or tid == "end":
                continue
            reachable.add(tid)
            t = turn_map[tid]
            queue.append(t.on_comply)
            queue.append(t.on_refuse)

        unreachable = seen_ids - reachable
        if unreachable:
            raise ValueError(
                f"Unreachable turns: {unreachable}. "
                "All turns must be reachable from the first turn."
            )

        if not isinstance(data["tags"], list):
            raise TypeError("'tags' must be a list")

        return AttackChain(
            id=str(data["id"]),
            name=str(data["name"]),
            category=data["category"],
            severity=data["severity"],
            description=str(data["description"]),
            turns=tuple(turns),
            tags=tuple(str(t) for t in data["tags"]),
            remediation=str(data["remediation"]),
        )

    def _validate_turn(self, data: dict) -> ChainTurn:
        """Validate a single turn dict.

        Args:
            data: Raw turn dict from JSON.

        Returns:
            Validated ChainTurn instance.

        Raises:
            KeyError: Missing required field.
            ValueError: Invalid detection config.
            TypeError: Wrong field type.
        """
        required = {
            "turn_id", "prompt", "detection",
            "on_comply", "on_refuse",
        }
        missing = required - data.keys()
        if missing:
            raise KeyError(f"Turn missing fields: {missing}")

        det = data["detection"]
        if not isinstance(det, dict):
            raise TypeError("'detection' must be a dict")

        method = det.get("method", "")
        if method not in VALID_DETECTION_METHODS:
            raise ValueError(
                f"Invalid detection method '{method}'. "
                f"Must be one of {sorted(VALID_DETECTION_METHODS)}"
            )

        success_if = det.get("success_if", "")
        if success_if not in VALID_SUCCESS_IF:
            raise ValueError(
                f"Invalid success_if '{success_if}'. "
                f"Must be one of {sorted(VALID_SUCCESS_IF)}"
            )

        if not isinstance(det.get("indicators", []), list):
            raise TypeError("'detection.indicators' must be a list")

        detection = DetectionConfig(
            method=method,
            indicators=det.get("indicators", []),
            success_if=success_if,
        )

        return ChainTurn(
            turn_id=str(data["turn_id"]),
            prompt=str(data["prompt"]),
            detection=detection,
            on_comply=str(data["on_comply"]),
            on_refuse=str(data["on_refuse"]),
        )
