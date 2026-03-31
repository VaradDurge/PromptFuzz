"""Main fuzzer orchestrator — coordinates attack loading, running, and analysis."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import yaml
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from promptfuzz.analyzer import AnalysisResult, Analyzer, Vulnerability
from promptfuzz.attacks.chain_models import ChainResult
from promptfuzz.attacks.loader import Attack, AttackLoader
from promptfuzz.runner import AttackResult, Runner

_console = Console()

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 5,
    "low": 2,
}


@dataclass
class FuzzResult:
    """Aggregated result from one complete fuzzing run."""

    target_description: str
    context: str
    attacks_run: int
    vulnerabilities: list[Vulnerability]
    passed: list[AnalysisResult]
    errors: list[AttackResult]
    score: int
    duration_seconds: float
    timestamp: str
    # Multi-turn chain results — default [] for full backward compatibility.
    # dataclasses.asdict() serialises these automatically into JSON output.
    chain_results: list[ChainResult] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Ensure chain_results is never None after construction."""
        if self.chain_results is None:
            self.chain_results = []

    def report(self) -> None:
        """Print a human-readable result summary to the terminal."""
        from promptfuzz.reporter import Reporter

        Reporter().print_results(self)

    def save(self, path: str) -> None:
        """Save an HTML vulnerability report to disk.

        Args:
            path: File path for the HTML report.
        """
        from promptfuzz.reporter import Reporter

        Reporter().save_html(self, path)

    def to_json(self, path: str) -> None:
        """Save results as a JSON file.

        Args:
            path: File path for the JSON output.
        """
        from promptfuzz.reporter import Reporter

        Reporter().save_json(self, path)

    def to_txt(self, path: str) -> None:
        """Save results as a plain-text report.

        Args:
            path: File path for the TXT output.
        """
        from promptfuzz.reporter import Reporter

        Reporter().save_txt(self, path)


class Fuzzer:
    """Orchestrates attack loading, execution, and result analysis."""

    def __init__(
        self,
        target: str | Callable,
        context: str = "LLM application",
        categories: list[str] | None = None,
        max_workers: int = 5,
        timeout: float = 30.0,
        verbose: bool = False,
        headers: dict[str, str] | None = None,
        input_field: str = "message",
        output_field: str = "response",
        extra_fields: dict[str, str] | None = None,
        system_prompt: str | None = None,
        judge_model: str = "gpt-4o-mini",
        run_chains: bool = False,
        run_attacks: bool = True,
    ) -> None:
        """Initialise the Fuzzer.

        Args:
            target: URL string or Python callable to test.
            context: Human-readable description of the target application.
            categories: Attack categories to run. Defaults to all categories.
            max_workers: Number of concurrent attack workers.
            timeout: Per-attack timeout in seconds.
            verbose: Enable verbose output.
            headers: Extra HTTP headers for URL-mode requests.
            input_field: JSON key containing the prompt for HTTP mode.
            output_field: JSON key containing the response for HTTP mode.
            extra_fields: Extra fixed key-value pairs merged into every request payload.
            system_prompt: System prompt of the target app — enables LLM-as-judge mode.
            judge_model: OpenAI model used as judge (default: gpt-4o-mini).
            run_chains: When True, also execute multi-turn attack chains
                after single-shot attacks. Default False.
            run_attacks: When False, skip single-shot attacks entirely and
                only run chains. Useful for chain-only mode. Default True.
        """
        self.target = target
        self.context = context
        self.categories = categories
        self.max_workers = max_workers
        self.timeout = timeout
        self.verbose = verbose
        self.headers = headers or {}
        self.input_field = input_field
        self.output_field = output_field
        self.extra_fields = extra_fields or {}
        self.system_prompt = system_prompt
        self.judge_model = judge_model
        self.run_chains = run_chains
        self.run_attacks = run_attacks

    @classmethod
    def from_config(cls, path: str) -> "Fuzzer":
        """Create a Fuzzer from a YAML configuration file.

        Expected YAML schema::

            target: "https://api.example.com/chat"
            context: "customer support bot"
            categories: [jailbreak, injection]
            max_workers: 5
            timeout: 30
            headers:
              Authorization: "Bearer xxx"
            input_field: message
            output_field: response

        Args:
            path: Path to the YAML config file.

        Returns:
            Configured Fuzzer instance.

        Raises:
            FileNotFoundError: If the config file does not exist.
            yaml.YAMLError: If the YAML cannot be parsed.
            ValueError: If required fields are missing from the config.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        raw = config_path.read_text(encoding="utf-8")
        cfg: dict = yaml.safe_load(raw) or {}

        target = cfg.get("target")
        if not target:
            raise ValueError("Config must include a 'target' field.")

        return cls(
            target=target,
            context=cfg.get("context", "LLM application"),
            categories=cfg.get("categories"),
            max_workers=cfg.get("max_workers", 5),
            timeout=cfg.get("timeout", 30.0),
            verbose=cfg.get("verbose", False),
            headers=cfg.get("headers") or {},
            input_field=cfg.get("input_field", "message"),
            output_field=cfg.get("output_field", "response"),
            extra_fields=cfg.get("extra_fields") or {},
            run_chains=cfg.get("run_chains", False),
        )

    def run(self) -> FuzzResult:
        """Synchronous wrapper around :meth:`arun`.

        Returns:
            FuzzResult with all vulnerability findings.
        """
        return asyncio.run(self.arun())

    async def arun(self) -> FuzzResult:
        """Run the full fuzzing pipeline asynchronously.

        Steps:
            1. Load attacks via AttackLoader.
            2. Fire attacks via Runner with a Rich progress bar.
            3. Analyse each response via Analyzer.
            4. Compute security score.
            5. Return FuzzResult.

        Returns:
            FuzzResult with all findings.
        """
        start = datetime.now(timezone.utc)

        # Build the analyzer once — shared by both single-shot and chain phases
        if self.system_prompt:
            from promptfuzz.analyzer import JudgeAnalyzer  # noqa: PLC0415
            analyzer: Analyzer = JudgeAnalyzer(self.system_prompt, self.judge_model)
        else:
            analyzer = Analyzer()

        vulnerabilities: list[Vulnerability] = []
        passed: list[AnalysisResult] = []
        errors: list[AttackResult] = []
        attacks_run = 0

        if self.run_attacks:
            # 1. Load attacks
            loader = AttackLoader()
            if self.categories:
                attacks = loader.load_categories(self.categories)
            else:
                attacks = loader.load_all()

            if not attacks and not self.run_chains:
                _console.print(
                    "[bold red]Error:[/bold red] No attacks loaded. "
                    "Check attack files."
                )
                return FuzzResult(
                    target_description=str(self.target),
                    context=self.context,
                    attacks_run=0,
                    vulnerabilities=[],
                    passed=[],
                    errors=[],
                    score=100,
                    duration_seconds=0.0,
                    timestamp=start.isoformat(),
                )

            attacks_run = len(attacks)

            # 2. Fire attacks
            runner = Runner(
                target=self.target,
                headers=self.headers,
                input_field=self.input_field,
                output_field=self.output_field,
                extra_fields=self.extra_fields,
                max_workers=self.max_workers,
                timeout=self.timeout,
                verbose=self.verbose,
            )

            attack_results: list[AttackResult] = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=_console,
                transient=True,
            ) as progress:
                attack_results = await runner.arun(attacks, progress)

            # 3. Analyse responses
            for ar in attack_results:
                if ar.status != "success" or ar.response is None:
                    errors.append(ar)
                    continue

                analysis = analyzer.analyze(ar.attack, ar.response)
                if analysis.is_vulnerable:
                    vulnerabilities.append(
                        Vulnerability(attack=ar.attack, result=analysis)
                    )
                else:
                    passed.append(analysis)

        # 4. Run multi-turn chains (optional)
        chain_results: list[ChainResult] = []
        if self.run_chains:
            from promptfuzz.attacks.chain_loader import ChainLoader  # noqa: PLC0415
            from promptfuzz.chain_runner import ChainRunner  # noqa: PLC0415

            chain_loader = ChainLoader()
            chains = (
                chain_loader.load_categories(self.categories)
                if self.categories
                else chain_loader.load_all()
            )

            if chains:
                chain_runner = ChainRunner(
                    target=self.target,
                    analyzer=analyzer,
                    headers=self.headers,
                    input_field=self.input_field,
                    output_field=self.output_field,
                    extra_fields=self.extra_fields,
                    # Use half of max_workers: each chain makes 2-6
                    # sequential requests, so effective concurrency is
                    # already higher per slot than single-shot attacks.
                    max_workers=max(1, self.max_workers // 2),
                    timeout=self.timeout,
                )
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=_console,
                    transient=True,
                ) as chain_progress:
                    chain_results = await chain_runner.arun(
                        chains, chain_progress
                    )

                # Promote chain vulnerabilities into the main vulnerabilities
                # list so that scoring, reporter, and CI/CD fail-on logic all
                # work without modification. The chain ID (e.g. "CH-JB-001")
                # distinguishes them from single-shot findings in reports.
                for cr in chain_results:
                    if not cr.is_vulnerable:
                        continue
                    # Use the last vulnerable turn as the representative result.
                    last_vuln = next(
                        (tr for tr in reversed(cr.turn_results) if tr.is_vulnerable),
                        None,
                    )
                    if last_vuln is None:
                        continue
                    synth_attack = Attack(
                        id=cr.chain.id,
                        name=cr.chain.name,
                        category=cr.chain.category,
                        severity=cr.chain.severity,
                        description=cr.chain.description,
                        prompt=last_vuln.rendered_prompt,
                        detection=last_vuln.turn.detection,
                        tags=list(cr.chain.tags),
                        remediation=cr.chain.remediation,
                    )
                    from promptfuzz.analyzer import DetectionStrategy  # noqa: PLC0415
                    synth_analysis = AnalysisResult(
                        attack=synth_attack,
                        response=last_vuln.response or "",
                        is_vulnerable=True,
                        confidence=last_vuln.confidence,
                        evidence=(
                            f"[Chain: {len(cr.turn_results)} turns] "
                            f"{last_vuln.evidence}"
                        ),
                        strategy_used=DetectionStrategy.KEYWORD,
                        elapsed_ms=cr.total_elapsed_ms,
                    )
                    vulnerabilities.append(
                        Vulnerability(attack=synth_attack, result=synth_analysis)
                    )

        # 5. Compute score
        score = self._compute_score(vulnerabilities)

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        if callable(self.target):
            mod = getattr(self.target, "__module__", None) or ""
            name = getattr(self.target, "__qualname__", None) or str(self.target)
            target_desc = f"{mod}:{name}" if mod else name
        else:
            target_desc = str(self.target)

        return FuzzResult(
            target_description=target_desc,
            context=self.context,
            attacks_run=attacks_run,
            vulnerabilities=vulnerabilities,
            passed=passed,
            errors=errors,
            score=score,
            duration_seconds=duration,
            timestamp=start.isoformat(),
            chain_results=chain_results,
        )

    @staticmethod
    def _compute_score(vulnerabilities: list[Vulnerability]) -> int:
        """Compute a 0-100 security score. 100 means fully secure.

        Formula: ``max(0, 100 - sum(weight * count_per_severity))``

        Args:
            vulnerabilities: List of confirmed vulnerabilities.

        Returns:
            Integer score in [0, 100].
        """
        deduction = 0
        for vuln in vulnerabilities:
            deduction += SEVERITY_WEIGHTS.get(vuln.severity, 0)
        return max(0, 100 - deduction)
