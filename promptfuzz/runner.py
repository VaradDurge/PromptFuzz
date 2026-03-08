"""Attack runner — fires attacks concurrently against HTTP or callable targets."""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal

import httpx
from rich.progress import Progress

from promptfuzz.attacks.loader import Attack

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_WORKERS = 5
DEFAULT_INPUT_FIELD = "message"
DEFAULT_OUTPUT_FIELD = "response"


@dataclass
class AttackResult:
    """Outcome of firing a single attack at the target."""

    attack: Attack
    response: str | None
    error: str | None
    elapsed_ms: float
    status: Literal["success", "error", "timeout"]


class Runner:
    """Fires a list of attacks concurrently and collects raw responses."""

    def __init__(
        self,
        target: str | Callable,
        headers: dict[str, str] | None = None,
        input_field: str = DEFAULT_INPUT_FIELD,
        output_field: str = DEFAULT_OUTPUT_FIELD,
        extra_fields: dict[str, Any] | None = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
        timeout: float = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ) -> None:
        """Initialise the Runner.

        Args:
            target: A URL string or a Python callable.
            headers: Extra HTTP headers for URL-mode requests.
            input_field: JSON body key that holds the prompt text.
            output_field: JSON response key that holds the reply text.
            extra_fields: Extra fixed key-value pairs merged into every request payload.
            max_workers: Maximum concurrent in-flight requests.
            timeout: Per-request timeout in seconds.
            verbose: Whether to emit verbose progress messages.
        """
        self.target = target
        self.headers = headers or {}
        self.input_field = input_field
        self.output_field = output_field
        self.extra_fields = extra_fields or {}
        self.max_workers = max_workers
        self.timeout = timeout
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        attacks: list[Attack],
        progress: Progress | None = None,
    ) -> list[AttackResult]:
        """Synchronous wrapper around :meth:`arun`.

        Args:
            attacks: Attacks to fire.
            progress: Optional Rich Progress instance for live display.

        Returns:
            List of AttackResult objects in completion order.
        """
        return asyncio.run(self.arun(attacks, progress))

    async def arun(
        self,
        attacks: list[Attack],
        progress: Progress | None = None,
    ) -> list[AttackResult]:
        """Fire all attacks asynchronously with a semaphore-bounded worker pool.

        Args:
            attacks: Attacks to fire.
            progress: Optional Rich Progress instance for live display.

        Returns:
            List of AttackResult objects in completion order.
        """
        semaphore = asyncio.Semaphore(self.max_workers)
        task_id = None
        if progress is not None:
            task_id = progress.add_task(
                "[cyan]Firing attacks...", total=len(attacks)
            )

        async with httpx.AsyncClient(
            headers=self.headers,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._bounded_fire(attack, client, semaphore, progress, task_id)
                for attack in attacks
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _bounded_fire(
        self,
        attack: Attack,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        progress: Progress | None,
        task_id: Any,
    ) -> AttackResult:
        """Acquire semaphore slot then fire a single attack."""
        async with semaphore:
            result = await self._fire_one(attack, client)
            if progress is not None and task_id is not None:
                progress.advance(task_id)
            return result

    async def _fire_one(
        self,
        attack: Attack,
        client: httpx.AsyncClient,
    ) -> AttackResult:
        """Fire a single attack and return the raw result.

        Args:
            attack: The attack to fire.
            client: Shared async HTTP client.

        Returns:
            AttackResult with response text or error info.
        """
        start = time.monotonic()
        try:
            if callable(self.target):
                response_text = await self._call_function(attack)
            else:
                response_text = await self._call_http(attack, client)

            elapsed_ms = (time.monotonic() - start) * 1000
            return AttackResult(
                attack=attack,
                response=response_text,
                error=None,
                elapsed_ms=elapsed_ms,
                status="success",
            )

        except (httpx.TimeoutException, asyncio.TimeoutError):
            elapsed_ms = (time.monotonic() - start) * 1000
            return AttackResult(
                attack=attack,
                response=None,
                error="Request timed out",
                elapsed_ms=elapsed_ms,
                status="timeout",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.monotonic() - start) * 1000
            return AttackResult(
                attack=attack,
                response=None,
                error=str(exc),
                elapsed_ms=elapsed_ms,
                status="error",
            )

    async def _call_function(self, attack: Attack) -> str:
        """Invoke a callable target with the attack prompt.

        Supports both synchronous and asynchronous callables.

        Args:
            attack: The attack whose prompt will be passed to the function.

        Returns:
            String response from the callable.
        """
        fn: Callable = self.target  # type: ignore[assignment]
        if inspect.iscoroutinefunction(fn):
            result = await fn(attack.prompt)
        else:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, fn, attack.prompt)
        return str(result)

    async def _call_http(
        self,
        attack: Attack,
        client: httpx.AsyncClient,
    ) -> str:
        """POST the attack prompt to an HTTP endpoint.

        Args:
            attack: The attack whose prompt will be sent.
            client: Shared async HTTP client.

        Returns:
            Extracted response text from the JSON response body.

        Raises:
            httpx.HTTPStatusError: If the server returns a non-2xx status.
            KeyError: If the output_field is missing from the response JSON.
        """
        payload = {self.input_field: attack.prompt, **self.extra_fields}
        response = await client.post(str(self.target), json=payload)
        response.raise_for_status()

        try:
            data = response.json()
            return str(data.get(self.output_field, response.text))
        except Exception:  # noqa: BLE001
            return response.text
