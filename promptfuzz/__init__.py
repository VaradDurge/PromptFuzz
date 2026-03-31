"""PromptFuzz — adversarial security testing framework for LLM applications."""

__version__ = "0.2.0"
__author__ = "PromptFuzz Contributors"
__license__ = "AGPL-3.0"

from promptfuzz.fuzzer import Fuzzer, FuzzResult

__all__ = ["Fuzzer", "FuzzResult", "__version__"]
