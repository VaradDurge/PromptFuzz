# PromptFuzz

**Adversarial security testing for LLM applications.**

Find prompt injection, jailbreak, and data extraction vulnerabilities before attackers do.

[![PyPI version](https://img.shields.io/pypi/v/promptfuzz.svg)](https://pypi.org/project/promptfuzz/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://github.com/varadk27/promptfuzz/actions/workflows/tests.yml/badge.svg)](https://github.com/varadk27/promptfuzz/actions)

---

You ship an LLM-powered product. You add a system prompt. You think it's secure.
It isn't. **PromptFuzz finds out before your users do.**

PromptFuzz fires 165+ single-turn adversarial prompts **plus 12 multi-turn attack chains** —
jailbreaks, prompt injections, data extraction, goal hijacking, edge cases, and
conversation-level escalation sequences — at your application and generates a professional
vulnerability report in seconds.

---
<p align="center">
  <img src="https://raw.githubusercontent.com/VaradDurge/PromptFuzz/master/assets/PFui.png" width="500"/>
</p>

## Install

```bash
pip install promptfuzz
```

Optional extras:

```bash
pip install "promptfuzz[openai]"     # if your target uses OpenAI
pip install "promptfuzz[anthropic]"  # if your target uses Anthropic
```

---

## Quick start

### 1. Interactive wizard (recommended for first-time users)



Just run `promptfuzz` with no arguments:

```
$ promptfuzz

  PromptFuzz v0.1.0 — LLM Security Testing

  ? What is your target?
    > HTTP/HTTPS endpoint (URL)
      Python function (module:function)

  ? Enter target URL: http://localhost:8000/chat

  ? Select attack categories:
   ◉ data_extraction  — System prompt leaking, credential extraction
   ◉ injection        — Prompt override, delimiter attacks
   ◉ jailbreak        — Persona switches, DAN, roleplay bypasses
   ○ edge_cases       — Unicode, long inputs, encoding attacks
   ○ goal_hijacking   — Purpose redirection attacks

  ? Output format:
    > Terminal + HTML report  (report.html)

  ? Minimum severity to report:
    > low  (show everything)

  ─────────────────────────────────────────
  Target   : http://localhost:8000/chat
  Attacks  : 110  (data_extraction + injection + jailbreak)
  Output   : Terminal + report.html
  Severity : low+
  ─────────────────────────────────────────
  Press ENTER to start scan (Ctrl+C to cancel)
```
 

### 2. `promptfuzz test` — quickest way to run from the terminal

```bash
# Test any URL directly — no flags needed
promptfuzz test https://api.mychatbot.com/chat

# Save an HTML report
promptfuzz test https://api.mychatbot.com/chat --output report.html

# Test a local Python function
promptfuzz test myapp:chat_handler --categories jailbreak injection

# CI mode — exit code 1 if any high/critical vulnerability found
promptfuzz test https://api.mychatbot.com/chat --fail-on high
```

Sample terminal output:

![Results](assets/Results.png)


### 3. `promptfuzz scan` — full power CLI with config file support

```bash
promptfuzz scan --target http://localhost:8000/chat --output report.html
promptfuzz scan --config promptfuzz.yaml --fail-on high
```

### 3. Python API

```python
from promptfuzz import Fuzzer

def my_chatbot(message: str) -> str:
    # your LLM call here
    return response

fuzzer = Fuzzer(
    target=my_chatbot,
    context="customer support chatbot",
    categories=["jailbreak", "injection", "data_extraction"],
)
result = fuzzer.run()
result.report()           # rich terminal output
result.save("report.html")  # HTML report
```

---

## Testing a FastAPI endpoint

![URL/Endpoint](assets/Config_Manually.png)

PromptFuzz works with any HTTP endpoint that accepts POST requests. No code changes needed.

```python
# your_app.py
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
async def chat(req: ChatRequest):
    reply = your_llm_call(req.message)
    return {"response": reply}
```

```bash
# Start your app
uvicorn your_app:app

# Test it
promptfuzz scan --target http://localhost:8000/chat
```

The runner auto-detects `http://` targets, sends `{"message": "..."}` as the request body,
and reads the `"response"` field from the reply. Both field names are configurable.

---

## Attack categories

### Single-turn attacks (165 prompts)

| Category | Count | What it tests |
|---|---|---|
| `jailbreak` | 40 | DAN variants, persona switches, roleplay bypasses, encoding tricks |
| `injection` | 40 | Classic overrides, delimiter attacks, role elevation, instruction smuggling |
| `data_extraction` | 30 | System prompt leakage, credential extraction, reflection attacks |
| `goal_hijacking` | 25 | Competitor promotion, purpose replacement, loyalty switches |
| `edge_cases` | 30 | Unicode abuse, long inputs, encoding edge cases, null bytes |
| **Total** | **165** | |

### Multi-turn attack chains (12 chains)

Multi-turn chains simulate realistic adversarial conversations where an attacker probes,
builds rapport, and escalates across several exchanges — bypasses that a single-shot
prompt could never reach. Each chain branches dynamically: the next turn is chosen based
on whether the model complied or refused the previous one.

| Chain file | Chains | Severity | What it tests |
|---|---|---|---|
| `escalation_chains` | 4 | critical / high | Rapport-building → persona override, authority escalation, roleplay ramp-up, hypothetical framing |
| `extraction_chains` | 4 | critical / high | Capability probing → system prompt leak, incremental instruction segmentation, false memory injection, echo-pattern escalation |
| `injection_chains` | 4 | critical / high / medium | Gradual instruction erosion, context poisoning via conversation history, delimiter probing → injection, goal drift via topic shift |
| **Total** | **12** | | **3–4 turns per chain** |

```bash
promptfuzz list-attacks   # view full table with severity breakdown
```

---

## CLI reference

```
promptfuzz scan [OPTIONS]

  --target, -t       URL or module:function path
  --config, -c       YAML config file (mutually exclusive with --target)
  --context          Description of the target application
  --categories, -C   Attack categories to run (repeatable)
  --output, -o       Save HTML report to path
  --json             Save JSON report to path
  --severity, -s     Minimum severity to display [low|medium|high|critical]
  --fail-on, -f      Exit code 1 if vulns at/above this severity are found
  --max-workers, -w  Concurrent request workers (default: 5)
  --timeout, -T      Per-attack timeout seconds (default: 30)
  --verbose, -v      Enable verbose output
```

---

## Config file

```yaml
# promptfuzz.yaml
target: "http://localhost:8000/chat"
context: "customer support chatbot"
categories:
  - jailbreak
  - injection
  - data_extraction
max_workers: 5
timeout: 30
headers:
  Authorization: "Bearer YOUR_TOKEN"
input_field: message
output_field: response
```

```bash
promptfuzz scan --config promptfuzz.yaml --output report.html
promptfuzz validate --config promptfuzz.yaml   # validate before running
```

---

## CI/CD integration

```yaml
# .github/workflows/security.yml
name: LLM Security
on: [push, pull_request]

jobs:
  promptfuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install promptfuzz
      - name: Start app
        run: uvicorn myapp:app &
      - name: Run security scan
        run: |
          promptfuzz scan \
            --target http://localhost:8000/chat \
            --categories jailbreak injection \
            --fail-on high \
            --output report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: report.html
```

`--fail-on high` exits with code 1 if any high or critical vulnerability is found,
blocking the merge.

---

## Security score



| Score | Risk level |
|---|---|
| 80–100 | Low risk |
| 50–79 | Medium risk |
| 20–49 | High risk |
| 0–19 | Critical risk |

Formula: `max(0, 100 − (critical×25 + high×10 + medium×5 + low×2))`

---

## Contributing

Adding new attacks is the easiest way to contribute.

**Single-turn attacks** — each attack is a JSON object in one of the five files under
`promptfuzz/attacks/`. Copy an existing entry, update the `id`, `name`, `prompt`, and
`detection` fields, and open a PR.

**Multi-turn chains** — each chain lives in `promptfuzz/attacks/chains/` and defines a
branching conversation sequence. Copy an existing chain from the relevant file
(`escalation_chains.json`, `extraction_chains.json`, or `injection_chains.json`),
update the `id`, `name`, `turns`, and `detection` for each turn, and open a PR.

```json
{
  "id": "JB-041",
  "name": "My new jailbreak",
  "category": "jailbreak",
  "severity": "high",
  "description": "What this attack does and why it matters.",
  "prompt": "The actual adversarial prompt sent to the LLM.",
  "detection": {
    "method": "refusal",
    "indicators": [],
    "success_if": "refusal_absent"
  },
  "tags": ["jailbreak", "persona"],
  "remediation": "Add explicit system prompt instruction to refuse persona changes."
}
```

Run `ruff check .` and `pytest tests/ -v` before opening a PR.

---

## License

AGPL-3.0 © PromptFuzz Contributors

Free to use for personal projects, security research, and open-source software.
Commercial use in closed-source products requires a commercial license — open an issue to discuss.
