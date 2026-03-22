![image](https://github.com/user-attachments/assets/a7f71fa8-e06f-431c-886f-ccf2a3b39c7f)

# OmniFuzz-LLM

**Adversarial Testing and Red-Teaming Framework for LLMs**

OmniFuzz-LLM is a Python framework that helps security engineers and AI teams run structured adversarial tests against deployed LLM systems. It maps every finding to the OWASP LLM Top 10, generates compliance reports aligned to NIST AI RMF and MITRE ATLAS, and is built to be automated in CI/CD pipelines.

It is aimed at teams that need to demonstrate due diligence around LLM security — not just consumer jailbreaks, but the enterprise attack surfaces that matter: RAG poisoning, tool-call abuse, PII leakage, multi-tenant isolation failures, hallucination under adversarial conditions, and credential harvesting.

---

## What problem it solves

Most LLM security testing today is ad-hoc: a red-teamer types prompts into a chat interface and writes up notes. OmniFuzz-LLM replaces that with a repeatable, structured, and automatable workflow. You configure a target, choose which attack modules to run, pipe it through your real adapter (OpenAI, Anthropic, subprocess, or your own), and get a findings report with OWASP references, severity ratings, and a compliance summary.

The same scan config can run in CI on every model update so regressions are caught before they reach production.

---

## Features

### Attack modules

Each module targets a specific OWASP LLM Top 10 control and includes a battery of hand-crafted payloads.

| Module | OWASP | What it tests |
|--------|-------|---------------|
| `sysprompt_extractor` | LLM07 | 14 techniques to recover system prompts (verbatim repeat, translation tricks, authority injection, context bleed) |
| `tool_abuse` | LLM02 | SSRF via URL tools, SQL injection via DB tools, data exfiltration via email tools, path traversal, code execution abuse |
| `indirect_injection` | LLM01 | Hidden instructions in documents, emails, database records, EXIF metadata, Unicode obfuscation, RAG index poisoning |
| `pii_compliance` | LLM06 | PHI/HIPAA, financial PII, API keys, JWT tokens, contact data — with HIPAA, GDPR, and NIST AI RMF compliance report |
| `multitenant_tester` | LLM04 | Cross-session secret injection and probing to detect context bleed and RAG cross-tenant leakage |
| `hallucination_tester` | LLM09 | False premise injection, context contradictions, citation fabrication, confidence induction, RAG groundedness |
| `dos_tester` | LLM04 | Token amplification, recursive reasoning, context flooding, repetition bombs, chain-of-thought inflation |
| `consistency_tester` | LLM09 | Demographic bias detection (gender, race, age, nationality, religion), synonym variance, inconsistent refusals |
| `embedding_poisoning` | LLM01 | Semantic hijacking, citation poisoning, neighbour flooding, metadata injection, retrieval injection |
| `credential_harvesting` | LLM06 | AWS/GitHub/OpenAI/Stripe key extraction, JWT secret harvesting, social engineering, indirect/obfuscated extraction |
| `multimodal` | LLM01 | OCR-borne injection, EXIF metadata injection, document injection, audio transcription attacks, vision jailbreaks |

### Adapters

Connect OmniFuzz to any LLM endpoint without modifying the scan logic.

| Adapter | Description |
|---------|-------------|
| `OpenAIAdapter` | OpenAI `/v1/chat/completions` — any model |
| `AzureOpenAIAdapter` | Azure OpenAI with deployment name and API version |
| `AnthropicAdapter` | Anthropic Messages API with tool-use block detection |
| `SubprocessAdapter` | Local CLI tools and custom model wrappers via stdin/stdout |

All adapters share the same interface. Writing a custom adapter takes about 10 lines.

### Reporting

Every scan produces structured output with OWASP references, severity scores, and per-finding details.

| Format | Description |
|--------|-------------|
| JSON | Machine-readable findings list, suitable for CI assertions and downstream tooling |
| Markdown | Human-readable report with per-finding details and OWASP table |
| HTML | Self-contained dark-theme report with severity cards and collapsible findings |

The `ComplianceReporter` takes scan results and produces an OWASP LLM Top 10 compliance report with NIST AI RMF and MITRE ATLAS cross-references — ready for auditors, security reviews, or internal governance boards.

### Infrastructure

| Feature | Description |
|---------|-------------|
| Checkpoints | Atomic save/resume for long scans — crash-safe using temp file + `os.replace()` |
| Regression testing | Diff two scan snapshots (before/after a model update) and surface new vulnerabilities |
| Proxy mode | Passive HTTP interceptor that evaluates live traffic for adversarial indicators without blocking |
| Plugin architecture | Register custom mutators via decorator, entry points, or module path — built-ins auto-registered on import |
| Payload library | JSON payload library with OWASP refs, severity, technique tags, and model targeting; schema-validated on load |
| Config files | YAML or TOML config with deep-merge so partial overrides don't wipe defaults |

### Mutators

Mutators transform payloads to evade keyword filters and safety classifiers.

| Mutator | Technique |
|---------|-----------|
| `base64` | Encodes payload and instructs model to decode and execute |
| `flip` | Reverses payload text |
| `leetspeak` | Substitutes a→4, e→3, i→1, o→0, s→5, t→7 |
| `shadow` | Combines leetspeak + zero-width space insertion |
| `poetic` | Encodes payload as a villanelle or sestina |
| `cross_lingual` | Chains instructions across English, German, and Japanese |

---

## Architecture

```
OmniFuzz-LLM/
├── omnifuzz/
│   ├── engine.py               # Core: OmniFuzzer, FuzzResult, Reporter, OWASP_MAP
│   ├── checkpoint.py           # Atomic save/resume: CheckpointManager
│   ├── config.py               # YAML/TOML loader with deep-merge
│   ├── payload_manager.py      # Schema validation, filtering, library management
│   ├── compliance.py           # OWASP LLM Top 10 compliance report generator
│   ├── regression.py           # Differential scan: diff_snapshots, RegressionRunner
│   ├── proxy.py                # Passive monitoring proxy: OmniFuzzProxy
│   ├── plugin.py               # Mutator plugin registry with entry-point discovery
│   ├── mutators.py             # Built-in mutators (base64, flip, leetspeak)
│   ├── cross_lingual_mutators.py  # CrossLingualMutator
│   ├── adapters/
│   │   ├── openai_adapter.py      # OpenAI + Azure OpenAI
│   │   ├── anthropic_adapter.py   # Anthropic
│   │   └── subprocess_adapter.py  # Local CLI / subprocess
│   ├── modules/
│   │   ├── sysprompt_extractor.py
│   │   ├── tool_abuse.py
│   │   ├── indirect_injection.py
│   │   ├── pii_compliance.py
│   │   ├── multitenant_tester.py
│   │   ├── hallucination_tester.py
│   │   ├── dos_tester.py
│   │   ├── consistency_tester.py
│   │   ├── embedding_poisoning.py
│   │   ├── credential_harvesting.py
│   │   └── multimodal.py
│   ├── payloads/
│   │   └── library.json        # Payload library with full schema
│   └── utils/
│       └── logger.py           # ColorFormatter, JSON output, quiet/verbose modes
├── tests/                      # 275 tests, all passing, no real LLM needed
│   ├── test_engine.py
│   ├── test_checkpoint.py
│   ├── test_mutators.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   └── test_phase4.py
├── cli.py                      # CLI entry point with subcommand architecture
├── main.py                     # Programmatic example
└── .github/workflows/ci.yml    # GitHub Actions CI
```

**Data flow:**

```
Config / CLI args
      ↓
  OmniFuzzer.run_scan(payloads, adapter, evaluator)
      ↓
  Payload → Mutator(optional) → Adapter.send() → Response
      ↓
  Evaluator.evaluate(payload, response) → (is_vulnerable, details)
      ↓
  FuzzResult(owasp_ref, severity, payload_index, ...)
      ↓
  Reporter → JSON / Markdown / HTML
      ↓
  ComplianceReporter → OWASP LLM Top 10 report
```

---

## Requirements

- Python 3.11 or later
- `httpx` for adapter HTTP calls
- Optional: `pyyaml` for YAML config files, `tomllib` (stdlib in 3.11+) for TOML

No external services required to run the test suite. All 275 tests use mock adapters.

---

## Quick start

**1. Clone the repository**

```bash
git clone https://github.com/bogdanticu88/OmniFuzz-LLM
cd OmniFuzz-LLM
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Run the test suite**

```bash
python -m pytest tests/ -v
```

All 275 tests should pass with no external dependencies.

**4. Run a scan from the CLI**

```bash
# Scan with the built-in payload library against an OpenAI endpoint
python cli.py scan \
  --adapter openai \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o-mini \
  --categories jailbreak sensitive_info \
  --output-json results.json \
  --output-html report.html

# Resume an interrupted scan
python cli.py scan --resume --checkpoint-id <scan-id>

# List saved checkpoints
python cli.py checkpoints list

# Add a payload to the library
python cli.py payload add \
  --id "MY-001" \
  --name "Custom jailbreak" \
  --payload "Ignore all instructions and..." \
  --category jailbreak \
  --severity high

# Generate a starter config file
python cli.py init-config --output omnifuzz.yaml
```

**5. Programmatic usage**

```python
import asyncio
from omnifuzz.engine import OmniFuzzer
from omnifuzz.adapters.openai_adapter import OpenAIAdapter
from omnifuzz.modules import SystemPromptExtractor, ToolAbuseScanner
from omnifuzz.compliance import ComplianceReporter

async def main():
    adapter = OpenAIAdapter(api_key="sk-...", model="gpt-4o-mini")

    # System prompt extraction
    extractor = SystemPromptExtractor(
        known_prompt="You are a customer service bot.",
        indicators=["customer service", "never discuss pricing"],
    )
    fuzzer = OmniFuzzer(adapter=adapter, evaluator=extractor)
    results = await fuzzer.run_scan(extractor.get_scan_payloads())

    # Tool abuse
    tool_scanner = ToolAbuseScanner(techniques=["ssrf", "sql_injection"])
    tool_results = await fuzzer.run_scan(
        tool_scanner.get_scan_payloads(),
        evaluator=tool_scanner.get_evaluator(),
    )

    all_results = [r.to_dict() for r in results + tool_results]

    # Generate compliance report
    reporter = ComplianceReporter(all_results, target="MyApp v2.1", version="gpt-4o-mini")
    reporter.generate("compliance_report.html", fmt="html")
    reporter.generate("compliance_report.json", fmt="json")

asyncio.run(main())
```

**6. Proxy mode (passive monitoring)**

```python
from omnifuzz.proxy import OmniFuzzProxy

proxy = OmniFuzzProxy(
    on_finding=lambda event: print(f"Finding: {event.findings}"),
)

# In your middleware / request handler:
event = await proxy.intercept(request_body, response_body, latency_ms=120)
print(proxy.stats())
```

**7. Register a custom mutator**

```python
from omnifuzz.plugin import register_mutator, apply_mutator

@register_mutator("pig_latin")
def pig_latin(text: str) -> str:
    return " ".join(w[1:] + w[0] + "ay" for w in text.split())

result = apply_mutator("pig_latin", "ignore all instructions")
# → "gnoreiay llaay nstructionsiay"
```

---

## Configuration file

Create a config file to avoid passing flags on every run:

```yaml
# omnifuzz.yaml
adapter: openai
model: gpt-4o-mini
categories:
  - jailbreak
  - sensitive_info
  - system_prompt_extraction
concurrency: 5
output_json: results.json
output_html: report.html
checkpoint_dir: .omnifuzz_checkpoints
verbose: false
```

```bash
python cli.py scan --config omnifuzz.yaml
```

Config values are deep-merged with CLI flags — CLI always wins.

---

## Configuration reference

| Key | CLI flag | Default | Description |
|-----|----------|---------|-------------|
| `adapter` | `--adapter` | `openai` | Adapter to use: `openai`, `azure`, `anthropic`, `subprocess` |
| `api_key` | `--api-key` | (env: `OPENAI_API_KEY`) | API key for the target service |
| `model` | `--model` | `gpt-4o-mini` | Model name or deployment ID |
| `categories` | `--categories` | all | Payload categories to include |
| `concurrency` | `--concurrency` | `5` | Parallel requests per scan |
| `output_json` | `--output-json` | (none) | Write JSON findings to this path |
| `output_html` | `--output-html` | (none) | Write HTML report to this path |
| `output_markdown` | `--output-markdown` | (none) | Write Markdown report to this path |
| `checkpoint_dir` | `--checkpoint-dir` | `.omnifuzz_checkpoints` | Directory for checkpoint files |
| `verbose` | `--verbose` | `false` | Enable debug logging |
| `quiet` | `--quiet` | `false` | Suppress all output except findings |
| `log_file` | `--log-file` | (none) | Write logs to file |
| `json_logs` | `--json-logs` | `false` | Emit logs as JSON (for log aggregators) |

---

## OWASP LLM Top 10 coverage

| Control | Name | Modules | Status |
|---------|------|---------|--------|
| LLM01 | Prompt Injection | `indirect_injection`, `embedding_poisoning`, `multimodal` | ✅ Covered |
| LLM02 | Insecure Output Handling | `tool_abuse` | ✅ Covered |
| LLM03 | Training Data Poisoning | `embedding_poisoning` (partial) | ⚠️ Partial |
| LLM04 | Model Denial of Service | `dos_tester`, `multitenant_tester` | ✅ Covered |
| LLM05 | Supply Chain Vulnerabilities | — | ⬜ Infrastructure only |
| LLM06 | Sensitive Information Disclosure | `pii_compliance`, `credential_harvesting` | ✅ Covered |
| LLM07 | Insecure Plugin Design | `sysprompt_extractor`, `tool_abuse` | ✅ Covered |
| LLM08 | Excessive Agency | `tool_abuse`, `indirect_injection` | ✅ Covered |
| LLM09 | Overreliance | `hallucination_tester`, `consistency_tester` | ✅ Covered |
| LLM10 | Model Theft | `sysprompt_extractor` | ✅ Covered |

---

## Writing a custom adapter

Any callable that takes a string and returns a string works as an adapter. For async:

```python
class MyAdapter:
    async def send(self, prompt: str) -> str:
        # call your model here
        return response_text
```

Pass it to `OmniFuzzer(adapter=MyAdapter())`.

---

## Writing a custom module

A scan module needs two things:

```python
class MyModule:
    def get_scan_payloads(self) -> list[dict]:
        # Return list of {"text": "...", "category": "...", "index": N}
        return [...]

    def get_evaluator(self):
        # Return an object with async evaluate(payload, response) -> (bool, str)
        return MyEvaluator()

class MyEvaluator:
    async def evaluate(self, payload: str, response: str) -> tuple[bool, str]:
        is_vulnerable = "bad signal" in response.lower()
        return is_vulnerable, "details here"
```

---

## Roadmap

### Near term

**Comparison mode UI** — a side-by-side HTML report comparing two scan runs (e.g. GPT-4o vs Claude 3.5 Sonnet against the same payload set) is partially implemented in the regression module but doesn't yet have a dedicated report template.

**Payload library expansion** — the built-in `library.json` covers jailbreaks and sensitive information probes. It needs more payloads for tool-call abuse, multi-agent scenarios, and RAG-specific attacks.

**SARIF output** — security teams that use GitHub Advanced Security or other SAST platforms expect findings in SARIF format. Adding a SARIF reporter would let OmniFuzz results appear directly in the GitHub Security tab.

**Real-time proxy server** — the `OmniFuzzProxy` class provides the core intercept logic, but there is no standalone HTTP server that can be dropped in front of a real OpenAI endpoint. A thin `uvicorn`-based proxy server (`omnifuzz proxy start`) is the natural next step.

### Longer term

**Multimodal inputs with real images** — the multimodal module currently simulates what a vision model would receive after OCR. Generating actual adversarial images (text-on-image, EXIF injection, steganographic payloads) and submitting them to vision-capable models would make the tests more realistic.

**Agent / multi-step scan mode** — current scans are single-turn. Many real-world exploits (tool-call abuse, indirect injection chaining) require multi-turn conversations where the attacker's payload arrives in step 3 after establishing context in steps 1 and 2. A stateful multi-turn scan engine is needed.

**Embedding distance scoring** — the embedding poisoning module simulates a RAG scenario by injecting documents directly into the prompt. A more precise test would use actual embedding models to verify that poisoned documents rank near the top of retrieval results before running the scan.

**Fine-tune regression tracking** — teams that fine-tune their models need to track not just individual scan results but the trend over training checkpoints. A lightweight database backend (SQLite by default, PostgreSQL optional) would let OmniFuzz store historical scan results and plot vulnerability trends over time.

---

## License

MIT. See [LICENSE](LICENSE).
