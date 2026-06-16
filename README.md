# LLM Red Teaming CLI

Use this CLI to probe open-source LLMs for safety issues and see how they handle risky prompts.

## Quick Start

### 1. Install Ollama for the quickest local setup

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3        # 4.7GB
ollama pull mistral       # 4.1GB
ollama pull qwen2.5       # 4.7GB
ollama pull gemma2        # 5.4GB

# Start the server (if not already running)
ollama serve
```

### 2. Run a red-team session

```bash
# Clone or download the repo
cd llm-redteam

# Run all attack modules against llama3
python cli.py run --target ollama/llama3

# Run specific modules only
python cli.py run --target ollama/mistral --attacks jailbreak,harmful

# Save the results
python cli.py run --target ollama/llama3 --output-json results.json --output-md report.md

# Keep the report updated while the run is still going
python cli.py run --target ollama/llama3 --output-md report.md --output-json results.json --live-report

# Verbose mode, so you can see each probe and response
python cli.py run --target ollama/llama3 -v

# Limit probes per module for a quick test
python cli.py run --target ollama/llama3 --max-probes 3

# List available attack modules
python cli.py list
```

> **Note - Attack Probes Are Private**
> This public repo includes the runner, judge, reporters, and target adapters.
> I keep the `attacks/` folder private on purpose, so people can't reuse the probes to game results or misuse the corpus.
> If you want access to the private attack pack for legitimate research or evaluation, open an issue and tell me what you're testing. I'll take a look and decide whether to share access later.

## What It Tests

| Module        | What it tests                                          |
|---------------|-------------------------------------------------------|
| `jailbreak`   | Prompt injection, persona override, DAN-style attacks |
| `harmful`     | Refusal of dangerous content requests                 |
| `pii`         | PII leakage, fabrication, data extraction             |
| `prompt_leakage` | System prompt leakage and hidden instruction disclosure |
| `output_handling` | Improper handling of injected or malicious output  |
| `data_poisoning` | Poisoned training data, label flips, backdoors     |
| `hallucination` | Fabricated facts, false premises, overconfidence    |
| `agentic`     | Scope violations, tool-use boundary enforcement       |
| `vector_weakness` | RAG / vector store poisoning and retrieval abuse  |
| `unbounded_consumption` | Runaway generation and resource exhaustion   |

These are the built-in attack families. The actual probe prompts stay in the private `attacks/` pack.

## Extra Benchmarks

You can also cross-check against a few external benchmark sets:

- `--harmbench <csv>` for HarmBench
- `--jailbreakbench <json>` for JailbreakBench
- `--garak` for Garak probes

## Supported Targets

```bash
# Ollama, running locally
python cli.py run --target ollama/llama3
python cli.py run --target ollama/mistral
python cli.py run --target ollama/qwen2.5:7b

# Hugging Face models download and run locally
# pip install transformers torch accelerate
python cli.py run --target hf/mistralai/Mistral-7B-Instruct-v0.2
python cli.py run --target hf/google/gemma-2-9b-it

# Any OpenAI-compatible endpoint, such as LM Studio or vLLM
python cli.py run --target openai-compat/my-model --base-url http://localhost:1234
```

## What You Get

The CLI prints results to the console and can also save them to:
- `results.json`
- `report.md`

## What's in the Repo

```
llm-redteam/
├── cli.py                  # Entry point
├── core/
│   ├── target.py           # Model adapters (Ollama, HF, OpenAI-compat)
│   ├── judge.py            # Rule-based response scorer
│   └── runner.py           # Orchestrates the session
├── attacks/                # Private — intentionally omitted from the public repo
└── reporters/
    ├── console.py
    ├── json_reporter.py
    └── markdown_reporter.py
```

## Adding Custom Probes

If you already have access to the private `attacks/` pack, add a new file in `attacks/`:

```python
class MyAttack:
    description = "My custom attack module"

    def probes(self):
        return [
            {"text": "Your probe here", "category": "my_category"},
        ]
```

Then register it in `attacks/__init__.py`:

```python
from attacks.my_attack import MyAttack
ATTACK_REGISTRY["my_attack"] = MyAttack
```

Then run it:

```bash
python cli.py run --target ollama/llama3 --attacks my_attack
```

## You'll Need

- Python 3.8+
- No external dependencies for Ollama or OpenAI-compatible targets
- `pip install transformers torch accelerate` for HuggingFace targets
