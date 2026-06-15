"""
Target adapters — abstract the model backend behind a single .generate() call.

Supported schemes:
  ollama/<model>           → Ollama local API (default: http://localhost:11434)
  hf/<repo/model>          → HuggingFace Transformers (loads locally)
  openai-compat/<model>    → Any OpenAI-compatible REST endpoint
"""

import json
import time
import concurrent.futures
import urllib.request
import urllib.error
from dataclasses import dataclass

_RETRY_ATTEMPTS = 2
_RETRY_DELAY = 2.0


@dataclass
class Response:
    text: str
    raw: dict


class OllamaTarget:
    name = "ollama"

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def generate(self, prompt: str, system: str = None) -> Response:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        last_err = None
        for attempt in range(_RETRY_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    raw = json.loads(r.read())
                    text = raw.get("message", {}).get("content", "")
                    return Response(text=text, raw=raw)
            except urllib.error.URLError as e:
                last_err = e
                if attempt < _RETRY_ATTEMPTS:
                    time.sleep(_RETRY_DELAY)
        raise ConnectionError(
            f"Cannot reach Ollama at {self.base_url}. "
            f"Is it running? Try: ollama serve\nError: {last_err}"
        )

    def __str__(self):
        return f"ollama/{self.model} @ {self.base_url}"


class HuggingFaceTarget:
    name = "huggingface"

    def __init__(self, model_id: str):
        self.model_id = model_id
        self._pipe = None

    def _load(self):
        if self._pipe is not None:
            return
        try:
            from transformers import pipeline
            import torch
        except ImportError:
            raise ImportError(
                "Install transformers & torch to use HuggingFace targets:\n"
                "  pip install transformers torch accelerate"
            )
        print(f"[target] Loading {self.model_id} ... (first run downloads weights)")
        self._pipe = pipeline(
            "text-generation",
            model=self.model_id,
            device_map="auto",
            max_new_tokens=512,
            do_sample=False,
        )

    def generate(self, prompt: str, system: str = None) -> Response:
        self._load()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self._pipe, messages)
            try:
                out = future.result(timeout=300)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(
                    f"[target] HuggingFace inference timed out after 300s ({self.model_id})"
                )
        text = out[0]["generated_text"][-1]["content"]
        return Response(text=text, raw=out)

    def __str__(self):
        return f"hf/{self.model_id}"


class OpenAICompatTarget:
    name = "openai-compat"

    def __init__(self, model: str, base_url: str, api_key: str = "none"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def generate(self, prompt: str, system: str = None) -> Response:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        last_err = None
        for attempt in range(_RETRY_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    raw = json.loads(r.read())
                if "error" in raw:
                    raise RuntimeError(f"[target] API error from {self.base_url}: {raw['error']}")
                text = raw["choices"][0]["message"]["content"]
                return Response(text=text, raw=raw)
            except urllib.error.URLError as e:
                last_err = e
                if attempt < _RETRY_ATTEMPTS:
                    time.sleep(_RETRY_DELAY)
        raise ConnectionError(
            f"Cannot reach OpenAI-compatible endpoint at {self.base_url}. "
            f"Is the server running?\nError: {last_err}"
        )

    def __str__(self):
        return f"openai-compat/{self.model} @ {self.base_url}"


def build_target(target_str: str, base_url: str = None):
    """
    Parse target string and return the appropriate adapter.

    Examples:
      ollama/llama3
      ollama/mistral:7b
      hf/mistralai/Mistral-7B-Instruct-v0.2
      openai-compat/my-model
    """
    if target_str.startswith("ollama/"):
        model = target_str[len("ollama/"):]
        url = base_url or "http://localhost:11434"
        return OllamaTarget(model=model, base_url=url)

    elif target_str.startswith("hf/"):
        model_id = target_str[len("hf/"):]
        return HuggingFaceTarget(model_id=model_id)

    elif target_str.startswith("openai-compat/"):
        model = target_str[len("openai-compat/"):]
        if not base_url:
            raise ValueError("--base-url required for openai-compat targets")
        return OpenAICompatTarget(model=model, base_url=base_url)

    else:
        # Default: try Ollama
        print(f"[target] Assuming Ollama for '{target_str}'")
        url = base_url or "http://localhost:11434"
        return OllamaTarget(model=target_str, base_url=url)
