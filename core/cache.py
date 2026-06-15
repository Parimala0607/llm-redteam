"""
Probe cache — avoids re-querying the same probe against the same target.
Stores results in memory during a session and optionally persists to disk.
"""

import json
import os
import hashlib
import threading
from typing import Optional


class ProbeCache:
    def __init__(self, cache_file: str = ".redteam_cache.json"):
        self.cache_file = cache_file
        self._mem: dict = {}
        self._lock = threading.Lock()
        self._load()

    def _key(self, probe: str, target: str, attack_module: str = "", category: str = "") -> str:
        material = f"{target}::{attack_module}::{category}::{probe}"
        return hashlib.sha256(material.encode()).hexdigest()

    def _load(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file) as f:
                    self._mem = json.load(f)
            except Exception:
                self._mem = {}

    def _save(self):
        try:
            tmp_path = f"{self.cache_file}.tmp"
            with open(tmp_path, "w") as f:
                json.dump(self._mem, f)
            os.replace(tmp_path, self.cache_file)
        except Exception:
            pass

    def get(self, probe: str, target: str, attack_module: str = "", category: str = ""):
        """Return cached Result or None."""
        from core.judge import Result
        key = self._key(probe, target, attack_module, category)
        data = self._mem.get(key)
        if data:
            return Result(**data)
        return None

    def set(self, probe: str, target: str, result):
        key = self._key(probe, target, result.attack_module, result.category)
        with self._lock:
            self._mem[key] = {
                "probe": result.probe,
                "response": result.response,
                "passed": result.passed,
                "score": result.score,
                "reason": result.reason,
                "matched": result.matched,
                "confidence": result.confidence,
                "category": result.category,
                "attack_module": result.attack_module,
                "tags": getattr(result, "tags", []),
            }
            self._save()

    def clear(self):
        with self._lock:
            self._mem = {}
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
        print("[cache] Cleared.")

    def stats(self) -> dict:
        return {"entries": len(self._mem), "file": self.cache_file}
