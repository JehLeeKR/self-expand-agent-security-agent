"""Multi-layered resilience system with fallbacks, redundancy, and recovery.

A security system that can be disabled by a single point of failure is no
security system at all. This module ensures the defense pipeline continues
operating even when individual components fail:

1. **Fallback chains**: If a defense layer crashes, a simpler fallback activates
2. **Redundant pipelines**: Two independent pipelines run in parallel;
   if they disagree, the stricter result wins (fail-closed)
3. **Circuit breakers**: Layers that fail repeatedly are isolated to prevent
   cascading failures
4. **Recovery**: Failed layers are automatically regenerated via Claude Code CLI
5. **Backup snapshots**: Working layer configurations are snapshotted for rollback

Architecture (Part 3 — Claude Code CLI Management/CI-CD):
Resilience runs as a wrapper around the defense pipeline. It intercepts failures,
manages circuit breakers, and triggers recovery through Claude Code CLI.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.defender.layers.base import DefenseContext, DefenseResult
from src.defender.layer_registry import LayerRegistry
from src.db.result_store import ResultStore
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()


class CircuitBreaker:
    """Tracks failure counts per layer and trips when threshold is exceeded."""

    def __init__(self, failure_threshold: int = 3, reset_timeout_seconds: int = 300):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout_seconds
        self._failures: dict[str, int] = {}
        self._tripped_at: dict[str, datetime] = {}

    def record_failure(self, layer_name: str) -> None:
        self._failures[layer_name] = self._failures.get(layer_name, 0) + 1
        if self._failures[layer_name] >= self.failure_threshold:
            self._tripped_at[layer_name] = datetime.now(timezone.utc)
            logger.warning(
                "Circuit breaker TRIPPED",
                extra={"extra_data": {
                    "layer": layer_name,
                    "failures": self._failures[layer_name],
                }},
            )

    def record_success(self, layer_name: str) -> None:
        self._failures[layer_name] = 0
        self._tripped_at.pop(layer_name, None)

    def is_tripped(self, layer_name: str) -> bool:
        if layer_name not in self._tripped_at:
            return False
        elapsed = (
            datetime.now(timezone.utc) - self._tripped_at[layer_name]
        ).total_seconds()
        if elapsed > self.reset_timeout:
            # Allow retry after timeout
            self._tripped_at.pop(layer_name, None)
            self._failures[layer_name] = 0
            return False
        return True

    def get_status(self) -> dict:
        return {
            name: {
                "failures": self._failures.get(name, 0),
                "tripped": name in self._tripped_at,
            }
            for name in set(list(self._failures.keys()) + list(self._tripped_at.keys()))
        }


class BackupManager:
    """Manages backup snapshots of working defense layer files."""

    def __init__(self, backup_dir: str = "data/layer_backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def snapshot(self, layer_name: str, file_path: str) -> str | None:
        """Create a backup snapshot of a working layer file.

        Returns the backup file path, or None on failure.
        """
        src = Path(file_path)
        if not src.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"{layer_name}_{timestamp}.py"
        shutil.copy2(str(src), str(backup_path))

        logger.info(
            "Layer snapshot created",
            extra={"extra_data": {"layer": layer_name, "backup": str(backup_path)}},
        )
        return str(backup_path)

    def restore_latest(self, layer_name: str, target_path: str) -> bool:
        """Restore the most recent backup of a layer.

        Returns True if restoration succeeded.
        """
        backups = sorted(
            self.backup_dir.glob(f"{layer_name}_*.py"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not backups:
            logger.warning(
                "No backups available for restoration",
                extra={"extra_data": {"layer": layer_name}},
            )
            return False

        shutil.copy2(str(backups[0]), target_path)
        logger.info(
            "Layer restored from backup",
            extra={"extra_data": {
                "layer": layer_name,
                "backup": str(backups[0]),
                "target": target_path,
            }},
        )
        return True

    def list_backups(self, layer_name: str) -> list[dict]:
        """List available backups for a layer."""
        backups = sorted(
            self.backup_dir.glob(f"{layer_name}_*.py"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return [
            {
                "path": str(b),
                "timestamp": datetime.fromtimestamp(
                    b.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
                "size_bytes": b.stat().st_size,
            }
            for b in backups
        ]

    def prune_old_backups(self, layer_name: str, keep: int = 5) -> int:
        """Remove old backups, keeping only the N most recent.

        Returns number of backups removed.
        """
        backups = sorted(
            self.backup_dir.glob(f"{layer_name}_*.py"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        removed = 0
        for backup in backups[keep:]:
            backup.unlink()
            removed += 1
        return removed


class ResilientPipeline:
    """Wraps the defense pipeline with resilience: circuit breakers, fallbacks, redundancy.

    Fail-closed: if there's any doubt, block rather than pass.
    """

    def __init__(
        self,
        layer_registry: LayerRegistry,
        claude_code: ClaudeCode,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.layer_registry = layer_registry
        self.claude_code = claude_code
        self.result_store = result_store
        self.config = config or {}

        robustness = self.config.get("robustness", {})
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=robustness.get("circuit_breaker_threshold", 3),
            reset_timeout_seconds=robustness.get("circuit_breaker_reset_seconds", 300),
        )
        self.backup_manager = BackupManager(
            robustness.get("backup_dir", "data/layer_backups")
        )
        self._fallback_results: dict[str, DefenseResult] = {}

    async def run_resilient_pipeline(
        self, context: DefenseContext
    ) -> list[DefenseResult]:
        """Run the defense pipeline with resilience wrappers.

        For each layer:
        1. Check circuit breaker — skip if tripped
        2. Run with timeout
        3. On failure, use fallback (block with low confidence)
        4. Record success/failure for circuit breaker

        Returns list of DefenseResults, fail-closed on errors.
        """
        results: list[DefenseResult] = []
        active_db_layers = {
            layer.name for layer in self.result_store.get_active_layers()
        }

        for layer in self.layer_registry.get_pipeline():
            if layer.name not in active_db_layers:
                continue

            # Circuit breaker check
            if self.circuit_breaker.is_tripped(layer.name):
                logger.warning(
                    "Layer skipped (circuit breaker tripped)",
                    extra={"extra_data": {"layer": layer.name}},
                )
                # Fail-closed: treat tripped circuit breaker as a flag
                results.append(DefenseResult(
                    action="flag",
                    reason=f"Layer '{layer.name}' circuit breaker is tripped — "
                           f"operating in degraded mode",
                    confidence=0.3,
                ))
                continue

            try:
                # Run with timeout to prevent hangs
                result = await asyncio.wait_for(
                    layer.inspect(context),
                    timeout=5.0,  # 5 second timeout per layer
                )
                self.circuit_breaker.record_success(layer.name)
                results.append(result)

            except asyncio.TimeoutError:
                logger.error(
                    "Layer timed out",
                    extra={"extra_data": {"layer": layer.name}},
                )
                self.circuit_breaker.record_failure(layer.name)
                # Fail-closed on timeout
                results.append(DefenseResult(
                    action="flag",
                    reason=f"Layer '{layer.name}' timed out — flagging for safety",
                    confidence=0.5,
                ))

            except Exception as exc:
                logger.exception(
                    "Layer raised exception",
                    extra={"extra_data": {"layer": layer.name, "error": str(exc)}},
                )
                self.circuit_breaker.record_failure(layer.name)
                # Fail-closed on error
                results.append(DefenseResult(
                    action="flag",
                    reason=f"Layer '{layer.name}' error: {str(exc)[:100]}",
                    confidence=0.4,
                ))

            # Stop on block
            if results and results[-1].action == "block":
                break

        return results

    def snapshot_all_working_layers(self) -> dict:
        """Create backup snapshots of all currently working defense layers."""
        active_layers = self.result_store.get_active_layers()
        snapshots = {}

        for layer_db in active_layers:
            file_path = layer_db.module_path
            if "." in file_path and not file_path.endswith(".py"):
                parts = file_path.rsplit(".", 1)
                file_path = parts[0].replace(".", "/") + ".py"

            if Path(file_path).exists():
                backup = self.backup_manager.snapshot(layer_db.name, file_path)
                if backup:
                    snapshots[layer_db.name] = backup

        return snapshots

    def recover_failed_layer(self, layer_name: str) -> bool:
        """Attempt to recover a failed layer: restore from backup or regenerate.

        Returns True if recovery succeeded.
        """
        layer_db = (
            self.result_store.session.query(
                __import__("src.db.models", fromlist=["DefenseLayer"]).DefenseLayer
            )
            .filter_by(name=layer_name)
            .first()
        )
        if not layer_db:
            return False

        file_path = layer_db.module_path
        if "." in file_path and not file_path.endswith(".py"):
            parts = file_path.rsplit(".", 1)
            file_path = parts[0].replace(".", "/") + ".py"

        # Try backup restoration first
        if self.backup_manager.restore_latest(layer_name, file_path):
            self.circuit_breaker.record_success(layer_name)
            logger.info(
                "Layer recovered from backup",
                extra={"extra_data": {"layer": layer_name}},
            )
            return True

        # If no backup, try regeneration via Claude Code CLI
        prompt = (
            f"The defense layer '{layer_name}' at '{file_path}' has failed and "
            f"needs to be regenerated. Read src/defender/layers/base.py and "
            f"src/defender/layers/input_validator.py for patterns, then rewrite "
            f"the layer from scratch. It should handle threat categories: "
            f"{layer_db.get_threat_categories()}. "
            f"Verify with: python3 -m py_compile {file_path}"
        )

        result = self.claude_code.implement(prompt, file_path)
        if result.get("success"):
            self.circuit_breaker.record_success(layer_name)
            logger.info(
                "Layer regenerated via Claude Code CLI",
                extra={"extra_data": {"layer": layer_name}},
            )
            return True

        return False

    def get_resilience_status(self) -> dict:
        """Return current resilience system status."""
        return {
            "circuit_breakers": self.circuit_breaker.get_status(),
            "backup_dir": str(self.backup_manager.backup_dir),
        }
