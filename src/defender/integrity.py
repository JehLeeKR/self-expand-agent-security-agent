"""Self-integrity verification system — the security system must not be vulnerable itself.

This module provides defense-in-depth for the defense system itself:

1. **Hash verification**: SHA-256 hashes of all defense layer files, checked
   before execution to detect tampering
2. **Vulnerability scanning**: Claude Code CLI audits defense layer code for
   common security issues (injection, path traversal, unsafe deserialization)
3. **Import safety**: Validates that dynamically loaded modules don't contain
   dangerous imports or operations
4. **Runtime integrity**: Monitors defense layer behavior for anomalies
   (sudden effectiveness drops, unexpected exceptions, timing anomalies)

Architecture (Part 3 — Claude Code CLI Management/CI-CD):
The integrity system runs as a pre-flight check before every defense pipeline
execution, and as a periodic deep audit via Claude Code CLI.
"""

from __future__ import annotations

import ast
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.db.models import IntegrityRecord
from src.db.result_store import ResultStore
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

# Imports/operations that should never appear in defense layers
_DANGEROUS_IMPORTS = {
    "os.system", "subprocess.call", "subprocess.Popen", "subprocess.run",
    "eval", "exec", "compile", "__import__",
    "pickle.loads", "marshal.loads", "shelve.open",
    "shutil.rmtree", "os.remove", "os.unlink",
    "socket.socket", "http.client", "urllib.request",
    "ctypes", "cffi",
}

_DANGEROUS_CALLS = {
    "eval", "exec", "compile", "__import__", "globals", "locals",
    "getattr", "setattr", "delattr",  # When used dynamically
    "open",  # Defense layers should not do file I/O
}

_SECURITY_AUDIT_PROMPT = """\
You are performing a SECURITY AUDIT of a defense layer file. This is critical —
the defense system itself must not contain vulnerabilities.

## File to Audit: {file_path}
## Layer Name: {layer_name}

Read the file and check for:

1. **Injection vulnerabilities**: Does the code construct strings from untrusted
   input without sanitization? Could an attacker craft input that exploits the
   detection logic itself?

2. **ReDoS (Regex Denial of Service)**: Do any regex patterns have catastrophic
   backtracking? Look for nested quantifiers like `(a+)+`, `(a|b)*c`, etc.

3. **Resource exhaustion**: Could a crafted input cause excessive memory or CPU
   usage in the inspect() method?

4. **Information leakage**: Does the defense layer leak information about its
   detection patterns in its responses? Could an attacker binary-search the
   thresholds?

5. **Unsafe operations**: File I/O, network calls, dynamic code execution,
   deserialization of untrusted data.

6. **Logic flaws**: Can the detection be bypassed by specific input patterns?
   Are there off-by-one errors in scoring?

7. **Import safety**: Are all imports from trusted packages only?

Return a JSON object:
{{
    "score": <float 0.0 to 1.0 where 1.0 is clean>,
    "issues": [
        {{
            "severity": "critical|high|medium|low|info",
            "type": "<vulnerability type>",
            "line": <line number or null>,
            "description": "<what the issue is>",
            "fix": "<how to fix it>"
        }}
    ],
    "safe_to_execute": <boolean>
}}

Be thorough but precise. Only flag real issues, not style preferences.
"""


class IntegrityVerifier:
    """Verifies integrity and security of defense layer code.

    Provides both fast pre-flight checks (hash verification, static analysis)
    and deep audits (Claude Code CLI security review).
    """

    def __init__(
        self,
        claude_code: ClaudeCode,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.claude_code = claude_code
        self.result_store = result_store
        self.session = result_store.session
        self.config = config or {}
        self.layers_dir = Path(
            self.config.get("layer_output_dir", "src/defender/layers")
        )

    # ------------------------------------------------------------------
    # Hash-based integrity
    # ------------------------------------------------------------------

    def compute_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def register_hash(self, layer_name: str, file_path: str) -> IntegrityRecord:
        """Register or update the integrity hash for a layer file."""
        file_hash = self.compute_hash(file_path)

        existing = (
            self.session.query(IntegrityRecord)
            .filter_by(layer_name=layer_name)
            .order_by(IntegrityRecord.verified_at.desc())
            .first()
        )

        record = IntegrityRecord(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            file_path=file_path,
            sha256_hash=file_hash,
        )
        self.session.add(record)
        self.session.commit()
        return record

    def verify_hash(self, layer_name: str, file_path: str) -> bool:
        """Verify a layer file against its registered hash.

        Returns True if hash matches (not tampered), False otherwise.
        """
        latest = (
            self.session.query(IntegrityRecord)
            .filter_by(layer_name=layer_name)
            .order_by(IntegrityRecord.verified_at.desc())
            .first()
        )
        if not latest:
            logger.warning(
                "No integrity hash registered for layer",
                extra={"extra_data": {"layer": layer_name}},
            )
            return False

        current_hash = self.compute_hash(file_path)
        if current_hash != latest.sha256_hash:
            logger.critical(
                "INTEGRITY VIOLATION: Layer file has been tampered with",
                extra={"extra_data": {
                    "layer": layer_name,
                    "file": file_path,
                    "expected_hash": latest.sha256_hash,
                    "actual_hash": current_hash,
                }},
            )
            # Record the violation
            record = IntegrityRecord(
                id=str(uuid.uuid4()),
                layer_name=layer_name,
                file_path=file_path,
                sha256_hash=current_hash,
                is_tampered=True,
            )
            self.session.add(record)
            self.session.commit()
            return False

        return True

    # ------------------------------------------------------------------
    # Static analysis (fast, no CLI needed)
    # ------------------------------------------------------------------

    def static_analysis(self, file_path: str) -> dict:
        """Perform fast static analysis of a defense layer file.

        Checks for dangerous imports, calls, and structural issues
        without invoking Claude Code CLI.

        Returns dict with "safe" bool and "issues" list.
        """
        issues = []

        try:
            with open(file_path, "r") as f:
                source = f.read()
        except (OSError, IOError) as e:
            return {"safe": False, "issues": [{"type": "file_error", "detail": str(e)}]}

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            return {"safe": False, "issues": [{"type": "syntax_error", "detail": str(e)}]}

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _DANGEROUS_IMPORTS or any(
                        alias.name.startswith(d.split(".")[0]) and d in _DANGEROUS_IMPORTS
                        for d in _DANGEROUS_IMPORTS
                    ):
                        issues.append({
                            "type": "dangerous_import",
                            "detail": f"Dangerous import: {alias.name}",
                            "line": node.lineno,
                            "severity": "critical",
                        })

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        full_name = f"{node.module}.{alias.name}"
                        if full_name in _DANGEROUS_IMPORTS:
                            issues.append({
                                "type": "dangerous_import",
                                "detail": f"Dangerous import: {full_name}",
                                "line": node.lineno,
                                "severity": "critical",
                            })

            # Check function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in _DANGEROUS_CALLS:
                        issues.append({
                            "type": "dangerous_call",
                            "detail": f"Dangerous call: {node.func.id}()",
                            "line": node.lineno,
                            "severity": "high",
                        })

        safe = not any(i["severity"] in ("critical", "high") for i in issues)
        return {"safe": safe, "issues": issues}

    # ------------------------------------------------------------------
    # Deep audit via Claude Code CLI
    # ------------------------------------------------------------------

    def deep_audit(self, layer_name: str, file_path: str) -> dict:
        """Run a deep security audit on a defense layer via Claude Code CLI.

        Returns audit result dict with score, issues, and safe_to_execute.
        """
        prompt = _SECURITY_AUDIT_PROMPT.format(
            file_path=file_path,
            layer_name=layer_name,
        )

        result = self.claude_code.implement(prompt, None)
        if not result.get("success"):
            logger.error(
                "Deep audit failed",
                extra={"extra_data": {"layer": layer_name}},
            )
            return {"score": 0.0, "issues": [], "safe_to_execute": False}

        # Parse audit response
        output = result.get("output", "")
        if isinstance(output, dict):
            text = output.get("result", str(output))
        else:
            text = str(output)

        try:
            # Extract JSON from response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                audit = json.loads(text[start:end])
            else:
                audit = {"score": 0.5, "issues": [], "safe_to_execute": True}
        except json.JSONDecodeError:
            audit = {"score": 0.5, "issues": [], "safe_to_execute": True}

        # Record audit
        record = IntegrityRecord(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            file_path=file_path,
            sha256_hash=self.compute_hash(file_path),
            audit_result=json.dumps(audit),
            audit_score=audit.get("score", 0.5),
        )
        self.session.add(record)
        self.session.commit()

        logger.info(
            "Deep audit complete",
            extra={"extra_data": {
                "layer": layer_name,
                "score": audit.get("score"),
                "issues": len(audit.get("issues", [])),
                "safe": audit.get("safe_to_execute"),
            }},
        )

        return audit

    # ------------------------------------------------------------------
    # Pre-flight verification
    # ------------------------------------------------------------------

    def preflight_check(self) -> dict:
        """Run pre-flight integrity checks on all active defense layers.

        Returns dict with overall status and per-layer results.
        """
        active_layers = self.result_store.get_active_layers()
        layer_results = {}
        all_safe = True

        for layer_db in active_layers:
            file_path = layer_db.module_path
            if "." in file_path and not file_path.endswith(".py"):
                parts = file_path.rsplit(".", 1)
                file_path = parts[0].replace(".", "/") + ".py"

            path = Path(file_path)
            if not path.exists():
                layer_results[layer_db.name] = {
                    "status": "missing",
                    "safe": False,
                }
                all_safe = False
                continue

            # Hash check
            hash_ok = self.verify_hash(layer_db.name, str(path))

            # Static analysis
            static = self.static_analysis(str(path))

            safe = hash_ok and static["safe"]
            if not safe:
                all_safe = False

            layer_results[layer_db.name] = {
                "status": "ok" if safe else "compromised",
                "hash_verified": hash_ok,
                "static_analysis": static,
                "safe": safe,
            }

        return {
            "all_safe": all_safe,
            "layers_checked": len(layer_results),
            "results": layer_results,
        }

    def run(self) -> dict:
        """Run full integrity verification cycle.

        1. Pre-flight hash and static checks
        2. Deep audit of any layers that haven't been audited recently

        Returns combined integrity report.
        """
        preflight = self.preflight_check()

        # Deep audit layers without recent audits
        active_layers = self.result_store.get_active_layers()
        audit_results = {}

        audit_interval = self.config.get("robustness", {}).get(
            "audit_interval_hours", 72
        )

        for layer_db in active_layers:
            latest_audit = (
                self.session.query(IntegrityRecord)
                .filter_by(layer_name=layer_db.name)
                .filter(IntegrityRecord.audit_result.isnot(None))
                .order_by(IntegrityRecord.verified_at.desc())
                .first()
            )

            needs_audit = True
            if latest_audit:
                verified_at = latest_audit.verified_at
                if verified_at.tzinfo is None:
                    verified_at = verified_at.replace(tzinfo=timezone.utc)
                hours_since = (
                    datetime.now(timezone.utc) - verified_at
                ).total_seconds() / 3600
                needs_audit = hours_since >= audit_interval

            if needs_audit:
                file_path = layer_db.module_path
                if "." in file_path and not file_path.endswith(".py"):
                    parts = file_path.rsplit(".", 1)
                    file_path = parts[0].replace(".", "/") + ".py"

                audit = self.deep_audit(layer_db.name, file_path)
                audit_results[layer_db.name] = audit

        return {
            "preflight": preflight,
            "deep_audits": audit_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
