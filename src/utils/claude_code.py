"""Wrapper around Claude Code CLI for autonomous code implementation."""

import json
import subprocess
from pathlib import Path

from src.utils.logging import get_logger

logger = get_logger()


class ClaudeCode:
    def __init__(self, binary: str = "claude", working_dir: str = ".", timeout: int = 300):
        self.binary = binary
        self.working_dir = Path(working_dir).resolve()
        self.timeout = timeout

    def implement(self, prompt: str, output_file: str | None = None) -> dict:
        """Use Claude Code CLI to implement code based on a prompt.

        Args:
            prompt: The implementation instruction for Claude Code.
            output_file: Optional specific file path to create/modify.

        Returns:
            dict with 'success', 'output', and optionally 'file_path'.
        """
        cmd = [
            self.binary,
            "-p", prompt,
            "--output-format", "json",
        ]

        logger.info(
            "Invoking Claude Code CLI",
            extra={"extra_data": {"prompt_preview": prompt[:200], "output_file": output_file}},
        )

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.working_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.error(
                    "Claude Code CLI failed",
                    extra={"extra_data": {"stderr": result.stderr[:500]}},
                )
                return {"success": False, "output": result.stderr, "file_path": output_file}

            # Try to parse structured output
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                output = result.stdout

            return {"success": True, "output": output, "file_path": output_file}

        except subprocess.TimeoutExpired:
            logger.error("Claude Code CLI timed out", extra={"extra_data": {"timeout": self.timeout}})
            return {"success": False, "output": "Timeout expired", "file_path": output_file}

    def verify_code(self, file_path: str) -> dict:
        """Run basic verification on generated code."""
        cmd = [
            self.binary,
            "-p", f"Review the file {file_path} for syntax errors and security issues. "
                  f"If there are issues, fix them. Respond with a JSON summary: "
                  f'{{"valid": true/false, "issues": [...]}}',
            "--output-format", "json",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.working_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return {"success": result.returncode == 0, "output": result.stdout}
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Verification timed out"}
