"""Wrapper around Anthropic SDK for threat analysis tasks."""

import os

import anthropic

from src.utils.logging import get_logger

logger = get_logger()


class ClaudeAPI:
    def __init__(self, model: str = "claude-sonnet-4-6", max_tokens: int = 4096):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def query(self, system_prompt: str, user_message: str) -> str:
        logger.info("Querying Claude API", extra={"extra_data": {"model": self.model}})
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text

    def query_json(self, system_prompt: str, user_message: str) -> dict:
        """Query Claude and parse the response as JSON."""
        import json

        raw = self.query(
            system_prompt + "\n\nRespond ONLY with valid JSON, no markdown fences.",
            user_message,
        )
        # Strip markdown fences if present despite instruction
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        return json.loads(cleaned.strip())
