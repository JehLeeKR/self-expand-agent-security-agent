"""Wrapper around Anthropic SDK for threat analysis tasks.

Features:
- Prompt caching: system prompts are cached via Anthropic's cache_control to
  avoid re-processing the same instructions on every call (~90% cost reduction
  for repeated system prompts within the cache TTL).
- Conversation context: supports multi-turn conversations so analyzers can
  carry context across sequential operations.
"""

import json
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

    def query(
        self,
        system_prompt: str,
        user_message: str,
        *,
        conversation: list[dict] | None = None,
        cache_system_prompt: bool = True,
    ) -> str:
        """Send a query to Claude API.

        Args:
            system_prompt: The system prompt instructing Claude's behavior.
            user_message: The user message to process.
            conversation: Optional prior conversation turns to maintain context.
                Each entry is {"role": "user"|"assistant", "content": str}.
            cache_system_prompt: If True, use Anthropic's prompt caching on the
                system prompt. This means repeated calls with the same system
                prompt (within the 5-minute cache TTL) will use cached tokens
                instead of re-processing, reducing cost by ~90% for the cached
                portion. The cache is keyed on the exact system prompt text.

        Returns:
            The assistant's response text.
        """
        # Build system prompt with optional caching
        if cache_system_prompt:
            system = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        else:
            system = system_prompt

        # Build messages: optional prior conversation + current user message
        messages = []
        if conversation:
            messages.extend(conversation)
        messages.append({"role": "user", "content": user_message})

        logger.info(
            "Querying Claude API",
            extra={"extra_data": {
                "model": self.model,
                "cached": cache_system_prompt,
                "conversation_turns": len(messages),
            }},
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=messages,
        )

        # Log cache performance if available
        usage = response.usage
        if hasattr(usage, "cache_read_input_tokens"):
            cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
            cache_create = getattr(usage, "cache_creation_input_tokens", 0) or 0
            if cache_read > 0 or cache_create > 0:
                logger.info(
                    "Prompt cache stats",
                    extra={"extra_data": {
                        "cache_read_tokens": cache_read,
                        "cache_creation_tokens": cache_create,
                        "input_tokens": usage.input_tokens,
                    }},
                )

        return response.content[0].text

    def query_json(
        self,
        system_prompt: str,
        user_message: str,
        *,
        conversation: list[dict] | None = None,
        cache_system_prompt: bool = True,
    ) -> dict | list:
        """Query Claude and parse the response as JSON.

        Supports the same caching and conversation features as query().
        """
        raw = self.query(
            system_prompt + "\n\nRespond ONLY with valid JSON, no markdown fences.",
            user_message,
            conversation=conversation,
            cache_system_prompt=cache_system_prompt,
        )
        # Strip markdown fences if present despite instruction
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        return json.loads(cleaned.strip())

    def query_with_context(
        self,
        system_prompt: str,
        messages: list[dict],
        *,
        cache_system_prompt: bool = True,
    ) -> str:
        """Send a full multi-turn conversation to Claude.

        This is the lowest-level method that gives full control over the
        conversation history. Use this when you need to maintain a running
        dialogue (e.g., iterative defense refinement).

        Args:
            system_prompt: The system prompt.
            messages: Full conversation as [{"role": ..., "content": ...}, ...].
            cache_system_prompt: Whether to cache the system prompt.

        Returns:
            The assistant's response text.
        """
        if cache_system_prompt:
            system = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        else:
            system = system_prompt

        logger.info(
            "Querying Claude API (full context)",
            extra={"extra_data": {
                "model": self.model,
                "message_count": len(messages),
            }},
        )

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=messages,
        )
        return response.content[0].text
