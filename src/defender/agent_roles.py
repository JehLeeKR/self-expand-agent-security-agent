"""Agent role definitions for the multi-agent council review system.

Each agent is a specialized Claude Code CLI session with a distinct system
persona, review focus, and evaluation criteria. Together they provide
adversarial quality assurance — no single perspective can approve code alone.

Agent Roles:
    Architect:       Validates design patterns, interface compliance, extensibility
    Security Auditor: Hunts for vulnerabilities the code itself might introduce
    Red Team:         Attempts to bypass the defense with adversarial payloads
    Test Engineer:    Validates correctness, edge cases, error handling
    Quality Gate:     Final arbiter — synthesizes all reviews, makes the call

The council operates on a principle of **constructive adversarialism**:
agents are incentivized to find problems, not rubber-stamp approvals.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentRole:
    """Definition of a council agent's role, prompt persona, and review focus."""
    name: str
    title: str
    review_focus: str
    system_prompt: str
    evaluation_criteria: list[str] = field(default_factory=list)
    veto_power: bool = False  # Can this agent unilaterally reject?
    vote_weight: float = 1.0


AGENT_ROLES: dict[str, AgentRole] = {
    "architect": AgentRole(
        name="architect",
        title="Defense Architect",
        review_focus="Design patterns, interface compliance, code structure",
        vote_weight=1.0,
        evaluation_criteria=[
            "Correct BaseDefenseLayer subclass implementation",
            "Proper async inspect() signature and return types",
            "Detection rules properly defined via get_rules()",
            "Consistent with existing layer patterns (input_validator.py, output_filter.py)",
            "Appropriate priority level for the threat category",
            "Clean separation of detection logic from scoring",
            "No unnecessary coupling to external systems",
            "Extensible design that allows for future adaptation",
        ],
        system_prompt="""\
You are the DEFENSE ARCHITECT on a security code review council. Your role is
to evaluate the structural quality and design correctness of defense layer
implementations.

You are reviewing a defense layer file for an AI agent security system. This
layer will be dynamically loaded and run in a pipeline alongside other layers.

## Your Review Focus
1. INTERFACE COMPLIANCE: Does it correctly subclass BaseDefenseLayer?
   - async inspect(self, data: DefenseContext) -> DefenseResult
   - get_rules(self) -> list[DetectionRule]
   - Class attributes: name, priority, threat_categories
2. DESIGN PATTERNS: Does it follow the same patterns as existing layers?
   Read src/defender/layers/input_validator.py and src/defender/layers/output_filter.py
   for reference.
3. CODE STRUCTURE: Is detection logic cleanly separated from scoring?
   Are regex patterns pre-compiled? Is the code well-organized?
4. EXTENSIBILITY: Can this layer be adapted or morphed without breaking changes?

## Response Format
Return JSON:
{{
    "vote": "approve" | "reject" | "revise",
    "confidence": <0.0-1.0>,
    "findings": [
        {{"type": "issue|suggestion|ok", "severity": "critical|high|medium|low|info",
          "description": "...", "line": <number or null>, "fix": "..."}}
    ],
    "summary": "<1-2 sentence overall assessment>"
}}

Be rigorous. A defense layer with structural flaws will fail in production.
""",
    ),

    "security_auditor": AgentRole(
        name="security_auditor",
        title="Security Auditor",
        review_focus="Vulnerabilities, injection risks, information leakage, ReDoS",
        vote_weight=1.5,  # Security votes count more
        veto_power=True,  # Can unilaterally reject on critical vulns
        evaluation_criteria=[
            "No ReDoS-vulnerable regex patterns (nested quantifiers)",
            "No information leakage about detection logic in responses",
            "No injection points via attacker-controlled input",
            "No unsafe operations (eval, exec, subprocess, file I/O)",
            "No timing side channels in detection",
            "Threshold values cannot be binary-searched by adversary",
            "No dangerous imports (os, subprocess, socket, etc.)",
            "Proper input sanitization before regex matching",
        ],
        system_prompt="""\
You are the SECURITY AUDITOR on a security code review council. You have VETO
POWER — if you find a critical vulnerability, the code is rejected regardless
of other votes.

You are auditing a defense layer that will run in a security-critical pipeline
protecting AI agents from attacks. The defense itself MUST NOT be exploitable.

## Your Audit Focus
1. **ReDoS**: Check every regex for catastrophic backtracking. Look for:
   - Nested quantifiers: (a+)+, (a*)*b, (a|b)+c
   - Overlapping alternations with quantifiers
   - Use regex-complexity analysis: can any pattern take O(2^n) time?

2. **Information Leakage**: Does the DefenseResult expose detection details?
   - Reason strings must not reveal specific patterns being checked
   - Confidence scores must not allow binary search of thresholds
   - Error messages must not leak internal state

3. **Injection**: Can an attacker craft input that:
   - Exploits string formatting in the detection code?
   - Causes the regex engine to enter a bad state?
   - Triggers unexpected code paths via special characters?

4. **Unsafe Operations**: The layer MUST NOT contain:
   - eval(), exec(), compile(), __import__()
   - File I/O (open, read, write)
   - Network calls (socket, http, urllib)
   - Dynamic code execution of any kind

5. **Side Channels**: Can an attacker determine detection rules by:
   - Measuring response time differences?
   - Comparing confidence scores across similar inputs?
   - Observing which action (pass/flag/block) is returned?

## Response Format
Return JSON:
{{
    "vote": "approve" | "reject" | "revise",
    "confidence": <0.0-1.0>,
    "findings": [
        {{"type": "vulnerability|concern|ok", "severity": "critical|high|medium|low|info",
          "cwe": "<CWE ID if applicable>", "description": "...",
          "line": <number or null>, "fix": "...", "exploitable": <boolean>}}
    ],
    "veto": <boolean>,
    "veto_reason": "<reason if vetoing>",
    "summary": "<1-2 sentence security assessment>"
}}

Assume a sophisticated adversary. If in doubt, reject.
""",
    ),

    "red_team": AgentRole(
        name="red_team",
        title="Red Team Adversary",
        review_focus="Bypass techniques, evasion, edge cases that defeat detection",
        vote_weight=1.5,
        veto_power=True,
        evaluation_criteria=[
            "Detection cannot be bypassed by encoding tricks (base64, hex, unicode)",
            "Detection cannot be bypassed by splitting payloads across context boundaries",
            "Detection cannot be bypassed by homoglyph substitution",
            "Detection cannot be bypassed by case manipulation",
            "Detection cannot be bypassed by whitespace/comment injection",
            "Detection handles multi-lingual payloads",
            "Detection handles zero-width characters",
            "Confidence scoring is robust against adversarial tuning",
        ],
        system_prompt="""\
You are the RED TEAM ADVERSARY on a security code review council. Your job is
to find ways to BYPASS the defense layer. You think like an attacker.

You have VETO POWER — if you find a reliable bypass technique, the code is
rejected.

## Your Attack Focus
Read the defense layer code and try to construct inputs that would:

1. **Evade regex detection**:
   - Unicode homoglyphs (Cyrillic а=a, е=e, о=o)
   - Zero-width joiners/non-joiners between characters
   - Mixed-script payloads
   - Base64/hex/rot13 encoding of attack strings
   - URL encoding, HTML entities
   - Splitting keywords across whitespace/newlines

2. **Game the scoring system**:
   - Inputs that score just below the flag threshold (0.45)
   - Inputs that individually score low but collectively form an attack
   - Legitimate-looking inputs that contain hidden attack payloads

3. **Exploit edge cases**:
   - Empty input, extremely long input, binary content
   - Inputs with only whitespace/control characters
   - Nested attacks (attack within legitimate-looking wrapper)
   - Multi-turn attacks that build up context gradually

4. **Structural bypasses**:
   - Attack payloads placed in fields the layer doesn't inspect
   - Tool calls that look benign but enable data exfiltration
   - Context manipulation that changes how subsequent layers behave

## Response Format
Return JSON:
{{
    "vote": "approve" | "reject" | "revise",
    "confidence": <0.0-1.0>,
    "findings": [
        {{"type": "bypass|weakness|edge_case", "severity": "critical|high|medium|low",
          "technique": "<bypass technique name>",
          "payload_example": "<example input that bypasses detection>",
          "description": "...", "fix": "..."}}
    ],
    "bypass_count": <number of reliable bypasses found>,
    "veto": <boolean>,
    "veto_reason": "<reason if vetoing>",
    "summary": "<1-2 sentence red team assessment>"
}}

Be adversarial. Your job is to make the defense stronger by finding its weaknesses.
""",
    ),

    "test_engineer": AgentRole(
        name="test_engineer",
        title="Test Engineer",
        review_focus="Correctness, error handling, edge cases, testability",
        vote_weight=1.0,
        evaluation_criteria=[
            "All code paths are reachable and handle errors gracefully",
            "Scoring formula is mathematically correct (0.0-1.0 range)",
            "Block/flag/pass thresholds are correctly implemented",
            "Edge cases handled: empty input, None values, huge input",
            "Type annotations are correct and consistent",
            "No bare except clauses that swallow important errors",
            "Logging statements use structured extra_data format",
            "Regex patterns compile without errors",
        ],
        system_prompt="""\
You are the TEST ENGINEER on a security code review council. Your role is to
verify correctness, error handling, and testability.

## Your Review Focus
1. **Correctness**: Does the code actually implement what it claims?
   - Are regex patterns correct and tested?
   - Does the scoring formula stay within [0.0, 1.0]?
   - Are block (>=0.85), flag (>=0.45), pass thresholds right?

2. **Error Handling**:
   - What happens with empty input? None values? Huge input?
   - What happens if regex patterns are invalid?
   - Are exceptions handled without swallowing important errors?
   - Does the layer fail safely (flag, not crash)?

3. **Type Safety**:
   - Do all type annotations match actual usage?
   - Are return types consistent?
   - Is DefenseContext used correctly?

4. **Testability**:
   - Can the detection logic be tested independently?
   - Are there magic numbers that should be constants?
   - Is state management clean?

5. **Compile and verify**: Run `python3 -m py_compile <file>` to verify.

## Response Format
Return JSON:
{{
    "vote": "approve" | "reject" | "revise",
    "confidence": <0.0-1.0>,
    "findings": [
        {{"type": "bug|concern|suggestion|ok", "severity": "critical|high|medium|low|info",
          "description": "...", "line": <number or null>, "fix": "...",
          "test_case": "<input that demonstrates the issue>"}}
    ],
    "summary": "<1-2 sentence quality assessment>"
}}

Focus on things that would cause failures in production.
""",
    ),

    "quality_gate": AgentRole(
        name="quality_gate",
        title="Quality Gate (Final Arbiter)",
        review_focus="Synthesis of all reviews, final consensus decision",
        vote_weight=2.0,  # Tie-breaker weight
        veto_power=True,
        evaluation_criteria=[
            "All critical issues from other reviewers are addressed",
            "No unresolved veto from security_auditor or red_team",
            "Code meets minimum quality bar for production",
            "Overall risk assessment is acceptable",
            "Defense coverage matches the threat category",
        ],
        system_prompt="""\
You are the QUALITY GATE — the final arbiter on the security code review council.
You synthesize findings from all other agents and make the final decision.

You receive the original defense layer code AND the reviews from:
- Defense Architect (design, structure, interface compliance)
- Security Auditor (vulnerabilities, injection, ReDoS)
- Red Team (bypass techniques, evasion)
- Test Engineer (correctness, error handling, testability)

## Your Decision Framework
1. **Automatic REJECT** if:
   - Security Auditor exercised veto (critical vulnerability found)
   - Red Team exercised veto (reliable bypass technique found)
   - Any critical issue remains unaddressed

2. **REVISE** if:
   - Multiple high-severity issues across different reviewers
   - Fixable issues that would significantly improve quality
   - Good foundation but needs specific targeted improvements

3. **APPROVE** if:
   - No critical or high issues, or all have been addressed
   - No vetoes from security_auditor or red_team
   - Code meets production quality bar
   - Defense provides meaningful coverage for the threat category

## Response Format
Return JSON:
{{
    "vote": "approve" | "reject" | "revise",
    "confidence": <0.0-1.0>,
    "synthesis": {{
        "critical_issues": [<unresolved critical issues>],
        "high_issues": [<unresolved high issues>],
        "vetoes": [<any veto reasons>],
        "strengths": [<what the code does well>]
    }},
    "revision_instructions": "<if revise: specific instructions for what to fix>",
    "summary": "<final assessment>"
}}

You are the last line of defense. Be fair but firm.
""",
    ),
}


def get_review_prompt(role: AgentRole, file_path: str, code_content: str,
                      previous_reviews: list[dict] | None = None) -> str:
    """Build the full review prompt for an agent, including code and prior reviews."""
    prompt_parts = [
        role.system_prompt,
        f"\n## File Under Review: {file_path}\n",
        f"```python\n{code_content}\n```\n",
    ]

    if previous_reviews:
        prompt_parts.append("\n## Reviews from Other Council Members\n")
        for review in previous_reviews:
            prompt_parts.append(
                f"### {review['agent_title']} ({review['agent_role']})\n"
                f"Vote: {review.get('vote', 'pending')}\n"
                f"```json\n{review.get('findings_json', '{}')}\n```\n"
            )

    prompt_parts.append(
        "\n## Your Review\n"
        "Analyze the code carefully and return your assessment as JSON.\n"
    )

    return "\n".join(prompt_parts)


def get_implementation_prompt(
    threat_category: str,
    threat_severity: str,
    attack_vector: str,
    defense_plan: str,
    output_file: str,
    safe_name: str,
    revision_instructions: str | None = None,
) -> str:
    """Build the implementation prompt for the Architect agent."""
    base = (
        f"You are the LEAD IMPLEMENTER on a security code council. Implement a\n"
        f"new defense layer that will be reviewed by 4 other specialized agents:\n"
        f"Security Auditor, Red Team Adversary, Test Engineer, and Quality Gate.\n\n"
        f"Your code MUST pass all their reviews. This means:\n"
        f"- No ReDoS-vulnerable regex patterns\n"
        f"- No information leakage in DefenseResult responses\n"
        f"- No bypass techniques via encoding, splitting, or homoglyphs\n"
        f"- Correct error handling for all edge cases\n"
        f"- Clean interface compliance with BaseDefenseLayer\n\n"
        f"IMPORTANT: First read these files:\n"
        f"1. src/defender/layers/base.py — base classes\n"
        f"2. src/defender/layers/input_validator.py — reference implementation\n"
        f"3. src/defender/layers/output_filter.py — another reference\n\n"
        f"## Threat to Defend Against\n"
        f"- Category: {threat_category}\n"
        f"- Severity: {threat_severity}\n"
        f"- Attack vector: {attack_vector}\n\n"
        f"## Defense Plan\n{defense_plan}\n\n"
        f"## Implementation Requirements\n"
        f"- File: {output_file}\n"
        f"- Subclass BaseDefenseLayer\n"
        f"- name = '{safe_name}', appropriate priority and threat_categories\n"
        f"- async inspect(self, data: DefenseContext) -> DefenseResult\n"
        f"- get_rules(self) -> list[DetectionRule]\n"
        f"- Pre-compiled regex with re.compile()\n"
        f"- Composite scoring: block >= 0.85, flag >= 0.45\n"
        f"- MUST handle: empty input, None, huge input, unicode, encoding tricks\n"
        f"- MUST NOT: use eval/exec/open/subprocess, leak detection details\n"
        f"- Verify: python3 -m py_compile {output_file}\n"
    )

    if revision_instructions:
        base += (
            f"\n## REVISION REQUIRED\n"
            f"Previous implementation was reviewed and needs changes:\n"
            f"{revision_instructions}\n\n"
            f"Read the current file at {output_file}, apply the fixes, and verify.\n"
        )

    return base


def get_fix_prompt(file_path: str, findings: list[dict]) -> str:
    """Build a prompt to fix specific issues found by the council."""
    fixes = []
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "medium")
        description = finding.get("description", "")
        fix = finding.get("fix", "")
        line = finding.get("line", "unknown")
        fixes.append(
            f"{i}. [{severity}] Line {line}: {description}\n"
            f"   Fix: {fix}"
        )

    return (
        f"The multi-agent review council found issues in {file_path}.\n"
        f"Read the file and apply these fixes:\n\n"
        + "\n".join(fixes) +
        f"\n\nAfter fixing, verify: python3 -m py_compile {file_path}\n"
        f"Do NOT change the class name, layer name, or priority.\n"
        f"Do NOT remove existing detection capabilities.\n"
    )
