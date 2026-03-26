"""Multi-agent council manager for defense layer quality assurance.

Instead of a single Claude Code CLI call, defense layer implementation goes
through a structured multi-agent review process:

    ┌─────────────────────────────────────────────────┐
    │              IMPLEMENTATION PHASE                │
    │  Architect Agent generates initial code          │
    └──────────────────────┬──────────────────────────┘
                           │
    ┌──────────────────────▼──────────────────────────┐
    │              PARALLEL REVIEW PHASE               │
    │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
    │  │ Security │ │ Red Team │ │  Test Engineer   │ │
    │  │ Auditor  │ │Adversary │ │                  │ │
    │  └─────┬────┘ └────┬─────┘ └───────┬──────────┘ │
    └────────┼───────────┼───────────────┼────────────┘
             │           │               │
    ┌────────▼───────────▼───────────────▼────────────┐
    │              QUALITY GATE PHASE                   │
    │  Final arbiter synthesizes all reviews            │
    │  Decision: APPROVE / REVISE / REJECT             │
    └──────────────────────┬──────────────────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
           APPROVE      REVISE       REJECT
           (deploy)   (loop back)   (abort)

The council operates for up to N rounds. Each round:
1. If round 1: Architect implements. If round 2+: Architect applies fixes.
2. Three reviewers evaluate in parallel (independent CLI sessions).
3. Quality Gate makes the final call based on all reviews.
4. If REVISE: consolidate feedback and loop to step 1.
5. If APPROVE: code passes to staging pipeline.
6. If REJECT: code is discarded, threat flagged for manual review.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.db.models import CouncilSession, CouncilVote
from src.db.result_store import ResultStore
from src.defender.agent_roles import (
    AGENT_ROLES,
    get_fix_prompt,
    get_implementation_prompt,
    get_review_prompt,
)
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()


class CouncilManager:
    """Orchestrates multi-agent council reviews for defense layer implementations.

    Each defense layer goes through structured adversarial review before
    it can be accepted. Multiple specialized agents review from different
    angles (security, bypass resistance, correctness, design), and a
    final Quality Gate agent synthesizes their findings.
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

        council_config = self.config.get("council", {})
        self.max_rounds = council_config.get("max_rounds", 3)
        self.required_approvals = council_config.get("required_approvals", 3)
        self.auto_fix = council_config.get("auto_fix", True)

    # ------------------------------------------------------------------
    # Core review cycle
    # ------------------------------------------------------------------

    def run_council_review(
        self,
        threat_category: str,
        threat_severity: str,
        attack_vector: str,
        defense_plan: dict,
        output_file: str,
        safe_name: str,
        threat_id: str | None = None,
    ) -> dict:
        """Run the full multi-agent council review cycle.

        Returns dict with:
            - approved: bool
            - session_id: str
            - rounds: int
            - final_vote: str
            - all_votes: list of vote summaries
        """
        # Create council session
        council_session = CouncilSession(
            id=str(uuid.uuid4()),
            layer_name=safe_name,
            threat_id=threat_id,
            max_rounds=self.max_rounds,
        )
        self.session.add(council_session)
        self.session.commit()

        logger.info(
            "Council session started",
            extra={"extra_data": {
                "session_id": council_session.id,
                "layer": safe_name,
                "max_rounds": self.max_rounds,
            }},
        )

        all_votes: list[dict] = []
        revision_instructions = None

        for round_num in range(1, self.max_rounds + 1):
            logger.info(
                f"Council round {round_num}/{self.max_rounds}",
                extra={"extra_data": {
                    "session_id": council_session.id,
                    "round": round_num,
                }},
            )

            council_session.total_rounds = round_num
            council_session.phase = "implementation" if round_num == 1 else "revision"
            self.session.commit()

            # Phase 1: Implementation / Revision
            impl_prompt = get_implementation_prompt(
                threat_category=threat_category,
                threat_severity=threat_severity,
                attack_vector=attack_vector,
                defense_plan=json.dumps(defense_plan, indent=2),
                output_file=output_file,
                safe_name=safe_name,
                revision_instructions=revision_instructions,
            )

            impl_result = self.claude_code.implement(impl_prompt, output_file)
            if not impl_result.get("success"):
                logger.error(
                    f"Implementation failed in round {round_num}",
                    extra={"extra_data": {
                        "session_id": council_session.id,
                        "error": str(impl_result.get("output", ""))[:300],
                    }},
                )
                if round_num == self.max_rounds:
                    return self._finalize_session(council_session, "reject", all_votes)
                continue

            # Read the generated code for review
            try:
                code_content = Path(output_file).read_text()
            except (OSError, IOError):
                logger.error(f"Cannot read generated file: {output_file}")
                continue

            # Phase 2: Parallel review by specialist agents
            council_session.phase = "review"
            self.session.commit()

            review_agents = ["security_auditor", "red_team", "test_engineer"]
            reviews: list[dict] = []

            for agent_name in review_agents:
                review = self._run_agent_review(
                    agent_name=agent_name,
                    file_path=output_file,
                    code_content=code_content,
                    session_id=council_session.id,
                    round_num=round_num,
                )
                reviews.append(review)
                all_votes.append(review)

            # Phase 3: Quality Gate synthesis
            council_session.phase = "final_vote"
            self.session.commit()

            gate_review = self._run_quality_gate(
                file_path=output_file,
                code_content=code_content,
                previous_reviews=reviews,
                session_id=council_session.id,
                round_num=round_num,
            )
            all_votes.append(gate_review)

            # Evaluate consensus
            decision = self._evaluate_consensus(reviews, gate_review)

            logger.info(
                f"Round {round_num} decision: {decision}",
                extra={"extra_data": {
                    "session_id": council_session.id,
                    "decision": decision,
                    "votes": {r["agent_role"]: r.get("vote", "unknown") for r in reviews + [gate_review]},
                }},
            )

            if decision == "approve":
                return self._finalize_session(council_session, "approve", all_votes)
            elif decision == "reject":
                return self._finalize_session(council_session, "reject", all_votes)
            else:
                # Revise: collect all fix instructions
                revision_instructions = self._consolidate_fixes(reviews, gate_review)

                # Apply auto-fixes if enabled
                if self.auto_fix:
                    all_findings = []
                    for review in reviews:
                        all_findings.extend(review.get("findings", []))
                    fixable = [f for f in all_findings
                               if f.get("severity") in ("critical", "high")
                               and f.get("fix")]
                    if fixable:
                        fix_prompt = get_fix_prompt(output_file, fixable)
                        self.claude_code.implement(fix_prompt, output_file)

        # Max rounds exhausted without approval
        return self._finalize_session(council_session, "reject", all_votes)

    # ------------------------------------------------------------------
    # Individual agent reviews
    # ------------------------------------------------------------------

    def _run_agent_review(
        self,
        agent_name: str,
        file_path: str,
        code_content: str,
        session_id: str,
        round_num: int,
    ) -> dict:
        """Run a single agent's review via Claude Code CLI."""
        role = AGENT_ROLES.get(agent_name)
        if not role:
            return {"agent_role": agent_name, "vote": "approve", "findings": []}

        prompt = get_review_prompt(role, file_path, code_content)

        logger.info(
            f"Running {role.title} review",
            extra={"extra_data": {
                "agent": agent_name,
                "session": session_id,
                "round": round_num,
            }},
        )

        result = self.claude_code.implement(prompt, None)

        # Parse the review response
        review = self._parse_review_response(result, agent_name, role)

        # Record the vote
        vote_record = CouncilVote(
            id=str(uuid.uuid4()),
            session_id=session_id,
            agent_role=agent_name,
            round_number=round_num,
            vote=review.get("vote", "revise"),
            confidence=review.get("confidence", 0.0),
            findings=json.dumps(review.get("findings", [])),
            suggested_fixes=json.dumps(
                [f.get("fix", "") for f in review.get("findings", []) if f.get("fix")]
            ),
        )
        self.session.add(vote_record)
        self.session.commit()

        review["agent_role"] = agent_name
        review["agent_title"] = role.title
        review["findings_json"] = json.dumps(review.get("findings", []))

        return review

    def _run_quality_gate(
        self,
        file_path: str,
        code_content: str,
        previous_reviews: list[dict],
        session_id: str,
        round_num: int,
    ) -> dict:
        """Run the Quality Gate final review with all prior reviews as context."""
        role = AGENT_ROLES["quality_gate"]

        prompt = get_review_prompt(role, file_path, code_content, previous_reviews)

        result = self.claude_code.implement(prompt, None)
        review = self._parse_review_response(result, "quality_gate", role)

        # Record vote
        vote_record = CouncilVote(
            id=str(uuid.uuid4()),
            session_id=session_id,
            agent_role="quality_gate",
            round_number=round_num,
            vote=review.get("vote", "revise"),
            confidence=review.get("confidence", 0.0),
            findings=json.dumps(review.get("findings", review.get("synthesis", {}))),
        )
        self.session.add(vote_record)
        self.session.commit()

        review["agent_role"] = "quality_gate"
        review["agent_title"] = role.title

        return review

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_review_response(
        self, cli_result: dict, agent_name: str, role: AgentRole,
    ) -> dict:
        """Parse a Claude Code CLI response into a structured review dict."""
        if not cli_result.get("success"):
            logger.warning(
                f"Agent {agent_name} CLI call failed",
                extra={"extra_data": {"error": str(cli_result.get("output", ""))[:200]}},
            )
            return {
                "vote": "revise",
                "confidence": 0.0,
                "findings": [],
                "summary": f"Agent {agent_name} failed to respond",
            }

        output = cli_result.get("output", "")
        if isinstance(output, dict):
            text = output.get("result", json.dumps(output))
        else:
            text = str(output)

        # Try to extract JSON from response
        try:
            # Look for JSON object
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                review = json.loads(text[start:end])
                # Normalize vote
                vote = review.get("vote", "revise").lower()
                if vote not in ("approve", "reject", "revise"):
                    vote = "revise"
                review["vote"] = vote
                return review
        except json.JSONDecodeError:
            pass

        # Fallback: treat as free-text review, default to revise
        return {
            "vote": "revise",
            "confidence": 0.3,
            "findings": [{"type": "parse_error", "description": "Could not parse structured response"}],
            "summary": text[:500] if text else "No response",
        }

    # ------------------------------------------------------------------
    # Consensus evaluation
    # ------------------------------------------------------------------

    def _evaluate_consensus(
        self, reviews: list[dict], gate_review: dict,
    ) -> str:
        """Evaluate whether consensus has been reached.

        Rules:
        1. Any veto from security_auditor or red_team → reject
        2. Quality Gate vote is the primary decision
        3. If Quality Gate says approve, need >= required_approvals from others
        4. Otherwise, follow Quality Gate's decision
        """
        # Check vetoes
        for review in reviews:
            agent = review.get("agent_role", "")
            role = AGENT_ROLES.get(agent)
            if role and role.veto_power and review.get("veto"):
                logger.warning(
                    f"Veto exercised by {agent}",
                    extra={"extra_data": {
                        "agent": agent,
                        "reason": review.get("veto_reason", ""),
                    }},
                )
                return "reject"

        gate_vote = gate_review.get("vote", "revise")

        if gate_vote == "reject":
            return "reject"

        if gate_vote == "approve":
            # Count approvals from specialist agents
            approvals = sum(1 for r in reviews if r.get("vote") == "approve")
            # Quality gate counts as one more
            if approvals + 1 >= self.required_approvals:
                return "approve"
            else:
                return "revise"

        return "revise"

    def _consolidate_fixes(
        self, reviews: list[dict], gate_review: dict,
    ) -> str:
        """Consolidate all fix suggestions from reviews into revision instructions."""
        parts = []

        for review in reviews:
            agent = review.get("agent_title", review.get("agent_role", "unknown"))
            findings = review.get("findings", [])
            critical_high = [
                f for f in findings
                if isinstance(f, dict) and f.get("severity") in ("critical", "high")
            ]
            if critical_high:
                parts.append(f"## {agent} ({len(critical_high)} critical/high issues)")
                for f in critical_high:
                    desc = f.get("description", "")
                    fix = f.get("fix", "")
                    parts.append(f"- {desc}")
                    if fix:
                        parts.append(f"  FIX: {fix}")

        gate_instructions = gate_review.get("revision_instructions", "")
        if gate_instructions:
            parts.append(f"\n## Quality Gate Instructions\n{gate_instructions}")

        return "\n".join(parts) if parts else "Address all review feedback."

    # ------------------------------------------------------------------
    # Session finalization
    # ------------------------------------------------------------------

    def _finalize_session(
        self,
        council_session: CouncilSession,
        decision: str,
        all_votes: list[dict],
    ) -> dict:
        """Finalize a council session with the given decision."""
        council_session.consensus_reached = decision in ("approve", "reject")
        council_session.consensus_action = decision
        council_session.completed_at = datetime.now(timezone.utc)
        self.session.commit()

        logger.info(
            f"Council session finalized: {decision}",
            extra={"extra_data": {
                "session_id": council_session.id,
                "layer": council_session.layer_name,
                "rounds": council_session.total_rounds,
                "decision": decision,
            }},
        )

        return {
            "approved": decision == "approve",
            "session_id": council_session.id,
            "rounds": council_session.total_rounds,
            "final_vote": decision,
            "all_votes": [
                {
                    "agent": v.get("agent_role"),
                    "vote": v.get("vote"),
                    "confidence": v.get("confidence"),
                }
                for v in all_votes
            ],
        }

    # ------------------------------------------------------------------
    # Status / reporting
    # ------------------------------------------------------------------

    def get_session_history(self, limit: int = 20) -> list[dict]:
        """Return recent council session summaries."""
        sessions = (
            self.session.query(CouncilSession)
            .order_by(CouncilSession.started_at.desc())
            .limit(limit)
            .all()
        )
        results = []
        for s in sessions:
            votes = (
                self.session.query(CouncilVote)
                .filter_by(session_id=s.id)
                .all()
            )
            results.append({
                "session_id": s.id,
                "layer": s.layer_name,
                "decision": s.consensus_action,
                "rounds": s.total_rounds,
                "started_at": str(s.started_at),
                "completed_at": str(s.completed_at) if s.completed_at else None,
                "votes": [
                    {"agent": v.agent_role, "vote": v.vote, "round": v.round_number}
                    for v in votes
                ],
            })
        return results
