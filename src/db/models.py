"""SQLAlchemy models for threat intelligence and test results databases."""

import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class RawThreat(Base):
    __tablename__ = "raw_threats"

    id = Column(String, primary_key=True)
    source = Column(String, nullable=False)  # arxiv, rss, web
    source_url = Column(String, unique=True)
    title = Column(String, nullable=False)
    summary = Column(Text)
    raw_content = Column(Text)
    collected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ClassifiedThreat(Base):
    __tablename__ = "classified_threats"

    id = Column(String, primary_key=True)
    raw_threat_id = Column(String, nullable=False)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    attack_vector = Column(Text)
    affected_components = Column(Text)  # JSON array
    defense_plan = Column(Text)  # JSON
    test_payloads = Column(Text)  # JSON array
    covered_by_layers = Column(Text)  # JSON array
    status = Column(String, default="new")
    classified_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def get_affected_components(self) -> list[str]:
        return json.loads(self.affected_components) if self.affected_components else []

    def get_test_payloads(self) -> list[str]:
        return json.loads(self.test_payloads) if self.test_payloads else []

    def get_covered_by_layers(self) -> list[str]:
        return json.loads(self.covered_by_layers) if self.covered_by_layers else []


class DefenseLayer(Base):
    __tablename__ = "defense_layers"

    name = Column(String, primary_key=True)
    module_path = Column(String, nullable=False)
    priority = Column(Integer, nullable=False)
    threat_categories = Column(Text)  # JSON array
    detection_rules = Column(Text)  # JSON array
    effectiveness_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def get_threat_categories(self) -> list[str]:
        return json.loads(self.threat_categories) if self.threat_categories else []


class TestRun(Base):
    __tablename__ = "test_runs"

    id = Column(String, primary_key=True)
    threat_id = Column(String, nullable=False)
    victim_profile = Column(String, nullable=False)
    defense_layers_active = Column(Text)  # JSON array
    detection_rate = Column(Float)
    prevention_rate = Column(Float)
    exfiltration_rate = Column(Float)
    false_positive_rate = Column(Float)
    latency_overhead_ms = Column(Float)
    details = Column(Text)  # JSON
    run_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Robustness & Resilience Models
# ---------------------------------------------------------------------------


class VariantGroup(Base):
    """Tracks groups of variant twin implementations for the same defense."""
    __tablename__ = "variant_groups"

    id = Column(String, primary_key=True)
    threat_category = Column(String, nullable=False)
    description = Column(Text)
    active_variant = Column(String)  # name of the currently active variant layer
    rotation_strategy = Column(String, default="round_robin")  # round_robin | best_performer | random
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class VariantMember(Base):
    """A single variant implementation within a variant group."""
    __tablename__ = "variant_members"

    id = Column(String, primary_key=True)
    group_id = Column(String, nullable=False)
    layer_name = Column(String, nullable=False)
    implementation_strategy = Column(String)  # e.g. "regex", "ml_heuristic", "llm_based"
    file_path = Column(String)
    effectiveness_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class StagingRecord(Base):
    """Tracks defense layers in staging evaluation before production promotion."""
    __tablename__ = "staging_records"

    id = Column(String, primary_key=True)
    layer_name = Column(String, nullable=False)
    stage = Column(String, default="shadow")  # shadow | canary | staged_rollout | production
    entered_stage_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    min_evaluation_hours = Column(Integer, default=24)
    test_runs_required = Column(Integer, default=10)
    test_runs_completed = Column(Integer, default=0)
    detection_rate_avg = Column(Float, default=0.0)
    false_positive_rate_avg = Column(Float, default=0.0)
    promotion_threshold = Column(Float, default=0.7)  # min effectiveness to promote
    rejection_threshold = Column(Float, default=0.3)   # below this -> reject
    promoted = Column(Boolean, default=False)
    rejected = Column(Boolean, default=False)
    rejection_reason = Column(Text)


class IntegrityRecord(Base):
    """Stores integrity hashes and audit results for defense layer files."""
    __tablename__ = "integrity_records"

    id = Column(String, primary_key=True)
    layer_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    sha256_hash = Column(String, nullable=False)
    verified_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_tampered = Column(Boolean, default=False)
    audit_result = Column(Text)  # JSON: vulnerability scan results
    audit_score = Column(Float, default=1.0)  # 1.0 = clean, 0.0 = critical issues


class ReviewRecord(Base):
    """Tracks periodic Claude Code CLI reviews of defense layers."""
    __tablename__ = "review_records"

    id = Column(String, primary_key=True)
    layer_name = Column(String, nullable=False)
    review_type = Column(String, nullable=False)  # security_audit | code_quality | effectiveness | regression
    findings = Column(Text)  # JSON array of findings
    severity = Column(String)  # info | low | medium | high | critical
    action_taken = Column(Text)  # JSON: what was done (patched, flagged, etc.)
    reviewed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AdaptationLog(Base):
    """Records self-learning adaptations: threshold changes, pattern updates."""
    __tablename__ = "adaptation_logs"

    id = Column(String, primary_key=True)
    layer_name = Column(String, nullable=False)
    adaptation_type = Column(String, nullable=False)  # threshold_tune | pattern_add | pattern_remove | weight_adjust
    old_value = Column(Text)  # JSON
    new_value = Column(Text)  # JSON
    reason = Column(Text)
    test_improvement = Column(Float)  # delta in effectiveness after adaptation
    applied_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class MetamorphicEvent(Base):
    """Records pattern rotation/evolution events for metamorphic defenses."""
    __tablename__ = "metamorphic_events"

    id = Column(String, primary_key=True)
    layer_name = Column(String, nullable=False)
    event_type = Column(String, nullable=False)  # pattern_rotate | signature_evolve | structure_morph
    patterns_before = Column(Text)  # JSON: old pattern set fingerprint
    patterns_after = Column(Text)   # JSON: new pattern set fingerprint
    effectiveness_before = Column(Float)
    effectiveness_after = Column(Float)
    rotated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_db(db_path: str) -> sessionmaker:
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def get_session(session_factory: sessionmaker) -> Session:
    return session_factory()
