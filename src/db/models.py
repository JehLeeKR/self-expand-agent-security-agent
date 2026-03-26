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


def init_db(db_path: str) -> sessionmaker:
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def get_session(session_factory: sessionmaker) -> Session:
    return session_factory()
