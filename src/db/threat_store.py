"""CRUD operations for threat intelligence data."""

import uuid

from sqlalchemy.orm import Session

from src.db.models import ClassifiedThreat, RawThreat


class ThreatStore:
    def __init__(self, session: Session):
        self.session = session

    def add_raw_threat(
        self, source: str, title: str, summary: str,
        source_url: str | None = None, raw_content: str | None = None,
    ) -> RawThreat | None:
        """Add a raw threat, skip if source_url already exists."""
        if source_url:
            existing = self.session.query(RawThreat).filter_by(source_url=source_url).first()
            if existing:
                return None

        threat = RawThreat(
            id=str(uuid.uuid4()),
            source=source,
            source_url=source_url,
            title=title,
            summary=summary,
            raw_content=raw_content,
        )
        self.session.add(threat)
        self.session.commit()
        return threat

    def get_unclassified_threats(self) -> list[RawThreat]:
        """Get raw threats that haven't been classified yet."""
        classified_ids = (
            self.session.query(ClassifiedThreat.raw_threat_id)
            .subquery()
        )
        return (
            self.session.query(RawThreat)
            .filter(~RawThreat.id.in_(classified_ids))
            .order_by(RawThreat.collected_at.desc())
            .all()
        )

    def add_classified_threat(self, **kwargs) -> ClassifiedThreat:
        threat = ClassifiedThreat(id=str(uuid.uuid4()), **kwargs)
        self.session.add(threat)
        self.session.commit()
        return threat

    def get_threats_by_status(self, status: str) -> list[ClassifiedThreat]:
        return (
            self.session.query(ClassifiedThreat)
            .filter_by(status=status)
            .order_by(ClassifiedThreat.classified_at.desc())
            .all()
        )

    def update_threat_status(self, threat_id: str, status: str) -> None:
        threat = self.session.query(ClassifiedThreat).filter_by(id=threat_id).first()
        if threat:
            threat.status = status
            self.session.commit()

    def get_all_classified(self) -> list[ClassifiedThreat]:
        return (
            self.session.query(ClassifiedThreat)
            .order_by(ClassifiedThreat.classified_at.desc())
            .all()
        )
