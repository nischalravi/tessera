from sqlalchemy.orm import Session

from .models import AuditLog


def audit(session: Session, actor: str, action: str, **detail) -> None:
    session.add(AuditLog(actor=actor, action=action, detail=detail))
