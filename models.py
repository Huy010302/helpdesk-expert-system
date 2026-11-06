from dataclasses import dataclass, asdict
from typing import Any, Dict, List


CLINICAL_SYSTEMS = {"HIS", "PACS", "LIS", "EMR"}


def derive_scope(affected_users: int) -> str:
    """Suy ra phạm vi vận hành từ số người bị ảnh hưởng (quy ước của đồ án)."""
    n = max(1, int(affected_users or 1))
    if n == 1:
        return "single_user"
    if n <= 9:
        return "multi_user"
    if n <= 49:
        return "department"
    return "hospital"


@dataclass
class TicketFacts:
    ticket_id: str
    requester_department: str = ""
    title: str = ""
    description: str = ""
    affected_system: str = "Workstation"
    symptoms: List[str] | None = None
    affected_users: int = 1
    service_down: bool = False
    workaround_available: bool = False
    vip_user: bool = False
    deadline_critical: bool = False
    critical_system: bool = False
    clinical_workflow_affected: bool = False
    patients_waiting: bool = False
    security_active: bool = False

    def to_working_memory(self) -> Dict[str, Any]:
        d = asdict(self)
        d["affected_users"] = max(1, int(self.affected_users or 1))
        d["scope"] = derive_scope(d["affected_users"])
        d["symptoms"] = set(self.symptoms or [])
        d["critical_system"] = bool(
            self.critical_system or self.affected_system in CLINICAL_SYSTEMS
        )
        return d


@dataclass
class TraceEntry:
    stage: str
    rule_id: str
    rule_name: str
    salience: int
    matched_facts: Dict[str, Any]
    produced_facts: Dict[str, Any]
    explanation: str


@dataclass
class Rule:
    rule_id: str
    stage: str
    name: str
    salience: int
    condition: Any
    action: Any
    explanation: str
