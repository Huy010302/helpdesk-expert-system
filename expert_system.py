from typing import Any, Dict, List
from models import TicketFacts, TraceEntry
from knowledge_base import (
    build_rules,
    CATEGORY_ORDER,
    SEVERITY_RANK,
    PRIORITY_RANK,
    SLA,
    RESPONSE_PLAYBOOKS,
)


class HelpdeskExpertSystem:
    STAGES = ["classification", "impact_urgency", "priority", "routing", "escalation"]

    def __init__(self):
        self.rules = build_rules()

    def _apply_produced(
        self,
        wm: Dict[str, Any],
        produced: Dict[str, Any],
        rule,
        category_candidates,
        escalations,
    ):
        if "candidate_category" in produced:
            cat = produced["candidate_category"]
            category_candidates.append(
                {
                    "category": cat,
                    "rule_id": rule.rule_id,
                    "salience": rule.salience,
                    "rank": CATEGORY_ORDER[cat],
                }
            )
            return

        if "impact" in produced:
            new = produced["impact"]
            old = wm.get("impact")
            if old is None or SEVERITY_RANK[new] > SEVERITY_RANK[old]:
                wm["impact"] = new
            return

        if "urgency" in produced:
            new = produced["urgency"]
            old = wm.get("urgency")
            if old is None or SEVERITY_RANK[new] > SEVERITY_RANK[old]:
                wm["urgency"] = new
            return

        if "priority" in produced:
            new = produced["priority"]
            old = wm.get("priority")
            if old is None or PRIORITY_RANK[new] > PRIORITY_RANK[old]:
                wm["priority"] = new
            return

        if "escalation" in produced:
            if produced["escalation"] not in escalations:
                escalations.append(produced["escalation"])
            return

        wm.update(produced)

    def _run_stage(self, stage, wm, trace, fired, category_candidates, escalations):
        """Forward chaining trong một stage, agenda ưu tiên salience giảm dần."""
        while True:
            agenda = []
            for rule in self.rules:
                if rule.stage != stage or rule.rule_id in fired:
                    continue
                ok, facts = rule.condition(wm)
                if ok:
                    agenda.append((rule.salience, rule.rule_id, rule, facts))

            if not agenda:
                break

            agenda.sort(key=lambda x: (-x[0], x[1]))
            _, _, rule, facts = agenda[0]
            produced = rule.action(wm)
            self._apply_produced(
                wm, produced, rule, category_candidates, escalations
            )
            fired.add(rule.rule_id)
            trace.append(
                TraceEntry(
                    stage,
                    rule.rule_id,
                    rule.name,
                    rule.salience,
                    facts,
                    produced,
                    rule.explanation,
                )
            )

    def classify(self, ticket: TicketFacts) -> Dict[str, Any]:
        wm = ticket.to_working_memory()
        trace: List[TraceEntry] = []
        fired = set()
        category_candidates = []
        escalations = []
        decision_notes = []

        self._run_stage(
            "classification", wm, trace, fired, category_candidates, escalations
        )

        if category_candidates:
            # Mỗi category chỉ giữ candidate mạnh nhất; salience là tiêu chí chính,
            # CATEGORY_ORDER chỉ dùng để phá hòa xác định (deterministic tie-break).
            unique = {}
            for candidate in category_candidates:
                old = unique.get(candidate["category"])
                if old is None or (candidate["salience"], candidate["rank"]) > (
                    old["salience"],
                    old["rank"],
                ):
                    unique[candidate["category"]] = candidate

            ordered = sorted(
                unique.values(),
                key=lambda c: (-c["salience"], -c["rank"], c["category"]),
            )
            wm["primary_category"] = ordered[0]["category"]
            wm["related_category"] = (
                ordered[1]["category"] if len(ordered) > 1 else None
            )
            wm["classification_status"] = "CLASSIFIED"
        else:
            # Không được mặc định sang Software: thiếu fact phải được nói rõ.
            wm["primary_category"] = "Unclassified"
            wm["related_category"] = None
            wm["classification_status"] = "NEEDS_MORE_INFORMATION"
            decision_notes.append(
                "Không có luật classification nào khớp; ticket được giữ tại Helpdesk để bổ sung fact."
            )

        for stage in self.STAGES[1:]:
            self._run_stage(stage, wm, trace, fired, category_candidates, escalations)

        priority = wm.get("priority", "P3")
        category = wm.get("primary_category", "Unclassified")
        return {
            "ticket_id": ticket.ticket_id,
            "primary_category": category,
            "related_category": wm.get("related_category"),
            "classification_status": wm.get("classification_status"),
            "impact": wm.get("impact", "LOW"),
            "urgency": wm.get("urgency", "MEDIUM"),
            "priority": priority,
            "priority_label": SLA[priority]["label"],
            "sla_response": SLA[priority]["response"],
            "assigned_team": wm.get("assigned_team", "Helpdesk"),
            "escalations": escalations,
            "recommendations": RESPONSE_PLAYBOOKS.get(
                category, RESPONSE_PLAYBOOKS["Unclassified"]
            ),
            "working_memory": {
                k: (sorted(v) if isinstance(v, set) else v) for k, v in wm.items()
            },
            "category_candidates": sorted(
                category_candidates, key=lambda c: -c["salience"]
            ),
            "decision_notes": decision_notes,
            "trace": trace,
        }

    @staticmethod
    def explain(result: Dict[str, Any]) -> str:
        lines = [
            f"Ticket: {result['ticket_id']}",
            f"Trạng thái phân loại: {result['classification_status']}",
            f"Nhóm chính: {result['primary_category']}",
            f"Nhóm liên quan: {result['related_category'] or 'Không có'}",
            f"Impact/Urgency: {result['impact']} / {result['urgency']}",
            f"Priority: {result['priority']} - {result['priority_label']}",
            f"Đội xử lý: {result['assigned_team']}",
            f"SLA phản hồi (cấu hình đồ án): {result['sla_response']}",
            "",
            "Các luật đã kích hoạt:",
        ]
        for t in result["trace"]:
            lines.append(
                f"- {t.rule_id} [{t.stage}]: {t.rule_name} | facts={t.matched_facts}"
            )
        for note in result.get("decision_notes", []):
            lines.append(f"- Ghi chú quyết định: {note}")
        if result["escalations"]:
            lines.append("")
            lines.append("Escalation:")
            lines.extend([f"- {x}" for x in result["escalations"]])
        return "\n".join(lines)
