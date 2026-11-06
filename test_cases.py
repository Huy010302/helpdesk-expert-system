from models import TicketFacts, derive_scope
from expert_system import HelpdeskExpertSystem

E = HelpdeskExpertSystem()


def T(case_id, system, symptoms, users=1, **kwargs):
    return TicketFacts(
        ticket_id=case_id,
        affected_system=system,
        symptoms=symptoms,
        affected_users=users,
        **kwargs,
    )


CASES = [
    ("TC01", T("TC01", "Workstation", ["network_down"], workaround_available=False), ("Network", "P3", "Network")),
    ("TC02", T("TC02", "Network", ["network_down"], users=25, service_down=True, deadline_critical=True), ("Network", "P1", "Network")),
    ("TC03", T("TC03", "Account", ["account_locked"], workaround_available=False), ("Account", "P3", "System")),
    ("TC04", T("TC04", "Account", ["password_reset"], workaround_available=True), ("Account", "P4", "System")),
    ("TC05", T("TC05", "Email", ["cannot_receive_email"], users=15, workaround_available=False), ("Email", "P2", "System")),
    ("TC06", T("TC06", "Workstation", ["device_no_power"], workaround_available=False), ("Hardware", "P3", "Helpdesk")),
    ("TC07", T("TC07", "Printer", ["printer_not_printing"], clinical_workflow_affected=True, patients_waiting=True, service_down=True), ("Printer", "P1", "Helpdesk")),
    ("TC08", T("TC08", "Workstation", ["software_crash"], workaround_available=False), ("Software", "P3", "Helpdesk")),
    ("TC09", T("TC09", "HIS", ["app_unavailable"], users=20, service_down=True, clinical_workflow_affected=True, patients_waiting=True), ("Business Application", "P1", "Application")),
    ("TC10", T("TC10", "PACS", ["app_slow"], users=6, workaround_available=False, clinical_workflow_affected=True, patients_waiting=True), ("Business Application", "P1", "Application")),
    ("TC11", T("TC11", "File Server", ["access_request"], workaround_available=True), ("Access/Permission", "P4", "System")),
    ("TC12", T("TC12", "File Server", ["permission_denied"], users=4, deadline_critical=True, workaround_available=False), ("Access/Permission", "P2", "System")),
    ("TC13", T("TC13", "Email", ["suspicious_email"], workaround_available=True), ("Security Incident", "P4", "Security")),
    ("TC14", T("TC14", "Workstation", ["malware_alert"], security_active=True, workaround_available=False), ("Security Incident", "P3", "Security")),
    ("TC15", T("TC15", "File Server", ["data_encrypted", "ransom_note"], users=50, service_down=True, critical_system=True, security_active=True), ("Security Incident", "P1", "Security")),
    ("TC16", T("TC16", "Workstation", ["hardware_failure", "malware_alert"], security_active=True), ("Security Incident", "P3", "Security")),
    ("TC17", T("TC17", "HIS", ["app_error", "cannot_login", "account_locked"], critical_system=True, service_down=False, workaround_available=False), ("Business Application", "P3", "Application")),
    ("TC18", T("TC18", "Printer", ["printer_offline", "network_down"], workaround_available=True), ("Printer", "P4", "Helpdesk")),
    # Regression: đúng ca phát hiện từ giao diện của người dùng.
    ("TC19", T("TC19", "Other", ["network_slow"], workaround_available=False), ("Network", "P3", "Network")),
    # Không có symptom -> không được mặc định sai sang Software.
    ("TC20", T("TC20", "Other", [], workaround_available=False), ("Unclassified", "P3", "Helpdesk")),
]


def run():
    passed_count = 0
    for name, ticket, expected in CASES:
        result = E.classify(ticket)
        got = (
            result["primary_category"],
            result["priority"],
            result["assigned_team"],
        )
        passed = got == expected
        passed_count += int(passed)
        print(f"{name}: expected={expected}, got={got} -> {'PASS' if passed else 'FAIL'}")
        if name in {"TC16", "TC17", "TC18", "TC19", "TC20"}:
            print(
                "   scope=",
                result["working_memory"]["scope"],
                "related=",
                result["related_category"],
                "candidates=",
                [(x["category"], x["rule_id"]) for x in result["category_candidates"]],
            )

    # Kiểm tra derivation scope độc lập.
    assert derive_scope(1) == "single_user"
    assert derive_scope(2) == "multi_user"
    assert derive_scope(9) == "multi_user"
    assert derive_scope(10) == "department"
    assert derive_scope(49) == "department"
    assert derive_scope(50) == "hospital"

    # Regression assertions rõ ràng.
    r19 = E.classify(T("REG-NET", "Other", ["network_slow"]))
    assert r19["primary_category"] == "Network"
    assert any(t.rule_id == "C01" for t in r19["trace"])

    r20 = E.classify(T("REG-UNKNOWN", "Other", []))
    assert r20["primary_category"] == "Unclassified"
    assert r20["classification_status"] == "NEEDS_MORE_INFORMATION"

    print(f"RESULT: {passed_count}/{len(CASES)} passed")
    print("SCOPE DERIVATION: PASS")
    print("REGRESSION TESTS: PASS")
    assert passed_count == len(CASES)


if __name__ == "__main__":
    run()
