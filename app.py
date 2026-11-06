import streamlit as st
import pandas as pd

from models import TicketFacts, derive_scope
from expert_system import HelpdeskExpertSystem
from database import save_ticket, recent_tickets, init_db, get_next_ticket_id
from knowledge_base import build_rules


st.set_page_config(
    page_title="Helpdesk Expert System",
    page_icon="🎫",
    layout="wide",
)
init_db()
engine = HelpdeskExpertSystem()

SYSTEMS = [
    "Workstation",
    "Network",
    "Internet",
    "Wi-Fi",
    "Printer",
    "Account",
    "Email",
    "HIS",
    "PACS",
    "LIS",
    "EMR",
    "File Server",
    "Other",
]

SYMPTOMS = {
    "Mất mạng": "network_down",
    "Mạng chậm": "network_slow",
    "Không Internet": "no_internet",
    "Tài khoản bị khóa": "account_locked",
    "Reset mật khẩu": "password_reset",
    "Không đăng nhập": "cannot_login",
    "Không gửi email": "cannot_send_email",
    "Không nhận email": "cannot_receive_email",
    "Hộp thư đầy": "mailbox_full",
    "Thiết bị không lên nguồn": "device_no_power",
    "Lỗi phần cứng": "hardware_failure",
    "Lỗi thiết bị ngoại vi": "peripheral_failure",
    "Phần mềm crash": "software_crash",
    "Lỗi hệ điều hành": "os_error",
    "Yêu cầu cài phần mềm": "install_request",
    "Máy in offline": "printer_offline",
    "Không in được": "printer_not_printing",
    "Kẹt giấy": "paper_jam",
    "Ứng dụng không khả dụng": "app_unavailable",
    "Ứng dụng báo lỗi": "app_error",
    "Ứng dụng chậm": "app_slow",
    "Yêu cầu cấp quyền": "access_request",
    "Permission denied": "permission_denied",
    "Không truy cập shared folder": "share_access_denied",
    "Email đáng ngờ": "suspicious_email",
    "Nghi phishing": "phishing_suspected",
    "Antivirus/Malware alert": "malware_alert",
    "Truy cập trái phép": "unauthorized_access",
    "Dữ liệu bị mã hóa": "data_encrypted",
    "Xuất hiện ransom note": "ransom_note",
}

SCOPE_LABELS = {
    "single_user": "1 người",
    "multi_user": "2–9 người",
    "department": "10–49 người (quy mô khoa/phòng)",
    "hospital": "≥50 người (quy mô bệnh viện)",
}

st.title("🎫 Hệ chuyên gia phân loại & định tuyến ticket Helpdesk CNTT")
st.caption(
    "Prototype học thuật cho Tổ CNTT bệnh viện — phân loại, priority, routing, SLA và explanation trace."
)


tab1, tab2, tab3 = st.tabs(
    ["Phân tích ticket", "Lịch sử SQLite", "Rule Base (45 luật)"]
)

with tab1:
    next_ticket_id = get_next_ticket_id()
    with st.form("ticket_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            ticket_id = st.text_input(
                "Mã ticket",
                value=next_ticket_id,
                disabled=True,
                key=f"ticket_id_{next_ticket_id}",
                help="Mã được tự động sinh từ lịch sử SQLite và không cần nhập tay.",
            )
            department = st.text_input(
                "Khoa/phòng yêu cầu", value="Khoa Khám bệnh"
            )
            system = st.selectbox("Hệ thống/thiết bị bị ảnh hưởng", SYSTEMS)

        with c2:
            title = st.text_input("Tiêu đề", value="Không truy cập được hệ thống")
            affected_users = st.number_input(
                "Số người bị ảnh hưởng", min_value=1, max_value=10000, value=1
            )
            st.caption(
                "Phạm vi không nhập thủ công; hệ thống tự suy ra từ số người bị ảnh hưởng."
            )
            service_down = st.checkbox("Dịch vụ ngừng hoàn toàn")
            workaround = st.checkbox("Có workaround/phương án thay thế")
            critical_system = st.checkbox("Đánh dấu hệ thống trọng yếu")

        with c3:
            vip = st.checkbox("VIP/user quan trọng")
            deadline = st.checkbox("Có deadline công việc gấp")
            clinical = st.checkbox("Ảnh hưởng luồng công việc lâm sàng")
            patients_waiting = st.checkbox("Đang có bệnh nhân chờ xử lý")
            security_active = st.checkbox("Dấu hiệu Security đang diễn ra")

        chosen = st.multiselect(
            "Triệu chứng/dấu hiệu quan sát được", list(SYMPTOMS.keys())
        )
        description = st.text_area(
            "Mô tả bổ sung (chưa dùng để suy diễn ở bản hiện tại)"
        )
        submitted = st.form_submit_button("Phân tích ticket", type="primary")

    if submitted:
        facts = TicketFacts(
            ticket_id=ticket_id.strip() or "HD-UNKNOWN",
            requester_department=department.strip(),
            title=title.strip(),
            description=description.strip(),
            affected_system=system,
            symptoms=[SYMPTOMS[x] for x in chosen],
            affected_users=int(affected_users),
            service_down=service_down,
            workaround_available=workaround,
            vip_user=vip,
            deadline_critical=deadline,
            critical_system=critical_system,
            clinical_workflow_affected=clinical,
            patients_waiting=patients_waiting,
            security_active=security_active,
        )
        result = engine.classify(facts)
        try:
            save_ticket(facts, result)
        except ValueError as exc:
            st.error(str(exc))
            st.stop()

        st.success(f"Đã phân tích và lưu {facts.ticket_id} vào SQLite.")

        a, b, c, d = st.columns(4)
        a.metric("Nhóm chính", result["primary_category"])
        b.metric("Priority", f"{result['priority']} - {result['priority_label']}")
        c.metric("Đội xử lý", result["assigned_team"])
        d.metric("SLA phản hồi", result["sla_response"])

        if result["classification_status"] == "NEEDS_MORE_INFORMATION":
            st.warning(
                "Chưa đủ fact để xác định nhóm kỹ thuật. Ticket được giữ tại Helpdesk và cần bổ sung thông tin."
            )

        st.write(f"**Nhóm liên quan:** {result['related_category'] or 'Không có'}")
        st.write(f"**Impact / Urgency:** {result['impact']} / {result['urgency']}")
        scope = result["working_memory"]["scope"]
        st.write(f"**Phạm vi suy ra:** {SCOPE_LABELS.get(scope, scope)}")

        if result["category_candidates"]:
            st.write(
                "**Ứng viên phân loại:** "
                + ", ".join(
                    f"{x['category']} ({x['rule_id']})"
                    for x in result["category_candidates"]
                )
            )

        if result["escalations"]:
            st.error(
                "\n".join(
                    ["Escalation:"] + [f"• {x}" for x in result["escalations"]]
                )
            )

        st.subheader("Đề xuất xử lý ban đầu")
        for i, item in enumerate(result["recommendations"], 1):
            st.write(f"{i}. {item}")

        st.subheader("Explanation Facility — Rule Trace")
        trace_df = pd.DataFrame(
            [
                {
                    "Rule": t.rule_id,
                    "Stage": t.stage,
                    "Tên luật": t.rule_name,
                    "Salience": t.salience,
                    "Facts khớp": str(t.matched_facts),
                    "Kết quả": str(t.produced_facts),
                }
                for t in result["trace"]
            ]
        )
        st.dataframe(trace_df, width="stretch", hide_index=True)

with tab2:
    rows = recent_tickets(100)
    history_df = pd.DataFrame(rows)
    st.dataframe(history_df, width="stretch", hide_index=True)
    if not history_df.empty:
        st.download_button(
            "Tải lịch sử CSV",
            history_df.to_csv(index=False).encode("utf-8-sig"),
            file_name="helpdesk_ticket_history.csv",
            mime="text/csv",
        )

with tab3:
    rules = build_rules()
    rules_df = pd.DataFrame(
        [
            {
                "ID": r.rule_id,
                "Stage": r.stage,
                "Tên luật": r.name,
                "Salience": r.salience,
                "Giải thích": r.explanation,
            }
            for r in rules
        ]
    )
    st.dataframe(rules_df, width="stretch", hide_index=True)
