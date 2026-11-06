import sqlite3, json, re
from pathlib import Path

DB_PATH = Path(__file__).with_name("helpdesk_history.db")


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ticket_id TEXT,
            title TEXT,
            requester_department TEXT,
            primary_category TEXT,
            related_category TEXT,
            impact TEXT,
            urgency TEXT,
            priority TEXT,
            assigned_team TEXT,
            sla_response TEXT,
            payload_json TEXT,
            result_json TEXT
        )""")


def get_next_ticket_id() -> str:
    """Sinh mã ticket tự động dạng HD-001, HD-002, ... từ dữ liệu SQLite.

    Chỉ xét các mã đúng mẫu HD-<số>. Các mã cũ/khác định dạng sẽ bị bỏ qua.
    Việc đọc trực tiếp database giúp bộ đếm vẫn đúng sau khi restart ứng dụng.
    """
    init_db()
    max_no = 0
    pattern = re.compile(r"^HD-(\d+)$", re.IGNORECASE)
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT ticket_id FROM tickets WHERE ticket_id IS NOT NULL").fetchall()
    for (ticket_id,) in rows:
        m = pattern.match(str(ticket_id).strip())
        if m:
            max_no = max(max_no, int(m.group(1)))
    return f"HD-{max_no + 1:03d}"


def save_ticket(ticket, result):
    init_db()
    payload = ticket.to_working_memory()
    payload["symptoms"] = sorted(payload.get("symptoms", []))
    serial_result = dict(result)
    serial_result["trace"] = [t.__dict__ for t in result["trace"]]
    with sqlite3.connect(DB_PATH) as con:
        # Bảo vệ khỏi trùng mã do thao tác lặp/đa tab.
        exists = con.execute(
            "SELECT 1 FROM tickets WHERE ticket_id = ? LIMIT 1",
            (ticket.ticket_id,),
        ).fetchone()
        if exists:
            raise ValueError(f"Ticket ID {ticket.ticket_id} đã tồn tại. Hãy tải lại trang để lấy mã mới.")

        con.execute("""INSERT INTO tickets(
            ticket_id,title,requester_department,primary_category,related_category,
            impact,urgency,priority,assigned_team,sla_response,payload_json,result_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",(
            ticket.ticket_id,ticket.title,ticket.requester_department,result["primary_category"],
            result["related_category"],result["impact"],result["urgency"],result["priority"],
            result["assigned_team"],result["sla_response"],json.dumps(payload,ensure_ascii=False),
            json.dumps(serial_result,ensure_ascii=False,default=str)))


def recent_tickets(limit=100):
    init_db()
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""SELECT created_at,ticket_id,title,requester_department,
            primary_category,related_category,impact,urgency,priority,assigned_team,sla_response
            FROM tickets ORDER BY id DESC LIMIT ?""",(limit,)).fetchall()
    return [dict(r) for r in rows]
