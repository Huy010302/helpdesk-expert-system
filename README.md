# Hệ chuyên gia phân loại & định tuyến ticket Helpdesk CNTT

Prototype học thuật cho Tổ CNTT bệnh viện.

## Điểm đã sửa trong V2
- `Mạng chậm / Mất mạng / Không Internet` được phân loại **Network** ngay cả khi `affected_system = Other`.
- Không còn fallback sai `không khớp luật -> Software`; thay bằng **Unclassified / NEEDS_MORE_INFORMATION**.
- `scope` không cho nhập thủ công. Hệ thống **tự suy ra từ affected_users** để tránh fact mâu thuẫn.
- Streamlit đã đổi `use_container_width` sang `width="stretch"` để hết cảnh báo deprecated.
- Thêm `Internet` vào danh sách hệ thống.
- Thêm tải lịch sử CSV.
- Tăng bộ kiểm thử từ 18 lên **20 test case**, có regression test cho lỗi đã phát hiện trên UI.

## Chức năng
- Working Memory từ form có cấu trúc.
- 45 luật production rule IF-THEN.
- Forward chaining theo 5 stage.
- Conflict resolution bằng salience và rank.
- Một nhóm chính + tối đa một nhóm liên quan.
- Impact/Urgency -> P1/P2/P3/P4.
- Routing: Helpdesk / Network / System / Application / Security.
- SLA phản hồi cấu hình đồ án: P1 15 phút; P2 30 phút; P3 4 giờ; P4 1 ngày làm việc.
- Escalation cho P1 và Security Incident.
- Explanation Facility lưu toàn bộ fired rules.
- SQLite lưu lịch sử.

## Cài đặt trên Windows PowerShell
Trong thư mục project:

```powershell
python -m ensurepip --upgrade
python -m pip install -r requirements.txt
```

## Chạy test

```powershell
python test_cases.py
```

Kết quả mong đợi:

```text
RESULT: 20/20 passed
SCOPE DERIVATION: PASS
REGRESSION TESTS: PASS
```

## Chạy giao diện

```powershell
python -m streamlit run app.py
```

Sau đó mở `http://localhost:8501`.

## Test nhanh lỗi đã sửa
- Hệ thống/thiết bị: `Other`
- Triệu chứng: `Mạng chậm`
- Số người ảnh hưởng: `1`
- Không có workaround

Kết quả mong đợi:
- Nhóm chính: `Network`
- Priority: `P3 - Medium`
- Đội xử lý: `Network`
- SLA: `4 giờ`
- Trace có luật `C01`.

## Lưu ý học thuật
ITIL 4 được sử dụng làm khung Incident Management. Ma trận Impact/Urgency, ngưỡng số người bị ảnh hưởng và SLA trong prototype là cấu hình giả định của đồ án/bệnh viện mẫu, không phải các giá trị bắt buộc của ITIL.
