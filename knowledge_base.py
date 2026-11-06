from typing import Any, Dict, List, Tuple
from models import Rule

CATEGORY_ORDER = {
    'Security Incident': 100,
    'Business Application': 90,
    'Printer': 85,
    'Network': 80,
    'Access/Permission': 75,
    'Account': 70,
    'Email': 65,
    'Hardware': 60,
    'Software': 55,
}

SEVERITY_RANK = {'LOW':1, 'MEDIUM':2, 'HIGH':3, 'CRITICAL':4}
PRIORITY_RANK = {'P4':1, 'P3':2, 'P2':3, 'P1':4}

SLA = {
    'P1': {'response': '15 phút', 'label': 'Critical'},
    'P2': {'response': '30 phút', 'label': 'High'},
    'P3': {'response': '4 giờ', 'label': 'Medium'},
    'P4': {'response': '1 ngày làm việc', 'label': 'Low'},
}

RESPONSE_PLAYBOOKS = {
    'Unclassified': [
        'Kiểm tra lại hệ thống/thiết bị bị ảnh hưởng và chọn ít nhất một triệu chứng quan sát được.',
        'Thu thập thông báo lỗi, ảnh chụp màn hình, thời điểm xảy ra và phạm vi ảnh hưởng.',
        'Giữ ticket tại Helpdesk để bổ sung fact trước khi định tuyến sang đội chuyên trách.',
    ],
    'Network': [
        'Xác nhận phạm vi ảnh hưởng và vị trí/khoa phòng.',
        'Kiểm tra kết nối vật lý/Wi-Fi, trạng thái switch/AP và gateway liên quan.',
        'Kiểm tra dịch vụ DHCP/DNS hoặc đường truyền nếu ảnh hưởng nhiều người dùng.',
        'Ghi nhận kết quả kiểm tra và chuyển Network khi cần can thiệp hạ tầng.',
    ],
    'Account': [
        'Xác minh danh tính/người yêu cầu theo quy trình nội bộ.',
        'Kiểm tra trạng thái khóa tài khoản, mật khẩu và thời điểm đăng nhập gần nhất.',
        'Thực hiện reset/unlock nếu thuộc quyền Helpdesk hoặc chuyển System nếu vượt thẩm quyền.',
        'Yêu cầu người dùng thử đăng nhập lại và xác nhận dịch vụ hoạt động.',
    ],
    'Email': [
        'Xác định lỗi gửi, nhận, đăng nhập hay dung lượng hộp thư.',
        'Kiểm tra kết nối và trạng thái dịch vụ email.',
        'Kiểm tra quota/cấu hình tài khoản và thử nghiệm bằng kênh webmail nếu có.',
        'Chuyển System nếu lỗi thuộc mail server hoặc ảnh hưởng nhiều tài khoản.',
    ],
    'Hardware': [
        'Kiểm tra nguồn, cáp, thiết bị ngoại vi và dấu hiệu lỗi phần cứng.',
        'Thử thao tác khởi động/đổi cổng/đổi phụ kiện an toàn ở mức Helpdesk.',
        'Ghi nhận serial/asset tag và tình trạng thiết bị.',
        'Chuyển bảo trì/thay thế nếu xác nhận lỗi phần cứng.',
    ],
    'Software': [
        'Xác định phần mềm, phiên bản và thông báo lỗi.',
        'Kiểm tra khả năng tái hiện lỗi và phạm vi chỉ một máy hay nhiều máy.',
        'Thực hiện thao tác hỗ trợ chuẩn như restart, kiểm tra cấu hình hoặc repair theo quyền.',
        'Chuyển nhóm phù hợp nếu cần cài đặt/quyền quản trị hoặc lỗi ứng dụng diện rộng.',
    ],
    'Printer': [
        'Kiểm tra nguồn, giấy, mực, lỗi hiển thị và hàng đợi in.',
        'Kiểm tra kết nối USB/LAN và trạng thái online của máy in.',
        'Thử in test page hoặc chuyển sang máy in dự phòng nếu có.',
        'Chuyển Network/Helpdesk phù hợp nếu lỗi kết nối hoặc phần cứng.',
    ],
    'Business Application': [
        'Xác nhận hệ thống và chức năng nghiệp vụ đang lỗi (HIS/PACS/LIS/EMR...).',
        'Xác định phạm vi người dùng/khoa phòng và bệnh nhân có đang chờ xử lý hay không.',
        'Kiểm tra trạng thái dịch vụ/ứng dụng và lỗi hiển thị cơ bản, không thay đổi dữ liệu nghiệp vụ.',
        'Chuyển Application ngay khi hệ thống lâm sàng gián đoạn hoặc ảnh hưởng nhiều người dùng.',
    ],
    'Access/Permission': [
        'Xác minh người yêu cầu và quyền cần cấp/thay đổi.',
        'Kiểm tra phê duyệt và nguyên tắc phân quyền của đơn vị.',
        'Không cấp quyền vượt thẩm quyền hoặc không có phê duyệt.',
        'Chuyển System/Application theo hệ thống đích sau khi đủ căn cứ.',
    ],
    'Security Incident': [
        'Hạn chế thao tác làm mất bằng chứng; ghi nhận thời gian, thiết bị và dấu hiệu bất thường.',
        'Nếu có mã độc/hoạt động tấn công đang diễn ra, cô lập thiết bị theo quy trình nội bộ khi được phép.',
        'Không tự xóa log hoặc tự xử lý sâu nếu chưa có hướng dẫn từ Tổ ATTT.',
        'Chuyển Security và báo ngay khi ticket mức P1 hoặc có dấu hiệu xâm nhập đang hoạt động.',
    ],
}

def has(wm, *names):
    s = wm.get('symptoms', set())
    return any(n in s for n in names)

def matched(wm, keys):
    out = {}
    for k in keys:
        v = wm.get(k)
        if isinstance(v, set): v = sorted(v)
        out[k] = v
    return out

def cat_action(name):
    return lambda wm: {'candidate_category': name}

def set_impact(level):
    return lambda wm: {'impact': level}

def set_urgency(level):
    return lambda wm: {'urgency': level}

def set_priority(level):
    return lambda wm: {'priority': level}

def set_team(team):
    return lambda wm: {'assigned_team': team}

def add_escalation(text):
    return lambda wm: {'escalation': text}

def build_rules() -> List[Rule]:
    R = []
    # --- C01-C15: ticket classification ---
    R += [
        Rule('C01','classification','Network - mất/chậm kết nối mạng',800,
             lambda w:(has(w,'network_down','network_slow','no_internet'), matched(w,['affected_system','symptoms'])),
             cat_action('Network'),'Triệu chứng mất mạng, mạng chậm hoặc không Internet tạo ứng viên Network; affected_system chỉ là fact bổ trợ.'),
        Rule('C02','classification','Network - sự cố kết nối diện rộng',820,
             lambda w:((w.get('scope') in {'department','hospital'} and has(w,'network_down','no_internet')), matched(w,['scope','affected_users','symptoms'])),
             cat_action('Network'),'Sự cố kết nối ảnh hưởng khoa/phòng hoặc toàn bệnh viện ưu tiên phân loại Network.'),
        Rule('C03','classification','Account - khóa/reset tài khoản',700,
             lambda w:(has(w,'account_locked','password_reset'), matched(w,['affected_system','symptoms'])),
             cat_action('Account'),'Khóa tài khoản hoặc yêu cầu reset mật khẩu thuộc nhóm Account.'),
        Rule('C04','classification','Account - không đăng nhập tài khoản chung',690,
             lambda w:(has(w,'cannot_login') and w.get('affected_system') in {'Account','Email','Workstation'}, matched(w,['affected_system','symptoms'])),
             cat_action('Account'),'Không đăng nhập trong ngữ cảnh tài khoản/email/máy trạm tạo ứng viên Account.'),
        Rule('C05','classification','Email - gửi/nhận/quota',650,
             lambda w:(has(w,'cannot_send_email','cannot_receive_email','mailbox_full'), matched(w,['affected_system','symptoms'])),
             cat_action('Email'),'Lỗi gửi/nhận email hoặc đầy hộp thư thuộc nhóm Email.'),
        Rule('C06','classification','Hardware - lỗi vật lý/nguồn',600,
             lambda w:(has(w,'device_no_power','hardware_failure','peripheral_failure'), matched(w,['affected_system','symptoms'])),
             cat_action('Hardware'),'Dấu hiệu nguồn hoặc linh kiện vật lý tạo ứng viên Hardware.'),
        Rule('C07','classification','Software - crash/OS/cài đặt',550,
             lambda w:(has(w,'software_crash','os_error','install_request'), matched(w,['affected_system','symptoms'])),
             cat_action('Software'),'Crash phần mềm, lỗi hệ điều hành hoặc yêu cầu cài đặt thuộc nhóm Software.'),
        Rule('C08','classification','Printer - lỗi in/online/kẹt giấy',850,
             lambda w:(w.get('affected_system')=='Printer' and has(w,'printer_offline','printer_not_printing','paper_jam'), matched(w,['affected_system','symptoms'])),
             cat_action('Printer'),'Lỗi vận hành máy in trên asset Printer tạo ứng viên Printer với ưu tiên phân loại cao hơn Network.'),
        Rule('C09','classification','Business Application - ứng dụng nghiệp vụ lỗi/ngừng',900,
             lambda w:(w.get('affected_system') in {'HIS','PACS','LIS','EMR'} and has(w,'app_unavailable','app_error'), matched(w,['affected_system','symptoms'])),
             cat_action('Business Application'),'HIS/PACS/LIS/EMR không khả dụng hoặc báo lỗi thuộc Business Application.'),
        Rule('C10','classification','Business Application - ứng dụng lâm sàng chậm',890,
             lambda w:(w.get('affected_system') in {'HIS','PACS','LIS','EMR'} and has(w,'app_slow'), matched(w,['affected_system','symptoms'])),
             cat_action('Business Application'),'Hiệu năng chậm của hệ thống lâm sàng tạo ứng viên Business Application.'),
        Rule('C11','classification','Access/Permission - yêu cầu cấp quyền',750,
             lambda w:(has(w,'access_request'), matched(w,['affected_system','symptoms'])),
             cat_action('Access/Permission'),'Yêu cầu cấp quyền được phân loại Access/Permission.'),
        Rule('C12','classification','Access/Permission - bị từ chối quyền',760,
             lambda w:(has(w,'permission_denied','share_access_denied'), matched(w,['affected_system','symptoms'])),
             cat_action('Access/Permission'),'Không đủ quyền hoặc bị từ chối truy cập tạo ứng viên Access/Permission.'),
        Rule('C13','classification','Security - phishing/email đáng ngờ',1000,
             lambda w:(has(w,'suspicious_email','phishing_suspected'), matched(w,['affected_system','symptoms'])),
             cat_action('Security Incident'),'Email đáng ngờ hoặc nghi phishing được ưu tiên phân loại Security Incident.'),
        Rule('C14','classification','Security - mã độc/truy cập trái phép',1010,
             lambda w:(has(w,'malware_alert','unauthorized_access'), matched(w,['affected_system','symptoms'])),
             cat_action('Security Incident'),'Cảnh báo mã độc hoặc truy cập trái phép thuộc Security Incident.'),
        Rule('C15','classification','Security - dấu hiệu ransomware',1020,
             lambda w:(has(w,'data_encrypted','ransom_note'), matched(w,['affected_system','symptoms'])),
             cat_action('Security Incident'),'Mã hóa dữ liệu hoặc ransom note là tín hiệu Security Incident có độ ưu tiên phân loại rất cao.'),
    ]

    # --- I01-I06: impact ---
    R += [
        Rule('I01','impact_urgency','Impact CRITICAL - bệnh nhân đang chờ',980,
             lambda w:(w.get('clinical_workflow_affected') and w.get('patients_waiting'), matched(w,['clinical_workflow_affected','patients_waiting','affected_system'])),
             set_impact('CRITICAL'),'Luồng công việc lâm sàng bị ảnh hưởng trong khi bệnh nhân đang chờ tạo impact CRITICAL.'),
        Rule('I02','impact_urgency','Impact CRITICAL - hệ thống trọng yếu ngừng',970,
             lambda w:(w.get('critical_system') and w.get('service_down'), matched(w,['critical_system','service_down','affected_system'])),
             set_impact('CRITICAL'),'Hệ thống trọng yếu ngừng hoàn toàn tạo impact CRITICAL.'),
        Rule('I03','impact_urgency','Impact HIGH - toàn bệnh viện hoặc >=50 người',860,
             lambda w:((w.get('scope')=='hospital' or int(w.get('affected_users',0))>=50), matched(w,['scope','affected_users'])),
             set_impact('HIGH'),'Phạm vi quy mô toàn bệnh viện (suy ra từ affected_users) hoặc >=50 người tạo impact HIGH.'),
        Rule('I04','impact_urgency','Impact HIGH - khoa/phòng hoặc 10-49 người',850,
             lambda w:((w.get('scope')=='department' or 10<=int(w.get('affected_users',0))<=49), matched(w,['scope','affected_users'])),
             set_impact('HIGH'),'Phạm vi quy mô khoa/phòng (suy ra từ affected_users) hoặc 10-49 người tạo impact HIGH.'),
        Rule('I05','impact_urgency','Impact MEDIUM - 2-9 người',700,
             lambda w:(2<=int(w.get('affected_users',0))<=9, matched(w,['affected_users'])),
             set_impact('MEDIUM'),'Ảnh hưởng 2-9 người được xem là impact MEDIUM trong cấu hình đồ án.'),
        Rule('I06','impact_urgency','Impact LOW - một người dùng',600,
             lambda w:(int(w.get('affected_users',0))<=1, matched(w,['affected_users'])),
             set_impact('LOW'),'Ticket đơn lẻ được xem là impact LOW nếu không có luật impact cao hơn.'),
    ]

    # --- U01-U05: urgency ---
    R += [
        Rule('U01','impact_urgency','Urgency CRITICAL - bệnh nhân đang chờ',990,
             lambda w:(w.get('clinical_workflow_affected') and w.get('patients_waiting'), matched(w,['clinical_workflow_affected','patients_waiting'])),
             set_urgency('CRITICAL'),'Khi bệnh nhân đang chờ một quy trình CNTT lâm sàng, urgency được đẩy lên CRITICAL.'),
        Rule('U02','impact_urgency','Urgency HIGH - Security đang hoạt động',900,
             lambda w:(w.get('primary_category')=='Security Incident' and w.get('security_active'), matched(w,['primary_category','security_active'])),
             set_urgency('HIGH'),'Security Incident đang diễn ra yêu cầu xử lý khẩn, urgency HIGH.'),
        Rule('U03','impact_urgency','Urgency HIGH - không workaround + deadline',880,
             lambda w:((not w.get('workaround_available')) and w.get('deadline_critical'), matched(w,['workaround_available','deadline_critical'])),
             set_urgency('HIGH'),'Không có phương án thay thế và có deadline công việc tạo urgency HIGH.'),
        Rule('U04','impact_urgency','Urgency HIGH - VIP bị gián đoạn',870,
             lambda w:(w.get('vip_user') and w.get('service_down'), matched(w,['vip_user','service_down'])),
             set_urgency('HIGH'),'Người dùng VIP bị gián đoạn hoàn toàn tạo urgency HIGH theo quy tắc nội bộ của đồ án.'),
        Rule('U05','impact_urgency','Urgency mặc định theo workaround',500,
             lambda w:(True, matched(w,['workaround_available','service_down'])),
             lambda w:{'urgency':'LOW' if w.get('workaround_available') else 'MEDIUM'},
             'Nếu không có yếu tố khẩn cao hơn, có workaround -> LOW; không có workaround -> MEDIUM.'),
    ]

    # --- P01-P08: priority matrix ---
    R += [
        Rule('P01','priority','P1 - impact CRITICAL',1000,
             lambda w:(w.get('impact')=='CRITICAL', matched(w,['impact','urgency'])), set_priority('P1'),'Impact CRITICAL luôn tạo P1.'),
        Rule('P02','priority','P1 - urgency CRITICAL',990,
             lambda w:(w.get('urgency')=='CRITICAL', matched(w,['impact','urgency'])), set_priority('P1'),'Urgency CRITICAL luôn tạo P1.'),
        Rule('P03','priority','P1 - HIGH x HIGH',950,
             lambda w:(w.get('impact')=='HIGH' and w.get('urgency')=='HIGH', matched(w,['impact','urgency'])), set_priority('P1'),'Impact HIGH và urgency HIGH tạo P1.'),
        Rule('P04','priority','P2 - HIGH/MEDIUM kết hợp',850,
             lambda w:((w.get('impact'),w.get('urgency')) in {('HIGH','MEDIUM'),('MEDIUM','HIGH')}, matched(w,['impact','urgency'])), set_priority('P2'),'Một chiều HIGH và chiều còn lại MEDIUM tạo P2.'),
        Rule('P05','priority','P2 - impact HIGH, urgency LOW',830,
             lambda w:(w.get('impact')=='HIGH' and w.get('urgency')=='LOW', matched(w,['impact','urgency'])), set_priority('P2'),'Impact HIGH vẫn giữ P2 dù có workaround.'),
        Rule('P06','priority','P3 - MEDIUM/MEDIUM hoặc LOW/HIGH',700,
             lambda w:((w.get('impact'),w.get('urgency')) in {('MEDIUM','MEDIUM'),('LOW','HIGH')}, matched(w,['impact','urgency'])), set_priority('P3'),'Tổ hợp MEDIUM/MEDIUM hoặc LOW/HIGH tạo P3.'),
        Rule('P07','priority','P3 - MEDIUM/LOW hoặc LOW/MEDIUM',680,
             lambda w:((w.get('impact'),w.get('urgency')) in {('MEDIUM','LOW'),('LOW','MEDIUM')}, matched(w,['impact','urgency'])), set_priority('P3'),'Tổ hợp MEDIUM/LOW hoặc LOW/MEDIUM tạo P3.'),
        Rule('P08','priority','P4 - LOW x LOW',600,
             lambda w:(w.get('impact')=='LOW' and w.get('urgency')=='LOW', matched(w,['impact','urgency'])), set_priority('P4'),'Impact LOW và urgency LOW tạo P4.'),
    ]

    # --- R01-R08: routing ---
    R += [
        Rule('R01','routing','Route Network',800, lambda w:(w.get('primary_category')=='Network',matched(w,['primary_category'])), set_team('Network'),'Ticket Network được định tuyến đến đội Network.'),
        Rule('R02','routing','Route Account/Permission',780, lambda w:(w.get('primary_category') in {'Account','Access/Permission'},matched(w,['primary_category'])), set_team('System'),'Account và Access/Permission được định tuyến đến System.'),
        Rule('R03','routing','Route Email',760, lambda w:(w.get('primary_category')=='Email',matched(w,['primary_category'])), set_team('System'),'Email được định tuyến đến System.'),
        Rule('R04','routing','Route Hardware',740, lambda w:(w.get('primary_category')=='Hardware',matched(w,['primary_category'])), set_team('Helpdesk'),'Hardware ban đầu được định tuyến Helpdesk để xác minh/đổi thiết bị cơ bản.'),
        Rule('R05','routing','Route Software',730, lambda w:(w.get('primary_category')=='Software',matched(w,['primary_category'])), set_team('Helpdesk'),'Software thông thường được định tuyến Helpdesk.'),
        Rule('R06','routing','Route Printer',720, lambda w:(w.get('primary_category')=='Printer',matched(w,['primary_category'])), set_team('Helpdesk'),'Printer được định tuyến Helpdesk ở bước đầu.'),
        Rule('R07','routing','Route Business Application',900, lambda w:(w.get('primary_category')=='Business Application',matched(w,['primary_category'])), set_team('Application'),'HIS/PACS/LIS/EMR được định tuyến Application.'),
        Rule('R08','routing','Route Security',1000, lambda w:(w.get('primary_category')=='Security Incident',matched(w,['primary_category'])), set_team('Security'),'Security Incident được định tuyến Security.'),
    ]

    # --- E01-E03: escalation ---
    R += [
        Rule('E01','escalation','Escalate P1 ngay Level 2/3',1000,
             lambda w:(w.get('priority')=='P1', matched(w,['priority','assigned_team'])),
             add_escalation('P1: chuyển ngay Level 2/Level 3 của đội phụ trách; bắt đầu SLA phản hồi 15 phút.'),
             'Mọi ticket P1 phải được escalation ngay.'),
        Rule('E02','escalation','P1 Security báo đồng thời Tổ ATTT',1100,
             lambda w:(w.get('priority')=='P1' and w.get('primary_category')=='Security Incident', matched(w,['priority','primary_category'])),
             add_escalation('P1 + Security Incident: đồng thời thông báo Tổ ATTT/Security và đầu mối quản lý sự cố theo quy trình nội bộ.'),
             'P1 Security Incident có escalation đồng thời đến Tổ ATTT.'),
        Rule('E03','escalation','P2 trọng yếu chuyển Level 2',850,
             lambda w:(w.get('priority')=='P2' and (w.get('critical_system') or w.get('clinical_workflow_affected')), matched(w,['priority','critical_system','clinical_workflow_affected'])),
             add_escalation('P2 trên hệ thống trọng yếu/luồng lâm sàng: chuyển Level 2 sớm, không giữ tại tuyến Helpdesk nếu chưa có hướng xử lý.'),
             'P2 liên quan hệ thống trọng yếu hoặc luồng lâm sàng cần escalation sớm.'),
    ]
    assert len(R) == 45, len(R)
    return R
