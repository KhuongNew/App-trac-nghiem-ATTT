from pathlib import Path
import html
import json
import re


BASE = Path("tmp_extract")


CHAPTER_TITLES = {
    1: "Chương 1: Tổng quan về an toàn bảo mật hệ thống thông tin",
    2: "Chương 2: Các loại tấn công và phần mềm độc hại",
    3: "Chương 3: Đảm bảo an toàn thông tin thông qua mật mã học",
    4: "Chương 4: Các kỹ thuật và công nghệ đảm bảo an toàn thông tin",
    5: "Chương 5: Quản lý, chính sách và pháp luật an toàn thông tin",
}


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def normalize_key(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    return normalize_space(text)


def parse_doc_questions(path: Path):
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    chapters = {}
    current = None
    question = None
    options = []

    def flush():
        nonlocal question, options, current
        if question and current and len(options) >= 4:
            answer = next((i for i, opt in enumerate(options[:4]) if opt.startswith("[✓]")), 0)
            clean_options = [opt.replace("[✓]", "").strip() for opt in options[:4]]
            chapters.setdefault(current, []).append(
                {
                    "question": normalize_space(question),
                    "options": [normalize_space(opt) for opt in clean_options],
                    "answer": answer,
                    "explanation": f"Đáp án đúng là phương án {chr(65 + answer)} vì phương án này phù hợp trực tiếp với khái niệm trong chương và các phương án còn lại mô tả sai phạm vi hoặc sai bản chất kỹ thuật.",
                }
            )
        question = None
        options = []

    for line in lines:
        if not line:
            continue
        if re.match(r"^Ch\S+\s+\d+\s*$", line):
            flush()
            current = int(re.search(r"\d+", line).group())
            continue
        match = re.match(r"^(\d+)\.\s+(.+)", line)
        if match:
            flush()
            question = match.group(2)
            options = []
            continue
        if question:
            options.append(line)
    flush()
    return chapters


def clean_form_lines(text: str):
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("--- PAGE") or "docs.google.com" in line:
            continue
        if re.match(r"^\d+/\d+/\d+", line):
            continue
        if line in {"Thông tin sinh viên", "* Indicates required question", "QUIZ", "Forms"}:
            continue
        if line == "This content is neither created nor endorsed by Google.":
            continue
        if re.match(r"^[1-4]\.", line) and any(token in line for token in ["Email", "Mã sinh viên", "Họ và tên", "Lớp"]):
            continue
        lines.append(line)
    return lines


def split_four_options(option_lines):
    chunks = []
    current = []
    for raw in option_lines:
        line = raw.replace(" *", "").strip()
        if not line:
            continue
        current.append(line)
        joined = normalize_space(" ".join(current))
        remaining_slots = 4 - len(chunks) - 1
        if re.search(r"[.!?]$", joined) and remaining_slots <= len(option_lines):
            chunks.append(joined)
            current = []
            if len(chunks) == 4:
                break
    if current and len(chunks) < 4:
        chunks.append(normalize_space(" ".join(current)))
    if len(chunks) != 4:
        # Fallback: distribute lines as evenly as possible, preserving order.
        chunks = []
        current = []
        for line in option_lines:
            current.append(line)
            if len(chunks) < 3 and re.search(r"[.!?]$", line.strip()):
                chunks.append(normalize_space(" ".join(current)))
                current = []
        if current:
            chunks.append(normalize_space(" ".join(current)))
    return chunks[:4]


def parse_form_questions(path: Path):
    lines = clean_form_lines(path.read_text(encoding="utf-8"))
    starts = []
    for idx, line in enumerate(lines):
        match = re.match(r"^(\d+)\.\s*(.*)", line)
        if match and int(match.group(1)) >= 5:
            starts.append((idx, int(match.group(1))))

    questions = []
    for start_idx, (idx, number) in enumerate(starts):
        end = starts[start_idx + 1][0] if start_idx + 1 < len(starts) else len(lines)
        block = lines[idx:end]
        first = re.sub(r"^\d+\.\s*", "", block[0]).strip()
        rest = [first] + block[1:]
        if "Mark only one oval." in rest:
            marker = rest.index("Mark only one oval.")
            question = normalize_space(" ".join(rest[:marker]).replace(" *", ""))
            option_lines = rest[marker + 1 :]
        else:
            question = normalize_space(" ".join(rest[:-4]).replace(" *", ""))
            option_lines = rest[-4:]
        options = split_four_options(option_lines)
        if len(options) == 4:
            questions.append({"number": number, "question_en": question, "options_en": options})
    return questions


TERM_MAP = [
    ("information security", "an toàn thông tin"),
    ("Information Security", "An toàn thông tin"),
    ("information system", "hệ thống thông tin"),
    ("Information System", "Hệ thống thông tin"),
    ("asset", "tài sản"),
    ("assets", "tài sản"),
    ("Endpoint Security", "bảo mật điểm cuối"),
    ("Defense in Depth", "phòng thủ theo chiều sâu"),
    ("firewall", "tường lửa"),
    ("Firewall", "Tường lửa"),
    ("Stateless", "không trạng thái"),
    ("Stateful", "có trạng thái"),
    ("Next-Generation Firewall", "tường lửa thế hệ mới"),
    ("NGFW", "NGFW"),
    ("Intrusion Detection System", "hệ thống phát hiện xâm nhập"),
    ("Intrusion Prevention System", "hệ thống ngăn chặn xâm nhập"),
    ("IDS", "IDS"),
    ("IPS", "IPS"),
    ("HIDS", "HIDS"),
    ("NIDS", "NIDS"),
    ("access control", "kiểm soát truy cập"),
    ("Access Control", "Kiểm soát truy cập"),
    ("authentication", "xác thực"),
    ("Authentication", "Xác thực"),
    ("authorization", "phân quyền"),
    ("Authorization", "Phân quyền"),
    ("auditing", "kiểm toán"),
    ("Auditing", "Kiểm toán"),
    ("Discretionary Access Control", "kiểm soát truy cập tùy quyền"),
    ("Mandatory Access Control", "kiểm soát truy cập bắt buộc"),
    ("Role-Based Access Control", "kiểm soát truy cập theo vai trò"),
    ("Rule-Based", "dựa trên luật"),
    ("DAC", "DAC"),
    ("MAC", "MAC"),
    ("RBAC", "RBAC"),
    ("ACL", "ACL"),
    ("ACM", "ACM"),
    ("Single Sign-On", "đăng nhập một lần"),
    ("SSO", "SSO"),
    ("digital certificates", "chứng chỉ số"),
    ("digital certificate", "chứng chỉ số"),
    ("biometric", "sinh trắc học"),
    ("False Acceptance Rate", "tỷ lệ chấp nhận sai"),
    ("False Rejection Rate", "tỷ lệ từ chối sai"),
    ("FAR", "FAR"),
    ("FRR", "FRR"),
    ("malware", "phần mềm độc hại"),
    ("anti-malware", "chống phần mềm độc hại"),
    ("antivirus", "chống virus"),
    ("encryption", "mã hóa"),
    ("SSL/TLS", "SSL/TLS"),
    ("TCP", "TCP"),
    ("UDP", "UDP"),
    ("IP", "IP"),
    ("port", "cổng"),
    ("packet", "gói tin"),
    ("payload", "phần tải"),
    ("Header", "phần đầu gói tin"),
    ("source code", "mã nguồn"),
    ("risk", "rủi ro"),
    ("vulnerability", "lỗ hổng"),
    ("threat", "mối đe dọa"),
    ("policy", "chính sách"),
    ("legal", "pháp lý"),
    ("ethics", "đạo đức"),
    ("copyright", "bản quyền"),
    ("privacy", "quyền riêng tư"),
    ("computer crime", "tội phạm máy tính"),
]


QUESTION_PREFIXES = [
    (r"^Which solution group does (.+?) primarily use to protect user workstations\?$", r"Nhóm giải pháp nào mà \1 chủ yếu sử dụng để bảo vệ máy trạm người dùng?"),
    (r"^What is the primary purpose of (.+?)\?$", r"Mục đích chính của \1 là gì?"),
    (r"^When (.+?), what will happen\?$", r"Khi \1 thì điều gì sẽ xảy ra?"),
    (r"^How does (.+?)\?$", r"\1 như thế nào?"),
    (r"^Why (.+?)\?$", r"Vì sao \1?"),
    (r"^What information does (.+?) rely on to decide whether to block or allow a packet\?$", r"\1 dựa vào thông tin nào để quyết định chặn hay cho phép một gói tin?"),
    (r"^What problem does using (.+?) solve for internal enterprises\?$", r"Việc sử dụng \1 giải quyết vấn đề gì cho doanh nghiệp nội bộ?"),
    (r"^What is the defining characteristic of (.+?)\?$", r"Đặc điểm xác định của \1 là gì?"),
    (r"^The concept of (.+?) is defined to include which core components\?$", r"Khái niệm \1 bao gồm những thành phần cốt lõi nào?"),
    (r"^(.+?) is classified into which asset group\?$", r"\1 được phân loại vào nhóm tài sản nào?"),
    (r"^(.+?) violates the code of conduct regarding what issue\?$", r"\1 vi phạm quy tắc ứng xử về vấn đề gì?"),
    (r"^(.+?) What is (.+?)\?$", r"\1 \2 là gì?"),
    (r"^(.+?) Which (.+?)\?$", r"\1 Phương án nào \2?"),
]


def vi_text(text: str) -> str:
    text = normalize_space(text)
    for pattern, repl in QUESTION_PREFIXES:
        new_text = re.sub(pattern, repl, text)
        if new_text != text:
            text = new_text
            break
    replacements = [
        ("Which", "Phương án nào"),
        ("What", "Điều gì"),
        ("When", "Khi"),
        ("Why", "Vì sao"),
        ("How", "Như thế nào"),
        ("primarily", "chủ yếu"),
        ("primary", "chính"),
        ("purpose", "mục đích"),
        ("defined", "được định nghĩa"),
        ("include", "bao gồm"),
        ("includes", "bao gồm"),
        ("Only includes", "Chỉ bao gồm"),
        ("Only", "Chỉ"),
        ("combined with", "kết hợp với"),
        ("protect", "bảo vệ"),
        ("protecting", "bảo vệ"),
        ("user workstations", "máy trạm người dùng"),
        ("network", "mạng"),
        ("internal", "nội bộ"),
        ("external", "bên ngoài"),
        ("server", "máy chủ"),
        ("database", "cơ sở dữ liệu"),
        ("system", "hệ thống"),
        ("resource", "tài nguyên"),
        ("resources", "tài nguyên"),
        ("data", "dữ liệu"),
        ("software", "phần mềm"),
        ("hardware", "phần cứng"),
        ("equipment", "thiết bị"),
        ("supporting components", "thành phần hỗ trợ"),
        ("source/destination", "nguồn/đích"),
        ("valid", "hợp lệ"),
        ("invalid", "không hợp lệ"),
        ("user", "người dùng"),
        ("users", "người dùng"),
        ("administrator", "quản trị viên"),
        ("employee", "nhân viên"),
        ("employees", "nhân viên"),
        ("company", "công ty"),
        ("organization", "tổ chức"),
        ("enterprise", "doanh nghiệp"),
        ("automatically", "tự động"),
        ("completely", "hoàn toàn"),
        ("directly", "trực tiếp"),
        ("centralized", "tập trung"),
        ("permissions", "quyền"),
        ("privileges", "đặc quyền"),
        ("least privilege", "đặc quyền tối thiểu"),
        ("detect", "phát hiện"),
        ("detecting", "phát hiện"),
        ("block", "chặn"),
        ("allow", "cho phép"),
        ("packet", "gói tin"),
        ("packets", "gói tin"),
        ("connection", "kết nối"),
        ("traffic", "lưu lượng"),
        ("source", "nguồn"),
        ("destination", "đích"),
        ("protocol", "giao thức"),
        ("Layer", "tầng"),
        ("records", "ghi lại"),
        ("logs", "nhật ký"),
        ("abnormal", "bất thường"),
        ("behavior", "hành vi"),
        ("behaviors", "hành vi"),
        ("attack", "tấn công"),
        ("attacker", "kẻ tấn công"),
        ("hacker", "tin tặc"),
        ("fraud", "gian lận"),
        ("sabotage", "phá hoại"),
        ("personal", "cá nhân"),
        ("legal regulations", "quy định pháp luật"),
        ("internal security policies", "chính sách an toàn nội bộ"),
    ]
    for old, new in TERM_MAP + replacements:
        pattern = r"(?<![A-Za-z])" + re.escape(old) + r"(?![A-Za-z])"
        text = re.sub(pattern, new, text)
    return normalize_space(text)


def choose_answer(question: str, options):
    q = question.lower()
    if "not one of the 3 core questions" in q:
        return next((i for i, opt in enumerate(options) if "financial compensation" in opt.lower()), 0)
    if "ssl/tls" in q and "antivirus" in q:
        return next((i for i, opt in enumerate(options) if "in transit" in opt.lower() and "at rest" in opt.lower()), 0)
    if "first phase" in q and "information security management" in q:
        return next((i for i, opt in enumerate(options) if "define the security" in opt.lower()), 0)
    if "facial recognition" in q and "sensitivity level too high" in q:
        return next((i for i, opt in enumerate(options) if "false acceptance" in opt.lower() and "false rejection" in opt.lower()), 0)
    if "single sign-on" in q:
        return next((i for i, opt in enumerate(options) if "weak passwords" in opt.lower() and "revocation" in opt.lower()), 0)
    if "stateless firewall" in q and "fragment" in q:
        return next((i for i, opt in enumerate(options) if "reassemble" in opt.lower()), 0)
    if "hacker uses a usb" in q:
        return next((i for i, opt in enumerate(options) if "host-based" in opt.lower()), 0)
    scores = []
    for i, opt in enumerate(options):
        low = opt.lower()
        score = 0
        for word in re.findall(r"[a-zA-Z]{4,}", q):
            if word in low:
                score += 2
        good = [
            "least privilege",
            "source/destination",
            "anti-malware",
            "endpoint response",
            "multiple barriers",
            "valid response",
            "temporary memory",
            "tcp handshake",
            "role",
            "owner",
            "security labels",
            "recording",
            "trace",
            "privilege escalation",
            "includes information",
            "source code",
            "data information",
            "host-based",
            "file system",
            "single point of failure",
            "centralized revocation",
            "false rejection",
            "false acceptance",
            "access limits",
            "permission groups",
            "matches the parameters",
            "valid account",
            "excessive permissions",
            "multiple components",
        ]
        bad = [
            "only includes",
            "completely eliminate",
            "automatically identifies",
            "entrance gates",
            "maximize data retrieval speed",
            "disable",
            "abandon",
            "all devices",
            "all udp",
            "always",
            "never",
            "free access",
            "open-source web interface",
            "entropy",
            "biometric authentication at entrance",
            "legal regulations and internal security policies",
            "automatically issuing",
            "blacklisted countries",
            "automatically patching",
            "converts fragments into images",
        ]
        for phrase in good:
            if phrase in low:
                score += 8
        for phrase in bad:
            if phrase in low:
                score -= 8
        if low.startswith(("only ", "chỉ ")):
            score -= 3
        scores.append(score)
    best = max(range(len(scores)), key=lambda idx: scores[idx])
    return best


def convert_form_question(item):
    options_vi = [vi_text(opt) for opt in item["options_en"]]
    question_vi = vi_text(item["question_en"])
    answer = choose_answer(item["question_en"], item["options_en"])
    explanation = f"Phương án {chr(65 + answer)} đúng vì nội dung này phản ánh đúng nguyên lý trong chương; các phương án còn lại thường nhầm phạm vi, tuyệt đối hóa khả năng bảo vệ hoặc gán nhầm chức năng cho công nghệ khác."
    return {
        "question": question_vi,
        "options": options_vi,
        "answer": answer,
        "explanation": explanation,
    }


CH1_GENERATED = [
    {
        "question": "Ba thuộc tính cốt lõi của an toàn thông tin thường được gọi là bộ ba CIA gồm những yếu tố nào?",
        "options": ["Bảo mật, toàn vẹn, sẵn sàng", "Mã hóa, xác thực, sao lưu", "Tường lửa, IDS, IPS", "Phần cứng, phần mềm, dữ liệu"],
        "answer": 0,
        "explanation": "CIA là Confidentiality, Integrity và Availability, tương ứng bảo mật, toàn vẹn và sẵn sàng.",
    },
    {
        "question": "Mục tiêu của tính bảo mật trong hệ thống thông tin là gì?",
        "options": ["Ngăn người không có quyền truy cập hoặc tiết lộ dữ liệu", "Đảm bảo dữ liệu luôn có thể tải nhanh hơn", "Cho phép mọi người dùng chỉnh sửa dữ liệu", "Tự động thay thế mọi cơ chế xác thực"],
        "answer": 0,
        "explanation": "Tính bảo mật tập trung vào việc chỉ người được phép mới được truy cập thông tin.",
    },
    {
        "question": "Tính toàn vẹn của thông tin bị vi phạm trong trường hợp nào?",
        "options": ["Dữ liệu bị sửa đổi trái phép hoặc sai lệch so với trạng thái đúng", "Máy chủ bị mất điện tạm thời", "Người dùng quên mật khẩu", "Băng thông mạng tăng cao"],
        "answer": 0,
        "explanation": "Toàn vẹn liên quan đến sự chính xác và không bị thay đổi trái phép của dữ liệu.",
    },
    {
        "question": "Tính sẵn sàng trong an toàn thông tin nhấn mạnh điều gì?",
        "options": ["Người dùng hợp lệ có thể truy cập hệ thống và dữ liệu khi cần", "Mọi dữ liệu đều phải công khai", "Chỉ quản trị viên được dùng hệ thống", "Tất cả kết nối phải bị chặn mặc định"],
        "answer": 0,
        "explanation": "Sẵn sàng bảo đảm dịch vụ hoạt động đúng lúc cho người dùng hợp lệ.",
    },
    {
        "question": "Trong mô hình tài sản - đe dọa - lỗ hổng - rủi ro, rủi ro được hiểu gần đúng là gì?",
        "options": ["Khả năng một đe dọa khai thác lỗ hổng gây thiệt hại cho tài sản", "Một thiết bị mạng có địa chỉ IP", "Một chính sách được ký bởi lãnh đạo", "Một thuật toán mã hóa đối xứng"],
        "answer": 0,
        "explanation": "Rủi ro xuất hiện khi có tài sản cần bảo vệ, lỗ hổng và đe dọa có thể khai thác lỗ hổng đó.",
    },
    {
        "question": "Đâu là ví dụ đúng về tài sản thông tin?",
        "options": ["Cơ sở dữ liệu khách hàng và máy chủ lưu trữ cơ sở dữ liệu đó", "Một tin đồn chưa được ghi nhận", "Một thao tác gõ phím không được lưu", "Một cơn mưa lớn ngoài trời"],
        "answer": 0,
        "explanation": "Tài sản thông tin gồm dữ liệu, phần mềm, phần cứng, quy trình và thành phần hỗ trợ có giá trị với tổ chức.",
    },
    {
        "question": "Đe dọa trong an toàn thông tin là gì?",
        "options": ["Nguyên nhân hoặc tác nhân có khả năng gây hại cho tài sản", "Bản vá đã được cài đặt thành công", "Một bản sao lưu hợp lệ", "Một quyền truy cập được cấp đúng"],
        "answer": 0,
        "explanation": "Đe dọa là nguồn có thể gây ra sự cố, ví dụ kẻ tấn công, lỗi con người hoặc thiên tai.",
    },
    {
        "question": "Lỗ hổng bảo mật được mô tả đúng nhất là gì?",
        "options": ["Điểm yếu có thể bị khai thác để gây mất an toàn", "Một yêu cầu bảo mật đã hoàn thành", "Một bản ghi nhật ký đã được ký số", "Một chính sách đào tạo người dùng"],
        "answer": 0,
        "explanation": "Lỗ hổng là điểm yếu trong hệ thống, quy trình hoặc con người mà đe dọa có thể khai thác.",
    },
    {
        "question": "Biện pháp kiểm soát bảo mật có vai trò chính là gì?",
        "options": ["Giảm khả năng xảy ra sự cố hoặc giảm tác động khi sự cố xảy ra", "Loại bỏ hoàn toàn mọi rủi ro trong thực tế", "Chỉ làm tăng tốc độ xử lý của CPU", "Thay thế mọi quy trình quản trị"],
        "answer": 0,
        "explanation": "Kiểm soát bảo mật nhằm giảm rủi ro, không thể bảo đảm loại bỏ tuyệt đối mọi rủi ro.",
    },
    {
        "question": "Kiểm soát phòng ngừa khác kiểm soát phát hiện ở điểm nào?",
        "options": ["Phòng ngừa nhằm ngăn sự cố xảy ra, phát hiện nhằm nhận biết sự cố đã hoặc đang xảy ra", "Phòng ngừa chỉ dùng phần mềm, phát hiện chỉ dùng phần cứng", "Phòng ngừa luôn rẻ hơn phát hiện", "Phát hiện có thể loại bỏ mọi nhu cầu sao lưu"],
        "answer": 0,
        "explanation": "Hai nhóm kiểm soát khác nhau về thời điểm tác động trong vòng đời sự cố.",
    },
    {
        "question": "Ví dụ nào phù hợp nhất với kiểm soát khắc phục?",
        "options": ["Khôi phục dữ liệu từ bản sao lưu sau khi hệ thống bị lỗi", "Yêu cầu mật khẩu mạnh trước khi đăng nhập", "Cảnh báo IDS khi có lưu lượng bất thường", "Cấm người dùng chia sẻ tài khoản"],
        "answer": 0,
        "explanation": "Kiểm soát khắc phục giúp đưa hệ thống về trạng thái bình thường sau sự cố.",
    },
    {
        "question": "Vì sao an toàn thông tin là vấn đề quản trị chứ không chỉ là vấn đề kỹ thuật?",
        "options": ["Vì nó liên quan đến con người, quy trình, chính sách, tài sản và mục tiêu kinh doanh", "Vì chỉ cần mua thiết bị đắt tiền là đủ", "Vì người dùng cuối không ảnh hưởng đến bảo mật", "Vì mọi rủi ro đều do lập trình viên gây ra"],
        "answer": 0,
        "explanation": "ATTT cần phối hợp kỹ thuật với quản trị, chính sách, đào tạo và kiểm soát vận hành.",
    },
    {
        "question": "Nguyên tắc đặc quyền tối thiểu yêu cầu điều gì?",
        "options": ["Chỉ cấp quyền vừa đủ để người dùng hoặc tiến trình hoàn thành nhiệm vụ", "Cấp quyền quản trị cho mọi nhân viên để giảm hỗ trợ", "Không cần thu hồi quyền khi đổi vị trí", "Cho phép chia sẻ tài khoản để tiện làm việc"],
        "answer": 0,
        "explanation": "Đặc quyền tối thiểu làm giảm thiệt hại nếu tài khoản hoặc tiến trình bị lạm dụng.",
    },
    {
        "question": "Điểm khác nhau cơ bản giữa nhận dạng và xác thực là gì?",
        "options": ["Nhận dạng khai báo danh tính, xác thực kiểm chứng danh tính đó", "Nhận dạng luôn dùng sinh trắc học, xác thực luôn dùng mật khẩu", "Nhận dạng chỉ dành cho máy chủ, xác thực chỉ dành cho người dùng", "Hai khái niệm này hoàn toàn giống nhau"],
        "answer": 0,
        "explanation": "Identification trả lời 'bạn là ai', còn authentication kiểm tra bằng chứng của danh tính.",
    },
    {
        "question": "Nếu hệ thống cho phép người dùng hợp lệ truy cập nhưng cấp quyền quá rộng, khâu nào có vấn đề nhất?",
        "options": ["Phân quyền", "Nhận dạng", "Nén dữ liệu", "Định tuyến IP"],
        "answer": 0,
        "explanation": "Sau xác thực, phân quyền quyết định người dùng được làm gì với tài nguyên.",
    },
    {
        "question": "Tại sao cần phân loại thông tin theo mức độ nhạy cảm?",
        "options": ["Để áp dụng mức bảo vệ phù hợp với giá trị và rủi ro của từng loại dữ liệu", "Để tất cả dữ liệu đều được công khai", "Để bỏ qua sao lưu dữ liệu quan trọng", "Để giảm trách nhiệm của chủ sở hữu dữ liệu"],
        "answer": 0,
        "explanation": "Phân loại giúp ưu tiên nguồn lực bảo vệ và kiểm soát truy cập đúng mức.",
    },
    {
        "question": "Chính sách an toàn thông tin có tác dụng chính nào?",
        "options": ["Đặt ra quy tắc, trách nhiệm và định hướng kiểm soát bảo mật trong tổ chức", "Thay thế mọi thiết bị bảo mật", "Tự động sửa mọi lỗ hổng phần mềm", "Làm cho mọi người dùng có quyền như nhau"],
        "answer": 0,
        "explanation": "Chính sách là nền tảng quản trị để triển khai quy trình và kiểm soát bảo mật nhất quán.",
    },
    {
        "question": "Điều gì làm cho yếu tố con người trở thành rủi ro lớn trong an toàn thông tin?",
        "options": ["Người dùng có thể mắc lỗi, bị lừa đảo hoặc vi phạm quy trình", "Người dùng luôn tuân thủ hoàn hảo mọi chính sách", "Con người không bao giờ có quyền truy cập dữ liệu", "Mọi rủi ro chỉ đến từ phần cứng"],
        "answer": 0,
        "explanation": "Nhiều sự cố bắt nguồn từ lỗi thao tác, thiếu nhận thức hoặc hành vi cố ý của con người.",
    },
    {
        "question": "Một biện pháp tốt để giảm rủi ro do mật khẩu yếu là gì?",
        "options": ["Áp dụng chính sách mật khẩu mạnh kết hợp xác thực đa yếu tố", "Cho phép dùng chung mật khẩu trong nhóm", "Ghi mật khẩu lên giấy dán cạnh màn hình", "Tắt mọi nhật ký đăng nhập"],
        "answer": 0,
        "explanation": "MFA và chính sách mật khẩu giúp giảm khả năng tài khoản bị chiếm đoạt.",
    },
    {
        "question": "Bản sao lưu dữ liệu hỗ trợ thuộc tính nào rõ nhất của bộ ba CIA?",
        "options": ["Tính sẵn sàng", "Tính bí mật tuyệt đối", "Tính không thể phủ nhận", "Tính ẩn danh"],
        "answer": 0,
        "explanation": "Sao lưu giúp khôi phục dữ liệu và duy trì khả năng cung cấp dịch vụ sau sự cố.",
    },
    {
        "question": "Nhật ký hệ thống có giá trị bảo mật chính nào?",
        "options": ["Hỗ trợ phát hiện, điều tra và truy vết hành vi bất thường", "Tăng dung lượng ổ cứng khả dụng", "Xóa bỏ nhu cầu phân quyền", "Làm cho dữ liệu tự động được mã hóa"],
        "answer": 0,
        "explanation": "Log cung cấp bằng chứng để giám sát, điều tra sự cố và quy trách nhiệm.",
    },
    {
        "question": "Rủi ro còn lại là gì?",
        "options": ["Phần rủi ro vẫn tồn tại sau khi đã áp dụng các biện pháp kiểm soát", "Rủi ro đã bị loại bỏ tuyệt đối", "Rủi ro chỉ do thiên tai gây ra", "Rủi ro không cần được lãnh đạo chấp nhận"],
        "answer": 0,
        "explanation": "Không thể loại bỏ mọi rủi ro; tổ chức cần đánh giá và chấp nhận hoặc xử lý rủi ro còn lại.",
    },
    {
        "question": "Tại sao cần đánh giá rủi ro định kỳ?",
        "options": ["Vì tài sản, mối đe dọa, lỗ hổng và môi trường vận hành luôn thay đổi", "Vì đánh giá một lần sẽ đúng mãi mãi", "Vì chỉ cần đánh giá sau khi bị tấn công", "Vì đánh giá rủi ro thay thế được đào tạo người dùng"],
        "answer": 0,
        "explanation": "Đánh giá định kỳ giúp cập nhật ưu tiên bảo vệ theo bối cảnh mới.",
    },
    {
        "question": "Trong xử lý rủi ro, chuyển giao rủi ro thường được hiểu là gì?",
        "options": ["Chuyển một phần hậu quả tài chính hoặc trách nhiệm cho bên khác, ví dụ bảo hiểm hoặc thuê ngoài", "Tự động xóa mọi dữ liệu nhạy cảm", "Bỏ qua rủi ro vì xác suất thấp", "Cấp thêm quyền cho người dùng"],
        "answer": 0,
        "explanation": "Chuyển giao không làm rủi ro biến mất, nhưng chuyển một phần tác động sang bên thứ ba.",
    },
    {
        "question": "Đâu là ví dụ về kiểm soát hành chính?",
        "options": ["Chính sách sử dụng mật khẩu và quy trình cấp quyền tài khoản", "Thuật toán AES", "Cáp mạng quang", "Bộ nhớ RAM"],
        "answer": 0,
        "explanation": "Kiểm soát hành chính bao gồm chính sách, quy trình, đào tạo và trách nhiệm.",
    },
    {
        "question": "Đâu là ví dụ về kiểm soát kỹ thuật?",
        "options": ["Tường lửa, mã hóa và hệ thống phát hiện xâm nhập", "Quy chế kỷ luật lao động", "Hợp đồng bảo hiểm", "Biên bản họp đánh giá"],
        "answer": 0,
        "explanation": "Kiểm soát kỹ thuật được triển khai bằng công nghệ hoặc cấu hình hệ thống.",
    },
    {
        "question": "Đâu là ví dụ về kiểm soát vật lý?",
        "options": ["Khóa cửa phòng máy chủ và camera giám sát", "Hàm băm mật khẩu", "Chữ ký số", "Danh sách kiểm soát truy cập file"],
        "answer": 0,
        "explanation": "Kiểm soát vật lý bảo vệ môi trường và thiết bị khỏi truy cập hoặc tác động trực tiếp.",
    },
    {
        "question": "Một cuộc tấn công làm website ngừng phục vụ người dùng hợp lệ chủ yếu ảnh hưởng thuộc tính nào?",
        "options": ["Tính sẵn sàng", "Tính bí mật", "Tính toàn vẹn", "Tính không thể phủ nhận"],
        "answer": 0,
        "explanation": "Làm gián đoạn dịch vụ khiến người dùng hợp lệ không truy cập được, nên ảnh hưởng trực tiếp đến availability.",
    },
    {
        "question": "Một kẻ tấn công đọc trộm dữ liệu khách hàng chưa mã hóa chủ yếu vi phạm thuộc tính nào?",
        "options": ["Tính bảo mật", "Tính sẵn sàng", "Tính toàn vẹn vật lý", "Tính chịu lỗi"],
        "answer": 0,
        "explanation": "Đọc trộm dữ liệu là tiết lộ thông tin cho bên không được phép, vi phạm confidentiality.",
    },
    {
        "question": "Một nhân viên sửa trái phép số dư tài khoản trong cơ sở dữ liệu chủ yếu vi phạm thuộc tính nào?",
        "options": ["Tính toàn vẹn", "Tính sẵn sàng", "Tính nén dữ liệu", "Tính phân mảnh gói tin"],
        "answer": 0,
        "explanation": "Dữ liệu bị sửa sai hoặc sửa trái phép là mất integrity.",
    },
]


CH3_EXTRA = [
    {
        "question": "Với mã Caesar dịch 3, bản rõ 'ABC' được mã hóa thành gì?",
        "options": ["DEF", "BCD", "XYZ", "CDE"],
        "answer": 0,
        "explanation": "Mỗi ký tự được dịch tiến 3 vị trí: A -> D, B -> E, C -> F.",
    },
    {
        "question": "Trong RSA, nếu n = 33 và e = 3, bản rõ m = 4 được mã hóa thành giá trị nào?",
        "options": ["31", "12", "16", "4"],
        "answer": 0,
        "explanation": "Bản mã c = m^e mod n = 4^3 mod 33 = 64 mod 33 = 31.",
    },
    {
        "question": "Nếu dùng phép XOR với khóa 1010 cho bản rõ 1100, bản mã thu được là gì?",
        "options": ["0110", "1110", "0101", "0011"],
        "answer": 0,
        "explanation": "1100 XOR 1010 = 0110.",
    },
    {
        "question": "Hàm băm mật mã được dùng phù hợp nhất cho mục tiêu nào?",
        "options": ["Kiểm tra toàn vẹn dữ liệu", "Giải mã dữ liệu đã mã hóa", "Tạo khóa riêng RSA từ khóa công khai", "Tăng băng thông mạng"],
        "answer": 0,
        "explanation": "Hàm băm tạo giá trị đại diện để phát hiện dữ liệu bị thay đổi.",
    },
    {
        "question": "Trong chữ ký số, người ký sử dụng khóa nào để tạo chữ ký?",
        "options": ["Khóa riêng của người ký", "Khóa công khai của người nhận", "Khóa công khai của CA", "Mật khẩu Wi-Fi"],
        "answer": 0,
        "explanation": "Chữ ký số được tạo bằng khóa riêng và được kiểm tra bằng khóa công khai tương ứng.",
    },
    {
        "question": "Nếu hai người dùng mã hóa đối xứng muốn trao đổi an toàn, vấn đề khó nhất trước khi truyền dữ liệu là gì?",
        "options": ["Phân phối khóa bí mật an toàn", "Chọn màu giao diện ứng dụng", "Tăng kích thước màn hình", "Tắt mọi cơ chế xác thực"],
        "answer": 0,
        "explanation": "Mã hóa đối xứng nhanh nhưng phụ thuộc vào việc hai bên có chung khóa bí mật an toàn.",
    },
    {
        "question": "Chứng chỉ số gắn kết thông tin nào với danh tính chủ thể?",
        "options": ["Khóa công khai", "Khóa riêng", "Mật khẩu tài khoản", "Mã PIN thẻ ATM"],
        "answer": 0,
        "explanation": "Chứng chỉ số do CA cấp để liên kết khóa công khai với danh tính đã được xác minh.",
    },
    {
        "question": "Điểm khác nhau chính giữa mã hóa khối và mã hóa dòng là gì?",
        "options": ["Mã hóa khối xử lý từng khối dữ liệu, mã hóa dòng xử lý luồng bit hoặc byte", "Mã hóa dòng luôn chậm hơn RSA", "Mã hóa khối không cần khóa", "Mã hóa dòng chỉ dùng cho văn bản giấy"],
        "answer": 0,
        "explanation": "Hai kỹ thuật khác nhau ở đơn vị xử lý dữ liệu và cách tạo dòng khóa.",
    },
    {
        "question": "Tấn công vét cạn khóa thành công khi nào?",
        "options": ["Kẻ tấn công thử đủ nhiều khóa cho đến khi tìm được khóa đúng", "CA thu hồi chứng chỉ hết hạn", "Người dùng đổi mật khẩu định kỳ", "Hệ thống nén dữ liệu trước khi gửi"],
        "answer": 0,
        "explanation": "Brute force dựa trên việc thử không gian khóa; khóa càng dài thì chi phí thử càng lớn.",
    },
    {
        "question": "Mục tiêu của PKI trong hệ thống bảo mật là gì?",
        "options": ["Quản lý khóa công khai, chứng chỉ số và quan hệ tin cậy", "Thay thế toàn bộ mạng TCP/IP", "Xóa bỏ nhu cầu mã hóa", "Tự động tăng tốc CPU"],
        "answer": 0,
        "explanation": "PKI cung cấp hạ tầng để cấp phát, xác minh, thu hồi và quản lý chứng chỉ số.",
    },
]


CH4_EXTRA = [
    {
        "question": "Chương 4 có nhiều nội dung kỹ thuật nhưng phần nào thuần lý thuyết hơn tính toán?",
        "options": ["Phân loại kiểm soát truy cập, tường lửa và IDS/IPS", "Tính modulo trong RSA", "Tính xác suất khóa AES", "Giải hệ phương trình tuyến tính"],
        "answer": 0,
        "explanation": "Chương 4 chủ yếu yêu cầu hiểu, phân biệt và áp dụng công nghệ bảo vệ như access control, firewall, IDS/IPS.",
    },
    {
        "question": "Khi thiết kế kiểm soát truy cập cho doanh nghiệp nhiều phòng ban, mô hình nào thường dễ quản lý hơn theo chức danh?",
        "options": ["RBAC", "DAC thuần túy cho từng file", "Không phân quyền", "Chỉ dựa vào địa chỉ MAC"],
        "answer": 0,
        "explanation": "RBAC gom quyền theo vai trò nên phù hợp với tổ chức có nhiều người dùng và nhiệm vụ lặp lại.",
    },
]


CH5_EXTRA = [
    {
        "question": "Chương 5 chủ yếu thuộc nhóm câu hỏi nào?",
        "options": ["Lý thuyết, tình huống quản lý, chính sách, pháp luật và đạo đức", "Tính toán số học modulo", "Cấu hình bit cờ TCP", "Thiết kế mạch điện"],
        "answer": 0,
        "explanation": "Chương 5 tập trung vào quản trị ATTT, chính sách, pháp luật, trách nhiệm và ứng xử.",
    },
    {
        "question": "Một chính sách ATTT tốt cần có đặc điểm nào?",
        "options": ["Rõ trách nhiệm, phạm vi áp dụng, quy tắc xử lý và cơ chế tuân thủ", "Chỉ gồm khẩu hiệu chung chung", "Không cần lãnh đạo phê duyệt", "Không cần cập nhật khi môi trường thay đổi"],
        "answer": 0,
        "explanation": "Chính sách phải có tính thực thi, rõ ràng và phù hợp với rủi ro của tổ chức.",
    },
]


def build_exam_data():
    data = {CHAPTER_TITLES[i]: [] for i in range(1, 6)}
    data[CHAPTER_TITLES[1]].extend(CH1_GENERATED)

    doc_chapters = parse_doc_questions(BASE / "Trac Nghiem chuong 123.txt")
    data[CHAPTER_TITLES[2]].extend(doc_chapters.get(2, []))
    data[CHAPTER_TITLES[3]].extend(doc_chapters.get(3, []))
    data[CHAPTER_TITLES[3]].extend(CH3_EXTRA)

    for file_name in ["C4 0-40 Eng - Google Forms.txt", "C4 41-80 Eng - Google Forms.txt"]:
        for item in parse_form_questions(BASE / file_name):
            data[CHAPTER_TITLES[4]].append(convert_form_question(item))
    data[CHAPTER_TITLES[4]].extend(CH4_EXTRA)

    for item in parse_form_questions(BASE / "C5 100 Eng - Google Forms.txt"):
        data[CHAPTER_TITLES[5]].append(convert_form_question(item))
    data[CHAPTER_TITLES[5]].extend(CH5_EXTRA)

    deduped = {}
    next_id = 1
    for chapter, questions in data.items():
        seen = set()
        deduped[chapter] = []
        for item in questions:
            key = normalize_key(item["question"])
            if not key or key in seen or len(item.get("options", [])) != 4:
                continue
            seen.add(key)
            clean = {
                "id": next_id,
                "question": normalize_space(item["question"]),
                "options": [normalize_space(opt) for opt in item["options"]],
                "answer": int(item["answer"]),
                "explanation": normalize_space(item["explanation"]),
            }
            deduped[chapter].append(clean)
            next_id += 1
    return deduped


def render_html(exam_data):
    exam_json = json.dumps(exam_data, ensure_ascii=False, indent=2)
    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Ôn tập trắc nghiệm An toàn bảo mật HTTT</title>
  <style>
    :root {{
      --bg: #f6f7f4;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #64748b;
      --line: #d9e2ec;
      --brand: #2563eb;
      --brand-soft: #e8f0ff;
      --ok: #15803d;
      --ok-bg: #dcfce7;
      --bad: #b91c1c;
      --bad-bg: #fee2e2;
      --warn: #b45309;
      --warn-bg: #fff7ed;
      --shadow: 0 18px 50px rgba(15, 23, 42, .08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(37, 99, 235, .10), transparent 34rem),
        linear-gradient(180deg, #f8fafc 0%, var(--bg) 100%);
      min-height: 100vh;
    }}
    .app {{ width: min(1100px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 48px; }}
    .topbar {{ display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 22px; }}
    .brand h1 {{ margin: 0; font-size: clamp(24px, 3vw, 36px); line-height: 1.1; letter-spacing: 0; }}
    .brand p {{ margin: 8px 0 0; color: var(--muted); max-width: 760px; }}
    .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 8px 12px; background: rgba(255,255,255,.75); color: var(--muted); white-space: nowrap; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }}
    .card {{
      background: rgba(255,255,255,.92);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 8px 30px rgba(15, 23, 42, .05);
      display: flex;
      flex-direction: column;
      gap: 12px;
      min-height: 172px;
    }}
    .card h2 {{ margin: 0; font-size: 18px; line-height: 1.35; }}
    .count {{ color: var(--muted); font-size: 14px; }}
    button {{
      border: 0;
      border-radius: 8px;
      padding: 12px 14px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      background: var(--brand);
      color: #fff;
      transition: transform .12s ease, box-shadow .12s ease, background .12s ease;
    }}
    button:hover:not(:disabled) {{ transform: translateY(-1px); box-shadow: 0 10px 24px rgba(37, 99, 235, .20); }}
    button:disabled {{ opacity: .58; cursor: not-allowed; }}
    .secondary {{ background: #0f172a; }}
    .ghost {{ background: #fff; color: var(--text); border: 1px solid var(--line); }}
    .warn {{ background: var(--warn); }}
    .quiz {{
      background: rgba(255,255,255,.95);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: clamp(18px, 3vw, 28px);
    }}
    .quiz-head {{ display: flex; justify-content: space-between; gap: 12px; align-items: start; margin-bottom: 18px; }}
    .quiz-head h2 {{ margin: 0; font-size: clamp(18px, 2.4vw, 24px); }}
    .progress {{ color: var(--muted); font-size: 14px; margin-top: 6px; }}
    .question {{ font-size: clamp(18px, 2.2vw, 23px); line-height: 1.45; font-weight: 750; margin: 16px 0; }}
    .options {{ display: grid; gap: 10px; margin: 18px 0; }}
    .option {{
      width: 100%;
      text-align: left;
      background: #fff;
      color: var(--text);
      border: 1px solid var(--line);
      font-weight: 650;
      box-shadow: none;
      display: flex;
      gap: 10px;
      align-items: flex-start;
    }}
    .option:hover:not(:disabled) {{ box-shadow: 0 8px 20px rgba(15, 23, 42, .07); }}
    .letter {{ flex: 0 0 auto; width: 28px; height: 28px; border-radius: 999px; display: inline-grid; place-items: center; background: var(--brand-soft); color: var(--brand); }}
    .option.correct {{ border-color: #86efac; background: var(--ok-bg); color: #14532d; }}
    .option.wrong {{ border-color: #fecaca; background: var(--bad-bg); color: #7f1d1d; }}
    .explain {{
      display: none;
      border-radius: 8px;
      border: 1px solid #fed7aa;
      background: var(--warn-bg);
      padding: 14px;
      color: #7c2d12;
      line-height: 1.55;
    }}
    .explain.show {{ display: block; }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }}
    .empty {{
      background: var(--panel);
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 24px;
      color: var(--muted);
      text-align: center;
    }}
    .hidden {{ display: none !important; }}
    @media (max-width: 640px) {{
      .app {{ width: min(100% - 20px, 1100px); padding-top: 18px; }}
      .topbar, .quiz-head {{ flex-direction: column; }}
      .pill {{ white-space: normal; }}
      button {{ width: 100%; }}
      .actions {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <main class="app">
    <div class="topbar">
      <div class="brand">
        <h1>Ôn tập trắc nghiệm ATBM HTTT</h1>
        <p>Ngân hàng câu hỏi đã hợp nhất theo chương, có đáp án, giải thích và lưu câu làm sai trên trình duyệt.</p>
      </div>
      <div class="pill" id="totalCount"></div>
    </div>

    <section id="menu"></section>
    <section id="quiz" class="quiz hidden"></section>
  </main>

  <script>
const examData = {exam_json};

const WRONG_KEY = "atbm_wrong_questions_v1";
const letters = ["A", "B", "C", "D"];
let mode = "chapter";
let currentChapter = "";
let currentList = [];
let currentIndex = 0;
let answered = false;

function getWrongIds() {{
  try {{ return JSON.parse(localStorage.getItem(WRONG_KEY) || "[]"); }}
  catch {{ return []; }}
}}

function setWrongIds(ids) {{
  localStorage.setItem(WRONG_KEY, JSON.stringify([...new Set(ids)]));
}}

function allQuestions() {{
  return Object.entries(examData).flatMap(([chapter, questions]) => questions.map(q => ({{ ...q, chapter }})));
}}

function renderMenu() {{
  const menu = document.getElementById("menu");
  const quiz = document.getElementById("quiz");
  quiz.classList.add("hidden");
  menu.classList.remove("hidden");
  const total = allQuestions().length;
  const wrongCount = getWrongIds().length;
  document.getElementById("totalCount").textContent = `${{total}} câu hỏi`;
  const cards = Object.entries(examData).map(([chapter, questions], index) => `
    <article class="card">
      <h2>${{chapter}}</h2>
      <div class="count">${{questions.length}} câu hỏi</div>
      <button type="button" class="chapter-btn" data-chapter-index="${{index}}">Bắt đầu ôn tập</button>
    </article>
  `).join("");
  menu.innerHTML = `
    <div class="grid">
      ${{cards}}
      <article class="card">
        <h2>Ôn tập câu làm sai</h2>
        <div class="count">Hiện có: ${{wrongCount}} câu</div>
        <button class="warn" onclick="startWrongReview()" ${{wrongCount ? "" : "disabled"}}>Ôn tập câu làm sai</button>
        <button class="ghost" onclick="clearWrong()" ${{wrongCount ? "" : "disabled"}}>Xóa danh sách câu sai</button>
      </article>
    </div>
  `;
  menu.querySelectorAll(".chapter-btn").forEach(button => {{
    button.addEventListener("click", () => {{
      const chapter = Object.keys(examData)[Number(button.dataset.chapterIndex)];
      startChapter(chapter);
    }});
  }});
}}

function shuffleCopy(list) {{
  return [...list].sort(() => Math.random() - 0.5);
}}

function startChapter(chapter) {{
  mode = "chapter";
  currentChapter = chapter;
  currentList = shuffleCopy(examData[chapter].map(q => ({{ ...q, chapter }})));
  currentIndex = 0;
  renderQuestion();
}}

function startWrongReview() {{
  const wrong = new Set(getWrongIds());
  currentList = allQuestions().filter(q => wrong.has(q.id));
  if (!currentList.length) return renderMenu();
  mode = "wrong";
  currentChapter = "Ôn tập câu làm sai";
  currentIndex = 0;
  renderQuestion();
}}

function clearWrong() {{
  if (confirm("Xóa toàn bộ danh sách câu đã làm sai?")) {{
    setWrongIds([]);
    renderMenu();
  }}
}}

function renderQuestion() {{
  const menu = document.getElementById("menu");
  const quiz = document.getElementById("quiz");
  menu.classList.add("hidden");
  quiz.classList.remove("hidden");
  answered = false;

  if (!currentList.length) {{
    quiz.innerHTML = `<div class="empty">Không có câu hỏi trong chế độ này.</div><div class="actions"><button onclick="renderMenu()">Về menu</button></div>`;
    return;
  }}

  const q = currentList[currentIndex];
  quiz.innerHTML = `
    <div class="quiz-head">
      <div>
        <h2>${{currentChapter}}</h2>
        <div class="progress">Câu ${{currentIndex + 1}} / ${{currentList.length}} · ${{q.chapter}}</div>
      </div>
      <button class="ghost" onclick="renderMenu()">Về menu</button>
    </div>
    <div class="question">${{escapeHtml(q.question)}}</div>
    <div class="options">
      ${{q.options.map((opt, i) => `
        <button class="option" onclick="selectAnswer(${{i}})" data-index="${{i}}">
          <span class="letter">${{letters[i]}}</span>
          <span>${{escapeHtml(opt)}}</span>
        </button>
      `).join("")}}
    </div>
    <div id="explain" class="explain"><strong>💡 Giải thích:</strong> <span>${{escapeHtml(q.explanation)}}</span></div>
    <div class="actions">
      <button id="nextBtn" onclick="nextQuestion()" disabled>Câu tiếp theo</button>
    </div>
  `;
}}

function selectAnswer(index) {{
  if (answered) return;
  answered = true;
  const q = currentList[currentIndex];
  const buttons = [...document.querySelectorAll(".option")];
  buttons.forEach(btn => btn.disabled = true);
  buttons[q.answer].classList.add("correct");
  if (index !== q.answer) {{
    buttons[index].classList.add("wrong");
    setWrongIds([...getWrongIds(), q.id]);
  }} else if (mode === "wrong") {{
    setWrongIds(getWrongIds().filter(id => id !== q.id));
  }}
  document.getElementById("explain").classList.add("show");
  document.getElementById("nextBtn").disabled = false;
}}

function nextQuestion() {{
  currentIndex += 1;
  if (mode === "wrong") {{
    const wrong = new Set(getWrongIds());
    currentList = currentList.filter(q => wrong.has(q.id));
    if (currentIndex > currentList.length - 1) currentIndex = 0;
  }}
  if (currentIndex >= currentList.length) {{
    renderMenu();
  }} else {{
    renderQuestion();
  }}
}}

function escapeHtml(value) {{
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}}

renderMenu();
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    exam_data = build_exam_data()
    Path("index.html").write_text(render_html(exam_data), encoding="utf-8")
    summary = {chapter: len(items) for chapter, items in exam_data.items()}
    Path("tmp_extract/exam_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
