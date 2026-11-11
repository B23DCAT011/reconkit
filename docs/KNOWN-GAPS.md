# Điểm yếu đã biết & kế hoạch nâng cấp — ReconKit

Danh sách các chỗ ReconKit **chưa đạt chuẩn sản phẩm thật**, kèm dẫn chứng trong code và
hướng sửa theo cách làm ngoài thực tế. Nguyên tắc: điểm yếu nào đã nhìn ra thì phải sửa,
không dùng lý do "chỉ là lab". Đường tắt nào cố ý giữ tạm thời cũng phải ghi vào đây.

Mỗi mục sửa xong = 1 nhánh = 1 PR; đánh dấu `[x]` và ghi số PR khi merge.

Rà soát lần đầu: 2026-10-28 (trên `main` sau PR #6).

---

## Mức 1 — Chạy sai / hỏng (ưu tiên sửa ngay)

- [x] **G1. Quét dải CIDR gộp mọi máy thành một Asset.**
  - ✅ **Đã sửa (F5)**: hợp đồng plugin đổi thành `scan(target) -> list[Asset]`, mỗi host
    một `Asset`. Plugin nmap đọc `<status>`, `<address>`, `<hostnames>`: `Asset.ip` là địa
    chỉ IPv4/IPv6 (bỏ qua MAC), `Asset.host` là tên người dùng gõ (`type="user"`) nếu có,
    không thì là IP; host up mà không có cổng mở vẫn là một asset. Orchestrator gộp báo cáo
    của nhiều plugin về cùng một máy (so IP; thiếu IP thì so tên). CLI in theo từng host.
    Đã kiểm với nmap thật: `127.0.0.0/30` → 4 asset riêng.
  - Còn lại: tên PTR và trường hợp một máy nhiều hostname chưa được lưu (cần thêm cột →
    F7). Host được trả về chưa được kiểm lại với scope (→ F6).
  - Dẫn chứng: `orchestrator.py` tạo một `Asset(host=target)` duy nhất; `NmapPlugin.parse_xml()`
    duyệt mọi `<host>` nhưng bỏ địa chỉ, trả về một danh sách `Service` phẳng.
  - Hậu quả: quét `10.0.0.0/24` ra một "máy" tên `10.0.0.0/24`; không biết cổng nào của máy
    nào; hai máy cùng lỗi sinh ra hai finding trùng fingerprint (mất một lỗi thật khi diff).
  - Sửa: plugin trả kết quả **theo từng host** (đọc `<address>`, `<hostnames>`); orchestrator
    gộp theo IP; điền `Asset.ip`.

- [x] **G2. Không có nmap vẫn báo quét thành công.**
  - Dẫn chứng: `orchestrator.py` — `if not plugin.is_available(): continue`.
  - Hậu quả: lưu một lần quét 0 service, người dùng tưởng máy sạch.
  - Sửa: không plugin nào chạy được → báo lỗi rõ ràng, không lưu run "thành công".
  - **Lỗi đi kèm (đã xác nhận với nmap 7.92): nmap thoát code 0 dù không quét được gì.**
    Tên không phân giải được → `<hosts up="0" down="0" total="0"/>`, lý do chỉ nằm ở stderr.
    Host không trả lời → `<hosts up="0" down="1" total="1"/>`, không có thẻ `<host>` nào.
    Cả hai trước đây đều được lưu thành run 0 service.
  - ✅ **Đã sửa (F4)**: orchestrator ném `NoPluginAvailableError` khi không plugin nào chạy
    được (kiểm tra *sau* scope); plugin bị bỏ qua trong khi plugin khác vẫn chạy được ghi
    vào `ScanRun.skipped_plugins` và CLI in cảnh báo. Plugin nmap đọc `runstats/hosts`:
    `total = 0` hoặc `up = 0` → `ScanError`. CLI trả exit code 4, không lưu run.
  - Còn lại: `skipped_plugins` chưa lưu vào DB (→ F7, `scan_run.status`). "Host không trả
    lời" hiện là *lỗi* vì chưa có chỗ ghi trạng thái từng host; khi có (F7, D1) nó sẽ thành
    một quan sát được lưu lại. Quét dải mà chỉ một phần host trả lời: từ F5 CLI in
    "N responded of M addresses", nhưng chưa liệt kê địa chỉ nào im lặng (→ D1).

- [x] **G3. nmap lỗi / quá thời gian làm chương trình crash.**
  - Dẫn chứng: `cli.py` chỉ bắt `RuntimeError`; `subprocess.CalledProcessError` và
    `subprocess.TimeoutExpired` không phải `RuntimeError`.
  - Hậu quả: in traceback Python thay vì thông báo lỗi.
  - Sửa: plugin bọc lỗi subprocess thành một exception riêng (vd `ScanError`) kèm stderr;
    CLI bắt và trả exit code rõ ràng.
  - ✅ **Đã sửa (F3)**: `ScanError` nằm trong `plugins/base.py` (thuộc hợp đồng plugin).
    Plugin nmap bọc 5 trường hợp: thiếu binary, không khởi chạy được (`OSError`), exit code
    khác 0 (kèm stderr của nmap), quá thời gian, XML hỏng / bị cắt. CLI in
    `scan failed [nmap]: …`, trả exit code 4 và **không lưu run** vào DB. Output của nmap
    được đọc theo UTF-8 thay vì codepage của Windows.

- [ ] **G4. Scope chỉ kiểm tra chuỗi nhập vào, không kiểm tra IP thật.**
  - Dẫn chứng: `scope.py` so khớp hostname, không phân giải DNS.
  - Hậu quả: domain trong allowlist nhưng trỏ tới IP ngoài phạm vi vẫn bị quét — lỗ hổng ở
    chính lớp an toàn.
  - **Lỗi đi kèm (đã xác nhận): denylist bị vượt qua bằng dải IP.** Scope
    `10.0.0.0/24` + `!10.0.0.1` → `is_allowed("10.0.0.1")` = False nhưng
    `is_allowed("10.0.0.0/24")` = True, nên nmap vẫn quét 10.0.0.1. Nguyên nhân: deny chỉ
    kiểm tra "target nằm *trong* deny" (`subnet_of`) thay vì "target *chồng lấn* deny"
    (`overlaps`). ✅ **Đã sửa (F2)**: dải chồng lấn deny bị từ chối cả dải (fail closed).
  - **Lỗi đi kèm thứ hai (đã xác nhận): chú thích cuối dòng vô hiệu hóa dòng deny.**
    `!10.0.0.1   # router` không parse được thành IP nên bị lưu thành *hostname* rác, IP
    vẫn quét được. Gốc rễ: chuỗi nào không phải IP thì bị *đoán* là hostname. ✅ **Đã sửa
    (F2)**: `#` là chú thích ở mọi vị trí; entry không hợp lệ → `ScopeError` kèm số dòng,
    CLI exit 2.
  - Khác: nmap mặc định chỉ quét IP đầu tiên của hostname; DNS có thể đổi giữa lúc kiểm tra
    và lúc quét (TOCTOU); chưa hỗ trợ wildcard `*.example.com`.
  - Sửa: phân giải hostname **một lần**, **mọi IP** phải nằm trong scope, rồi đưa **IP**
    (không phải hostname) cho nmap; dải chồng lấn deny → truyền `--exclude` cho nmap;
    kiểm tra lại scope cho từng host trong kết quả (liên quan G1, subfinder sau này).

- [ ] **G5. Đọc finding từ DB mất thông tin service.**
  - Dẫn chứng: bảng `finding` không có cột `service_id`; `Storage.findings_for_run()` trả
    `Finding.service = None`.
  - Hậu quả: không biết lỗi nằm ở cổng nào; diff giữa các lần quét thiếu dữ liệu.
  - Sửa: thêm `finding.service_id REFERENCES service(id)` và đọc lại đầy đủ.

## Mức 2 — Thiếu so với công cụ thật

- [ ] **G6. Chỉ quét 1.000 cổng phổ biến** (mặc định của nmap).
  Sửa: scan profile `quick` / `full` (`-p-`); quét định kỳ dùng `full`.
- [ ] **G7. Cố định `-T4` và timeout 300s.**
  Sửa: cấu hình được tốc độ, timeout, rate limit (file config + cờ CLI).
- [ ] **G8. CVE khớp đúng phiên bản, bỏ qua CPE.**
  Sửa: khớp theo CPE + **dải phiên bản** (`versionStartIncluding`, `versionEndExcluding`…).
  - Thêm: nmap thật trả version kiểu `7.4p1 Debian 10+deb9u7`, không phải `7.4` → so khớp
    chính xác với seed **trượt ngay cả ví dụ OpenSSH 7.4**. `tests/data/nmap_sample.xml` đang
    dùng version "sạch" (`7.4`) nên test không bắt được. Cần chuẩn hóa version (tách upstream
    `7.4p1` khỏi hậu tố distro) và so sánh theo số, không theo chuỗi (`7.10` > `7.9`).
    Fixture test nên lấy từ output nmap thật.
  - Tên sản phẩm của nmap ≠ tên trong CPE (`Apache httpd` ↔ `apache:http_server`) — thêm lý
    do phải khớp theo CPE thay vì theo tên.
- [ ] **G9. Dữ liệu CVE chỉ là seed 4 dòng.**
  Sửa: `NvdCveSource` đồng bộ NVD API 2.0 về cache local (có API key, tôn trọng rate limit);
  cân nhắc OSV, CISA KEV.
- [ ] **G10. Không phân biệt "chắc chắn" và "có thể" bị lỗi** (backport của distro giữ nguyên
  số phiên bản). Sửa: thêm `Finding.confidence` (`tentative` / `confirmed`).
- [ ] **G11. Severity là nhãn gõ tay.** Sửa: lưu điểm + vector CVSS; cân nhắc EPSS để ưu tiên.
- [ ] **G12. Fingerprint có `title`.** Sửa câu chữ title là lỗi cũ thành "lỗi mới".
  Sửa: định danh theo asset + port + protocol + CVE/rule id (đổi schema fingerprint có version).
- [ ] **G13. Không lưu bằng chứng** (`evidence` rỗng, XML nmap bị bỏ).
  Sửa: lưu output gốc của tool theo run; điền `evidence` cho finding.
- [ ] **G14. `scan_run` không có trạng thái / lỗi / phiên bản tool.**
  Sửa: thêm `status`, `error`, `tool_version`.
- [ ] **G15. Thiếu index khóa ngoại, thiếu `ON DELETE CASCADE`, chưa có migration.**
  Sửa: index FK, cascade, bảng `schema_version` + migration đơn giản.
- [x] **G16. `Asset.ip` không bao giờ được điền.** (sửa cùng G1) ✅ F5: plugin nmap điền từ
  `<address addrtype="ipv4|ipv6">`.
- [ ] **G21. Không có dấu vết kiểm toán về uỷ quyền.** (từ Bài 3)
  - Dẫn chứng: `scan_run` chỉ lưu `target`, `started_at`, `finished_at`. Không biết lần quét
    đó dùng file scope nào (nội dung lúc đó ra sao), ai chạy, theo giấy phép / đợt kiểm thử
    nào. Scope cũng không có khung giờ được phép quét.
  - Hậu quả: khi bên bị quét hỏi "ai cho phép quét máy này lúc 2 giờ sáng", DB không trả lời
    được; sửa file scope sau khi quét là mất dấu.
  - Sửa: lưu vào `scan_run` mã băm SHA-256 + đường dẫn của file scope, người chạy, và một
    trường tham chiếu giấy phép (`--engagement`); cân nhắc khung giờ trong file scope.

## Mức 3 — Hoàn thiện sản phẩm / portfolio

- [x] **G17. Chưa có CI.** Sửa: GitHub Actions chạy pytest + ruff + mypy cho mọi PR. (F1, `chore/ci`)
- [ ] **G18. Chỉ in ra màn hình.** Sửa: xuất báo cáo JSON / HTML / SARIF.
- [ ] **G19. Dùng `print`, chưa có logging.** Sửa: module `logging`, cờ `--verbose`.
- [ ] **G20. Chưa có Docker, README chưa có demo.** Sửa: Dockerfile, ảnh/GIF demo, mục
  "Known limitations" trong README trỏ về file này.
