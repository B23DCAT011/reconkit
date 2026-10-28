# Điểm yếu đã biết & kế hoạch nâng cấp — ReconKit

Danh sách các chỗ ReconKit **chưa đạt chuẩn sản phẩm thật**, kèm dẫn chứng trong code và
hướng sửa theo cách làm ngoài thực tế. Nguyên tắc: điểm yếu nào đã nhìn ra thì phải sửa,
không dùng lý do "chỉ là lab". Đường tắt nào cố ý giữ tạm thời cũng phải ghi vào đây.

Mỗi mục sửa xong = 1 nhánh = 1 PR; đánh dấu `[x]` và ghi số PR khi merge.

Rà soát lần đầu: 2026-10-28 (trên `main` sau PR #6).

---

## Mức 1 — Chạy sai / hỏng (ưu tiên sửa ngay)

- [ ] **G1. Quét dải CIDR gộp mọi máy thành một Asset.**
  - Dẫn chứng: `orchestrator.py` tạo một `Asset(host=target)` duy nhất; `NmapPlugin.parse_xml()`
    duyệt mọi `<host>` nhưng bỏ địa chỉ, trả về một danh sách `Service` phẳng.
  - Hậu quả: quét `10.0.0.0/24` ra một "máy" tên `10.0.0.0/24`; không biết cổng nào của máy
    nào; hai máy cùng lỗi sinh ra hai finding trùng fingerprint (mất một lỗi thật khi diff).
  - Sửa: plugin trả kết quả **theo từng host** (đọc `<address>`, `<hostnames>`); orchestrator
    gộp theo IP; điền `Asset.ip`.

- [ ] **G2. Không có nmap vẫn báo quét thành công.**
  - Dẫn chứng: `orchestrator.py` — `if not plugin.is_available(): continue`.
  - Hậu quả: lưu một lần quét 0 service, người dùng tưởng máy sạch.
  - Sửa: không plugin nào chạy được → báo lỗi rõ ràng, không lưu run "thành công".

- [ ] **G3. nmap lỗi / quá thời gian làm chương trình crash.**
  - Dẫn chứng: `cli.py` chỉ bắt `RuntimeError`; `subprocess.CalledProcessError` và
    `subprocess.TimeoutExpired` không phải `RuntimeError`.
  - Hậu quả: in traceback Python thay vì thông báo lỗi.
  - Sửa: plugin bọc lỗi subprocess thành một exception riêng (vd `ScanError`) kèm stderr;
    CLI bắt và trả exit code rõ ràng.

- [ ] **G4. Scope chỉ kiểm tra chuỗi nhập vào, không kiểm tra IP thật.**
  - Dẫn chứng: `scope.py` so khớp hostname, không phân giải DNS.
  - Hậu quả: domain trong allowlist nhưng trỏ tới IP ngoài phạm vi vẫn bị quét — lỗ hổng ở
    chính lớp an toàn.
  - **Lỗi đi kèm (đã xác nhận): denylist bị vượt qua bằng dải IP.** Scope
    `10.0.0.0/24` + `!10.0.0.1` → `is_allowed("10.0.0.1")` = False nhưng
    `is_allowed("10.0.0.0/24")` = True, nên nmap vẫn quét 10.0.0.1. Nguyên nhân: deny chỉ
    kiểm tra "target nằm *trong* deny" (`subnet_of`) thay vì "target *chồng lấn* deny"
    (`overlaps`).
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
- [ ] **G16. `Asset.ip` không bao giờ được điền.** (sửa cùng G1)

## Mức 3 — Hoàn thiện sản phẩm / portfolio

- [x] **G17. Chưa có CI.** Sửa: GitHub Actions chạy pytest + ruff + mypy cho mọi PR. (F1, `chore/ci`)
- [ ] **G18. Chỉ in ra màn hình.** Sửa: xuất báo cáo JSON / HTML / SARIF.
- [ ] **G19. Dùng `print`, chưa có logging.** Sửa: module `logging`, cờ `--verbose`.
- [ ] **G20. Chưa có Docker, README chưa có demo.** Sửa: Dockerfile, ảnh/GIF demo, mục
  "Known limitations" trong README trỏ về file này.
