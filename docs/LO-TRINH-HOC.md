# Lộ trình học — ReconKit

Học song song với làm: mỗi bài gắn với một phần code. Mỗi bài có 3 phần — **thuật ngữ**,
**thực tế người ta làm thế nào**, **ReconKit có theo không** — và kết luận được ghi thành
việc cần làm trong [`TASKS.md`](../TASKS.md) / [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

Ghi chú thiết kế ban đầu: [`GHI-CHU.md`](../GHI-CHU.md).

| Bài | Chủ đề | Gắn với code | Trạng thái |
|---|---|---|---|
| 1 | Recon: quét cổng & nhận diện dịch vụ | `plugins/nmap.py`, `Service` | ✅ 2026-10-28 |
| — | Phân tích lỗi Mức 1: G1 CIDR, G4 scope/DNS, G2, G3, G5 | orchestrator, scope, cli, storage | ✅ 2026-10-28 |
| 2 | CVE, CPE, CVSS, NVD, KEV, EPSS | `cve.py`, `cve_seed.json` | ✅ 2026-10-28 |
| 3 | Scope & pháp lý: Rules of Engagement, xin phép quét, luật VN | `scope.py` | ⏭️ tiếp theo |
| 4 | Vòng đời finding: mới / còn mở / đã vá / tái xuất hiện | fingerprint, `feat/diff` | |
| 5 | Kiến trúc: pipeline, plugin, repository, transaction, migration | orchestrator, storage | |
| 6 | Công cụ thật (OpenVAS, Nessus, nuclei, DefectDojo) so với ReconKit | toàn dự án | |

---

## Bài 1 — Recon: quét cổng & nhận diện dịch vụ

- **Attack surface**: mọi chỗ kẻ tấn công chạm được. ReconKit = lập bản đồ attack surface và
  theo dõi nó thay đổi.
- **Passive** (tra nguồn công khai, vd subfinder) vs **active** (gửi gói tin, vd nmap → bắt buộc
  có scope).
- Trạng thái cổng: `open` / `closed` (máy trả lời, không có gì nghe) / `filtered` (firewall chặn).
- `-sV` = gửi probe, so câu trả lời với cơ sở mẫu để **đoán** product/version; **banner** là chuỗi
  dịch vụ tự gửi ra.
- Thực tế: quét cổng nhanh (masscan/naabu) rồi mới `-sV` trên cổng mở; quét đủ 65.535 cổng
  (`-p-`) — nmap mặc định chỉ 1.000 cổng; không tin tuyệt đối version (backport); tốc độ quét là
  thông số thỏa thuận với khách hàng.

## Phân tích lỗi Mức 1 (chi tiết trong KNOWN-GAPS.md)

- **CIDR** `10.0.0.0/24` = 256 địa chỉ. Đơn vị chuẩn trong scanner là **một máy (IP)**, không
  phải target. Gộp cả dải thành 1 asset → không biết lỗi ở máy nào, hai lỗi ở hai máy trùng
  fingerprint (G1).
- **DNS**: một tên → nhiều IP, IP đổi được, tên của mình ≠ máy của mình (CDN, SaaS).
  **TOCTOU**: kiểm tra một lúc, dùng một lúc khác. Đúng: phân giải 1 lần, kiểm mọi IP, quét
  bằng IP. Denylist phải kiểm **chồng lấn** (`overlaps`), không phải **nằm trong**
  (`subnet_of`). **Defense in depth**: kiểm trước, trong và sau khi quét (G4).
- **Fail loud vs fail silent**: công cụ bảo mật tệ nhất là báo "0 lỗi" khi thực ra chưa quét (G2).
- **Cây exception**: `except RuntimeError` không bắt `CalledProcessError` / `TimeoutExpired`.
  Bọc lỗi tại ranh giới (plugin) thành một loại lỗi của mình (G3).
- **Khóa ngoại**: finding phải trỏ tới service, nếu không đọc lại từ DB sẽ mất "lỗi ở cổng nào" (G5).
- Bài học chung: công cụ bảo mật được đánh giá trước hết ở chỗ **có nói thật không**.

## Bài 2 — CVE, CPE, CVSS, NVD, KEV, EPSS

- **CVE** = mã lỗ hổng; **CWE** = loại lỗi (vd CWE-22 path traversal); **CPE** = tên chuẩn phần
  mềm `cpe:2.3:a:vendor:product:version:…`; **CVSS** = điểm 0–10 + vector; **NVD** (NIST) làm giàu
  CVE bằng CPE/CVSS/CWE; **KEV** (CISA) = đã bị khai thác thật; **EPSS** (FIRST) = xác suất bị
  khai thác trong 30 ngày.
- CVSS đo **mức nghiêm trọng nếu bị khai thác**, không đo **khả năng bị khai thác** → ưu tiên
  KEV → EPSS → CVSS.
- NVD ghi **dải phiên bản** trên CPE (`versionEndIncluding: 7.7`), không ghi từng version. So
  version theo số (`7.10` > `7.9`), không theo chuỗi.
- nmap thật trả `7.4p1 Debian 10+deb9u7` → phải chuẩn hóa. **Backport**: distro vá nhưng giữ số
  version → quét từ xa chỉ là đoán (`confidence: tentative`); quét có đăng nhập mới chính xác.
- Thực tế: đồng bộ NVD về cache local (rate limit, offline, tái lập kết quả), không hỏi NVD mỗi
  lần quét; không phụ thuộc một nguồn (NVD tồn đọng từ 2024). **OSV** mạnh cho thư viện mã nguồn mở.

## Bài 3 — (hôm sau) Scope & pháp lý
