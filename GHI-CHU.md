# Ghi chú học tập — ReconKit

File này lưu những gì đã tìm hiểu được cho dự án. Cứ bổ sung dần khi học thêm.

Tài liệu thiết kế đầy đủ: https://claude.ai/artifact/69X8tKYCnShu8rYwzaNiV8
Lộ trình học (các bài đã học + tóm tắt): [`docs/LO-TRINH-HOC.md`](docs/LO-TRINH-HOC.md)
Lộ trình làm dự án: [`TASKS.md`](TASKS.md) · Điểm yếu cần sửa: [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md)
Cập nhật lần cuối: 2026-09-16

---

## 1. "Quét" (scan) là gì — quét đối tượng nào

- Đầu vào: **domain** (`example.com`), **IP** (`203.0.113.10`), hoặc **dải IP / CIDR** (`10.0.0.0/24`).
- Bản chất: thăm dò hệ thống **qua mạng** để biết nó lộ ra cái gì. Tool **không đột nhập**, chỉ lập bản đồ + chỉ ra điểm yếu để đi vá.
- Trong đồ án: tự dựng máy ảo/container có lỗ hổng (vd Metasploitable) hoặc dải IP lab của mình để quét — hợp pháp, an toàn.

### Các giai đoạn recon (ví dụ với `example.com`)
| Giai đoạn | Quét cái gì | Ví dụ kết quả |
|---|---|---|
| Subdomain | Tìm tên miền con | `api.example.com`, `mail.example.com` |
| Live/Port | Host còn sống? Cổng nào mở? | port 443 (web), 22 (SSH) |
| Fingerprint | Phần mềm + phiên bản đang chạy | `nginx 1.18.0`, `OpenSSH 7.4` |
| CVE | Đối chiếu lỗ hổng đã công bố | `OpenSSH 7.4` → `CVE-2018-15473` |

Ẩn dụ tòa nhà: subdomain = mấy cửa; port = cửa nào mở; fingerprint = loại khóa; CVE = khóa đó có lỗi bẻ khóa nào chưa.

---

## 2. Kiến trúc: Pipeline + Plugin

- **Orchestrator**: biết thứ tự các *giai đoạn*, truyền dữ liệu. Không biết chi tiết tool nào.
- **Plugin/Adapter**: mỗi công cụ ngoài (subfinder, nmap, nuclei...) là 1 plugin, cùng implement một interface. Thêm tool = viết 1 plugin, không sửa lõi.
- **Schema chung** (`Asset`, `Service`, `Finding`): mọi module nói cùng "ngôn ngữ".
- **Lõi stateless + state trong DB**: điều kiện để (a) scale ngang sau này, (b) làm tính năng diff giữa các lần quét.

---

## 3. Mô hình cài đặt & vận hành

- Chọn **dịch vụ chạy nền, quét theo lịch** (scheduler tự đẩy job → worker quét → ghi DB). Người dùng không gõ lệnh mỗi lần.
- Đóng gói bằng **Docker Compose**: `docker compose up -d` là chạy. Máy đích chỉ cần Docker.
- Phức tạp hơn CLI ở 4 nhóm: **Scheduler / Queue+Worker / State bền+diff / API+thông báo**. Cách giảm phức tạp: làm bản CLI trước, bọc dần các lớp dịch vụ.

---

## 4. Hai chế độ chạy

| | Nội bộ (mặc định) | Ngoài (chạy tay) |
|---|---|---|
| Mục tiêu | Máy/dải IP nội bộ | Domain người dùng tự nhập |
| Kích hoạt | Scheduler theo lịch | Bấm nút trên dashboard |
| Scope | Allowlist sẵn | Phải xác nhận được phép |

→ Cùng một pipeline, chỉ khác cửa vào + mức kiểm soát scope.

---

## 5. Xác minh vá bằng fingerprint (hash)

- Nén mỗi **finding** thành 1 mã hash ổn định (băm theo *từng phát hiện*, KHÔNG băm cả domain).
- **Chuẩn hóa** trước khi băm: bỏ trường nhiễu (timestamp, session id...) để hash không đổi vô nghĩa.
- Leo thang cảnh báo:
  - Hash trùng + ticket "đã fix" → 🔴 **fix giả**, cảnh báo căng.
  - Hash mới xuất hiện → ⚠️ bề mặt tấn công mới.
  - Hash biến mất → có thể đã vá (chỉ là *tín hiệu*, không chắc chắn).
- Chỉ cần thêm cột `fingerprint` vào bảng `finding`.

---

## 6. Cơ sở dữ liệu trong Docker — có "đảm bảo" không?

Không tự động; phải cấu hình đúng 3 lớp:
1. **Volume (bắt buộc)** — filesystem container là tạm thời, không có volume thì rebuild/crash mất sạch.
2. **DB đúng số worker** — 1 tiến trình: SQLite ổn; nhiều worker: PostgreSQL.
3. **Backup định kỳ** — máy hỏng thì mất dù có volume → dump ra ngoài.
- Toàn vẹn: ghi trọn 1 `scan_run` trong 1 transaction (worker chết → rollback).

---

## 7. Thuật ngữ cần nhớ

- **Port**: cổng dịch vụ trên một máy (443 = HTTPS, 22 = SSH...).
- **Banner**: chuỗi máy trả về, thường lộ tên + phiên bản phần mềm.
- **Fingerprint**: đoán phần mềm/phiên bản từ banner/header.
- **CPE**: định danh chuẩn cho sản phẩm (dùng để map CVE tự động).
- **CVE**: mã lỗ hổng đã công bố. **CVSS**: điểm mức độ nghiêm trọng.
- **EPSS**: xác suất bị khai thác thực tế. **KEV** (CISA): danh sách đã bị khai thác thật.
- **Scope**: phạm vi được phép quét (allowlist/denylist).
- **Idempotency**: chạy lại không nhân đôi dữ liệu.

---

## 8. Quyết định còn để ngỏ

- [ ] Ngôn ngữ: **Python** (viết nhanh, report mạnh) vs **Go** (concurrency, cùng nhà với tool tích hợp).
- [ ] Engine queue (Redis + RQ/Celery?).
- [ ] Phạm vi dashboard.

## 9. Cần tìm hiểu thêm (điền dần)

- [ ] Cách nmap/subfinder/nuclei hoạt động & parse output của chúng.
- [ ] NVD API lấy dữ liệu CVE như thế nào.
- [ ] Docker Compose cơ bản (service, volume, network).
- [ ] Repository pattern để tách logic khỏi engine DB.
- [ ] (ghi thêm...)
