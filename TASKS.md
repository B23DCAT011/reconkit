# Lộ trình công việc — ReconKit

Chiến lược: dựng **một lát cắt dọc (vertical slice)** chạy được trước — một lệnh CLI quét 1
target trong lab và lưu kết quả theo schema chung — rồi mới bọc dần các lớp dịch vụ
(scheduler, queue, API, dashboard) như mô tả trong `GHI-CHU.md`.

Mỗi task = 1 nhánh = 1 PR, merge lần lượt theo thứ tự dưới đây.

## Giai đoạn 1 — Lát cắt dọc (CLI)

- [x] `chore/scaffold` — cấu hình dự án: layout package, pyproject, pytest, lint.
- [ ] `feat/schema` — kiểu dữ liệu chung `Asset` / `Service` / `Finding` + fingerprint.
- [ ] `feat/scope` — cổng an toàn: chỉ cho quét target nằm trong allowlist.
- [ ] `feat/plugin-nmap` — interface plugin + adapter nmap (parse output `-oX`).
- [ ] `feat/integration` — storage SQLite + orchestrator + CLI chạy end-to-end.

## Giai đoạn 2 — Mở rộng (sau khi slice chạy)

- [ ] Plugin `subfinder` (subdomain), `nuclei` (template checks).
- [ ] Stage CVE: map `Service` → CPE → CVE (NVD API), sinh `Finding`.
- [ ] Diff giữa các lần quét dựa trên `fingerprint` (fix giả / bề mặt mới).

## Giai đoạn 3 — Dịch vụ chạy nền

- [ ] Scheduler + queue (Redis + RQ/Celery) + worker.
- [ ] API + thông báo.
- [ ] Đóng gói Docker Compose + volume + backup DB.
- [ ] Lab mục tiêu (Metasploitable / container có lỗ hổng) trong network nội bộ.
