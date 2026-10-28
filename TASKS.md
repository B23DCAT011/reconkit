# Lộ trình công việc — ReconKit

Mục tiêu: một **sản phẩm chạy được thật**, đủ chuẩn để đưa vào portfolio xin việc. Không
dùng lý do "chỉ là lab" để bỏ qua điểm yếu: chỗ nào đã nhìn ra thì sửa; đường tắt nào cố ý
giữ tạm phải ghi vào [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) (mã `G1`…`G20`).

Quy trình: mỗi task = 1 nhánh = 1 PR, merge trên GitHub theo thứ tự dưới đây. Lộ trình học
song song: [`docs/LO-TRINH-HOC.md`](docs/LO-TRINH-HOC.md).

Cập nhật lần cuối: 2026-10-28.

## Giai đoạn 1 — Lát cắt dọc (CLI) ✅

- [x] `chore/scaffold` — layout package, pyproject, pytest, lint. (PR #1)
- [x] `feat/schema` — `Asset` / `Service` / `Finding` + fingerprint. (PR #2)
- [x] `feat/scope` — allowlist/denylist. (PR #3)
- [x] `feat/plugin-nmap` — interface plugin + adapter nmap. (PR #4)
- [x] `feat/integration` — SQLite + orchestrator + CLI end-to-end. (PR #5)
- [x] `feat/cve` — bước CVE offline, nguồn CVE cắm được. (PR #6)
- [ ] `docs/known-gaps` — rà soát điểm yếu + lộ trình này.

## Giai đoạn 1.5 — Sửa nền móng (đang làm)

Sửa **trước khi** thêm tính năng mới, vì những thứ này càng để lâu càng khó sửa: hợp đồng
plugin (mọi plugin sau này phải theo), schema DB và fingerprint (dữ liệu tích lũy theo
format cũ), và lớp an toàn scope.

| # | Nhánh | Sửa | Vì sao ở vị trí này |
|---|---|---|---|
| F1 | `chore/ci` | G17 — GitHub Actions chạy pytest + ruff + mypy | Có trước để mọi PR sửa lỗi sau đều được kiểm tự động |
| F2 | `fix/scope-deny-overlap` | G4 (phần denylist bị vượt qua bằng dải IP) | Lỗi an toàn nghiêm trọng nhất, sửa nhỏ, độc lập |
| F3 | `fix/scan-errors` | G3 — bọc lỗi subprocess thành `ScanError`, CLI báo lỗi rõ | Độc lập; cần có trước F4 để plugin mới dùng luôn |
| F4 | `fix/no-plugin-available` | G2 — không plugin nào chạy được → lỗi, không lưu run "sạch" | Nhỏ; sửa cả câu sai trong README |
| F5 | `refactor/per-host-assets` | G1 + G16 — plugin trả kết quả theo từng host, điền `Asset.ip` | Đổi hợp đồng plugin: phải xong trước khi thêm subfinder/nuclei |
| F6 | `fix/scope-resolve` | G4 (phần DNS) — phân giải 1 lần, kiểm mọi IP, quét bằng IP, `--exclude`, kiểm lại sau quét | Cần F2 + F5 (có danh sách host để kiểm lại) |
| F7 | `refactor/storage-schema` | G5 + G14 + G15 — `finding.service_id`, `scan_run.status/error/tool_version`, index FK, cascade, `schema_version` | Đổi schema DB trước khi có dữ liệu thật tích lũy |
| F8 | `fix/fingerprint-identity` | G12 — fingerprint theo asset + port + protocol + CVE/rule id | Phải ổn định trước `feat/diff` |
| F9 | `feat/evidence` | G13 — lưu output gốc của tool, điền `evidence` | Cần F7 (schema) |

## Giai đoạn 2 — Mở rộng theo chuẩn thực tế

- [ ] CVE thật: khớp CPE + dải phiên bản, chuẩn hóa version (G8); `NvdCveSource` đồng bộ
      NVD API 2.0 về cache local (G9); `Finding.confidence` cho vấn đề backport (G10);
      CVSS score/vector, CWE, KEV, EPSS + xếp ưu tiên (G11).
- [ ] Scan profile `quick` / `full`, cấu hình tốc độ / timeout (G6, G7).
- [ ] `feat/diff` — so fingerprint giữa các lần quét: lỗi mới / đã hết / fix giả.
- [ ] Báo cáo JSON / HTML / SARIF (G18); `logging` + `--verbose` (G19).
- [ ] Plugin `subfinder` (subdomain, cần wildcard scope), `nuclei` (template checks).
- [ ] (Nâng cao) Quét có đăng nhập — đối chiếu gói đã cài với Debian/Ubuntu security tracker.

## Giai đoạn 3 — Dịch vụ chạy nền

- [ ] Scheduler + queue (Redis + RQ/Celery) + worker.
- [ ] API + thông báo.
- [ ] Đóng gói Docker Compose + volume + backup DB; README có demo (G20).
- [ ] Lab mục tiêu (Metasploitable / container có lỗ hổng) trong network nội bộ.
