# ReconKit

Bộ điều phối recon & quản lý lỗ hổng chạy nền (đồ án an toàn thông tin).

> ⚠️ Chỉ dùng trên tài sản của mình hoặc được uỷ quyền bằng văn bản (lab, mạng nội bộ, chương trình có scope hợp pháp).

## Tài liệu thiết kế (SDD v0.1)
https://claude.ai/artifact/69X8tKYCnShu8rYwzaNiV8

## Trạng thái
- [x] Tài liệu thiết kế
- [x] Chốt ngôn ngữ: **Python** (zero-dependency core — chỉ dùng thư viện chuẩn)
- [x] Lát cắt dọc: schema + scope + plugin nmap + orchestrator + storage + CLI

Lộ trình chi tiết: [`TASKS.md`](TASKS.md).

## Cài đặt (dev)

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows; macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest                        # 27 tests
```

## Dùng thử

```bash
# scope.txt: allowlist, mỗi dòng một target (host / IP / CIDR, '!' = deny)
printf 'scanme.lab\n10.0.0.0/24\n' > scope.txt

reconkit scan scanme.lab --scope scope.txt --db reconkit.db
```

Target ngoài allowlist sẽ bị từ chối ngay (exit code 3). Cần cài `nmap` trên PATH để
có kết quả service thật; không có nmap thì pipeline vẫn chạy và lưu run rỗng.
