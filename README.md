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
pytest
```

## Dùng thử

```bash
# scope.txt: allowlist, mỗi dòng một target (host / IP / CIDR, '!' = deny)
printf 'scanme.lab\n10.0.0.0/24\n' > scope.txt

reconkit scan scanme.lab --scope scope.txt --db reconkit.db
```

Cần cài `nmap` trên PATH. ReconKit chỉ lưu một lần quét khi nó thực sự quét được: một run
0 service nghĩa là "đã quét và không thấy gì", không bao giờ là "chưa quét".

| Exit code | Ý nghĩa |
|---|---|
| 0 | Quét xong, kết quả đã lưu vào DB |
| 2 | Đầu vào sai: không thấy file scope, hoặc file scope có dòng không hợp lệ |
| 3 | Từ chối: target nằm ngoài scope |
| 4 | Quét thất bại, **không lưu gì**: thiếu nmap, nmap lỗi / quá thời gian, không phân giải được tên, không host nào trả lời |
