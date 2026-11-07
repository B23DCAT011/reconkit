# Thiết kế & quyết định — ReconKit

Bản tóm tắt của tài liệu "Phân tích & Thiết kế hệ thống v0.2" (bản Word lưu ngoài git).
Các quyết định dưới đây được chốt ngày **2026-11-07**; muốn đổi thì sửa file này trong một PR
và ghi lý do.

Liên quan: [`TASKS.md`](../TASKS.md) (lộ trình) · [`KNOWN-GAPS.md`](KNOWN-GAPS.md) (điểm yếu G1–G20)

## Đích đến

Từ một công cụ CLI quét một mục tiêu, ReconKit trở thành **dịch vụ chạy nền**:

- quét định kỳ các mạng đã được uỷ quyền;
- **ghi nhớ** kết quả theo thời gian;
- phát hiện thay đổi: máy mới, cổng mới, lỗi mới, lỗi đã vá, **fix giả**;
- gửi cảnh báo;
- hiển thị **bản đồ bề mặt tấn công** trên web.

Lõi hiện tại (orchestrator + plugin + schema + storage) **không bị viết lại**. Nó trở thành
phần *worker*, các lớp mới chỉ bọc bên ngoài.

Bản đồ **không phải sơ đồ đi dây**. Nó là đồ thị quan hệ suy ra từ dữ liệu quét:

```
máy quét → hop (traceroute) → dải mạng → host → cổng/dịch vụ → lỗ hổng
                                           ↑
                               tên miền (phân giải DNS)
```

Vì thế bản đồ không hiện được những thứ máy quét không thấy, ví dụ switch lớp 2 hay đoạn
mạng bị firewall chặn.

## Nguyên tắc: dữ liệu đúng trước, giao diện sau

Với dữ liệu hiện tại thì chưa vẽ được bản đồ:

- quét một dải IP thì mọi máy bị gộp thành một asset (G1);
- finding đọc lại từ DB không biết thuộc cổng nào (G5);
- fingerprint có chứa `title`, nên chỉ cần sửa câu chữ là thành "lỗi mới" (G12).

Các nhánh F5, F7, F8 của Giai đoạn 1.5 chính là bước **tạo ra dữ liệu cho bản đồ**. Vì vậy
cột mốc M1 (giao diện đầu tiên) chỉ bắt đầu sau F9.

## Các quyết định đã chốt

| # | Câu hỏi | Chọn | Lý do |
|---|---|---|---|
| D1 | Mô hình dữ liệu | **Lai**: kho tài sản (`host`, `service`, `finding` có `first_seen` / `last_seen` / `status`) + lịch sử từng run (`observation`, `route_hop`, `evidence`, `finding_event`). Làm cùng `feat/diff` ở GĐ 2. | Có cả hiện trạng lẫn lịch sử, nên trả lời được "lỗi này mở bao lâu", "lần quét nào thấy gì". Không làm phình F7. |
| D2 | Giao diện đầu tiên | **Báo cáo HTML tĩnh** (M1), một file, mở offline | Thấy kết quả sớm, chưa phải dựng server và đăng nhập |
| D3 | Thư viện vẽ đồ thị | **Cytoscape.js** | *Compound node* (host nằm trong dải mạng) khớp đúng mô hình; dùng lại được ở web app |
| D4 | Web framework (GĐ 3) | **FastAPI** | Python có type hint như lõi; tự sinh tài liệu API |
| D5 | Frontend web app | **Quyết sau M1** (htmx hay React) | M1 sẽ cho thấy cần tương tác tới mức nào |
| D6 | Hàng đợi (GĐ 3) | **Redis + RQ** | Đơn giản, đủ cho vài worker |
| D7 | Traceroute | **Có**, plugin nmap bật `--traceroute` theo profile | Cần cho các hop trên bản đồ; đổi lại quét lâu hơn một chút |
| D8 | Lộ trình | **Chèn M1 sau F9** | Xem `TASKS.md` |

Ràng buộc chung: lõi vẫn **không phụ thuộc thư viện ngoài**. Thư viện web và hàng đợi đặt
trong gói tuỳ chọn `reconkit[server]`.

## Vòng đời một lỗ hổng (dựa trên fingerprint)

```
MỚI → ĐANG MỞ → ĐÃ BÁO SỬA → (run sau không thấy) → ĐÃ XÁC MINH VÁ → (thấy lại) → TÁI XUẤT HIỆN
                     │
                     └→ (run sau vẫn thấy) → FIX GIẢ  ⚠ cảnh báo mức cao nhất
ĐANG MỞ → (tự hết, chưa ai báo sửa) → BIẾN MẤT  (cần kiểm tra: đã vá hay máy đang tắt?)
ĐANG MỞ → CHẤP NHẬN RỦI RO  (phải có lý do + hạn xem lại)
```

"Không thấy" chưa chắc là "đã vá". Chỉ xác nhận đã vá khi host vẫn phản hồi mà lỗi không còn.
