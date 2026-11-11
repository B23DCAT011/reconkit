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
| 3 | Scope & pháp lý: Rules of Engagement, xin phép quét, luật VN | `scope.py` | ✅ 2026-11-11 |
| 4 | Vòng đời finding: mới / còn mở / đã vá / tái xuất hiện | fingerprint, `feat/diff` | ⏭️ tiếp theo |
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

## Bài 3 — Scope & pháp lý

> Ghi chú học tập, không phải tư vấn pháp lý. Luật thay đổi: trước khi quét thật cho một tổ
> chức, đọc văn bản gốc và hỏi người có chuyên môn pháp lý.

**Thuật ngữ**

- **Authorization (uỷ quyền)**: sự cho phép **bằng văn bản** của người **có quyền** với hệ
  thống. Đây là ranh giới duy nhất giữa pentest và tấn công — kỹ thuật thì giống hệt nhau.
- **Scope**: danh sách cụ thể được phép đụng vào (IP, dải, domain) và **không** được đụng vào
  (out-of-scope). Trong ReconKit: file `--scope`, dòng `!` là deny.
- **Rules of Engagement (RoE)**: "luật chơi" của một đợt kiểm thử — scope, khung giờ được quét,
  kỹ thuật bị cấm (DoS, social engineering…), giới hạn tốc độ, đầu mối liên lạc khi có sự cố,
  cách xử lý dữ liệu nhạy cảm lỡ nhìn thấy.
- **Bug bounty / VDP**: chương trình công khai cho phép người ngoài tìm lỗi, kèm scope và
  **safe harbor** (cam kết không kiện nếu làm đúng luật chơi). Không có chương trình = không
  có phép, kể cả khi "chỉ muốn báo lỗi giúp".

**Thực tế người ta làm thế nào**

- Không có giấy thì không quét. Người ký phải là **chủ thật** của hệ thống: nhân viên IT
  không tự cho phép được; khách hàng thuê cloud/hosting không cho phép thay nhà cung cấp
  được (mỗi cloud có chính sách pentest riêng); một domain trỏ về CDN/SaaS thì IP đó là của
  bên thứ ba.
- Scope ghi bằng **IP/dải cụ thể**, và kiểm tra lại lúc quét: tên miền có thể đổi IP giữa lúc
  ký và lúc quét (đây chính là G4 phần DNS → F6).
- Mọi lần quét đều để lại **dấu vết kiểm toán**: ai quét, lúc nào, từ IP nào, vào đâu, theo
  giấy phép nào. Khi bên kia báo sự cố, đây là thứ chứng minh mình làm đúng phạm vi.
- Quét cổng **chưa** phải là xâm nhập, nhưng **không vì thế mà hợp pháp**: nó là bước chuẩn
  bị của tấn công, gây cảnh báo ở bên bị quét, có thể vi phạm điều khoản của nhà mạng/cloud,
  và quét mạnh có thể làm treo thiết bị yếu (khi đó là gây rối loạn hoạt động, không còn là
  "chỉ nhìn"). Nơi luyện tập hợp pháp: máy của mình, lab ảo (Metasploitable, DVWA),
  `scanme.nmap.org` (theo đúng điều kiện họ ghi), HackTheBox / TryHackMe.

**Luật Việt Nam (các văn bản cần biết tên)**

- **Bộ luật Hình sự 2015 (sửa đổi 2017), Điều 285–290** — nhóm tội phạm công nghệ thông tin:
  285 (sản xuất, mua bán công cụ, phần mềm để dùng vào mục đích trái pháp luật), 286 (phát
  tán chương trình gây hại), 287 (cản trở, gây rối loạn hoạt động mạng), 288 (đưa hoặc sử
  dụng trái phép thông tin mạng), **289 (xâm nhập trái phép vào mạng máy tính, mạng viễn
  thông hoặc phương tiện điện tử của người khác)**, 290 (dùng mạng để chiếm đoạt tài sản).
- Điều 289 khoản 1 (theo Nghị quyết 80/2021/NQ-UBTVQH15 giải thích): cố ý **vượt qua cảnh
  báo, mã truy cập, tường lửa, sử dụng quyền quản trị của người khác hoặc bằng phương thức
  khác** để xâm nhập trái phép. Từ khoá là *trái phép* — có uỷ quyền hợp lệ thì không còn
  yếu tố này.
- **Luật An ninh mạng 2025 (116/2025/QH15)**, hiệu lực 01/7/2026, thay cho cả Luật An toàn
  thông tin mạng 2015 và Luật An ninh mạng 2018; các hành vi bị nghiêm cấm nằm ở Điều 7.
  (Tài liệu cũ hơn giữa 2026 vẫn dẫn hai luật cũ.)
- Mức nhẹ hơn hình sự là xử phạt hành chính (nghị định về xử phạt trong lĩnh vực viễn thông,
  công nghệ thông tin). Ở nước khác: CFAA (Mỹ), Computer Misuse Act (Anh) — cùng nguyên tắc
  "không có phép = phạm luật".

**ReconKit có theo không**

| Thực tế yêu cầu | ReconKit hiện tại |
|---|---|
| Không quét khi chưa khai báo phạm vi | ✅ `--scope` bắt buộc; ngoài allowlist → từ chối, exit 3 |
| Có danh sách loại trừ, lỗi thì nghiêng về an toàn | ✅ deny `!`, dải chồng lấn deny bị từ chối, dòng sai → dừng (F2) |
| Kiểm tra IP thật, không chỉ tên | ❌ G4 phần DNS → **F6** |
| Kiểm lại từng host trong kết quả | ❌ → **F6** (cần cho subfinder sau này) |
| Giới hạn tốc độ / khung giờ theo RoE | ❌ cố định `-T4` (G7); chưa có khung giờ (G21) |
| Dấu vết kiểm toán: ai, lúc nào, theo giấy phép nào | ❌ `scan_run` chỉ có target + thời gian → **G21** |
| Nhắc người dùng về trách nhiệm pháp lý | ⚠️ chỉ có một dòng cảnh báo trong README |

Kết luận: file scope của ReconKit là **cái khoá kỹ thuật**, không phải **giấy phép**. Công cụ
chỉ biết "người dùng khai là được phép"; trách nhiệm có giấy thật vẫn ở người chạy. Việc của
công cụ là làm cho quét nhầm thật khó (F2, F6) và để lại bằng chứng đã làm đúng (G21).
