# 🛡️ DFIR Report: Lockdown (CyberDefenders)

![Category](https://img.shields.io/badge/Category-DFIR%20%2F%20SOC-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Tools](https://img.shields.io/badge/Tools-Wireshark%20%7C%20Volatility%203%20%7C%20VirusTotal-success)

Báo cáo Điều tra Pháp y Kỹ thuật số & Ứng cứu Sự cố (DFIR) chi tiết cho bài lab **Lockdown** trên nền tảng CyberDefenders. Quá trình điều tra truy vết toàn bộ vòng đời tấn công từ bước rà quét mạng, khai thác giao thức SMB, cài cắm Web Shell cho đến phân tích pháp y bộ nhớ và dịch ngược mã độc.

**Người thực hiện:** Thiều Đình Hưng (B24DCCN267)  
**Định hướng:** SOC Analyst / Blue Team Security  

---

## 📑 Mục lục
1. [Tóm tắt Sự cố (Executive Summary)](#1-tóm-tắt-sự-cố-executive-summary)
2. [Tài liệu Điều tra (Forensic Artifacts)](#2-tài-liệu-điều-tra-forensic-artifacts)
3. [Phân tích Dòng thời gian & Kỹ thuật (Technical Investigation)](#3-phân-tích-dòng-thời-gian--kỹ-thuật-technical-investigation)
   - [Giai đoạn 1: Rà quét mạng & Thăm dò](#giai-đoạn-1-rà-quét-mạng--thăm-dò)
   - [Giai đoạn 2: Khai thác SMB & Rò rỉ dữ liệu](#giai-đoạn-2-khai-thác-smb--rò-rỉ-dữ-liệu)
   - [Giai đoạn 3: Triển khai Web Shell & C2](#giai-đoạn-3-triển-khai-web-shell--c2)
4. [Pháp y Bộ nhớ (Memory Forensics)](#4-pháp-y-bộ-nhớ-memory-forensics)
5. [Phân tích Mã độc (Malware Analysis)](#5-phân-tích-mã-độc-malware-analysis)
6. [Chỉ số Thỏa hiệp (IoCs)](#6-chỉ-số-thỏa-hiệp-iocs)
7. [Khuyến nghị Khắc phục (Remediation)](#7-khuyến-nghị-khắc-phục-remediation)

---

## 1. Tóm tắt Sự cố (Executive Summary)

Hệ thống giám sát phát hiện lưu lượng outbound bất thường từ máy chủ Microsoft IIS (`10.0.2.15`). Qua phân tích PCAP và RAM Dump, xác định kẻ tấn công (`10.0.2.4`) đã thực hiện rà quét cổng, khai thác cấu hình chia sẻ tệp SMB sai lệch bằng tài khoản đặc quyền (`WORKGROUP\root`). 

Kẻ tấn công đã đọc được tệp tin nhạy cảm `information.txt`, từ đó phát hiện thư mục SMB được liên kết trực tiếp với thư mục gốc của Web Server. Lợi dụng điểm yếu này, một Web Shell (`shell.aspx`) đã được tải lên và kích hoạt qua HTTP, thiết lập kết nối Reverse Shell về cổng `4443`. Nhằm duy trì quyền truy cập, một mã độc gián điệp thuộc họ **AgentTesla** (`updatenow.exe`) đã được chèn vào thư mục Startup của hệ thống.

---

## 2. Tài liệu Điều tra (Forensic Artifacts)

*   **Network Capture:** `capture.pcapng` (Lưu lượng mạng ghi lại quá trình xâm nhập).
*   **Memory Dump:** `memdump.mem` (Ảnh chụp RAM vật lý lấy bằng FTK Imager lúc `2024-09-10 06:09:42 UTC`).
*   **Malware Sample:** `updatenow.exe` (SHA-256: `c25a6673a...`).

---

## 3. Phân tích Dòng thời gian & Kỹ thuật (Technical Investigation)

### Giai đoạn 1: Rà quét mạng & Thăm dò
**MITRE ATT&CK:** *Network Service Discovery (T1046), Active Scanning (T1595)*

Thống kê IPv4 Conversations (`Statistics -> Conversations`) cho thấy sự đột biến lưu lượng (6,007 packets) giữa `10.0.2.4` và `10.0.2.15`. Kẻ tấn công sử dụng công cụ Nmap thực hiện **TCP SYN Scan** (gửi 1,076 gói tin SYN probes) để xác định các cổng mở: `80 (HTTP)`, `135 (RPC)`, `139 (NetBIOS)`, và `445 (SMB)`.

![Traffic Spike](PCAP_IPv4_Conversations_Traffic_Spike.png)
![TCP SYN Scan](PCAP_Filter_TCP_SYN_Scan_Probes.png)

Tiếp đó, kẻ tấn công chạy Nmap Scripting Engine (NSE) dò quét cổng 80, lộ rõ dấu vết `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine...)`.

![HTTP NSE Probes](PCAP_HTTP_Nmap_NSE_Enumeration.png)

### Giai đoạn 2: Khai thác SMB & Rò rỉ dữ liệu
**MITRE ATT&CK:** *Valid Accounts (T1078), SMB/Windows Admin Shares (T1021.002)*

Từ Frame `#2670`, kẻ tấn công chuyển hướng sang khai thác SMB, xác thực thành công qua NTLMSSP với tài khoản **`WORKGROUP\root`**. Sau khi dò quét các thư mục chia sẻ (Tree Connect tới `IPC$` và `Documents`), đối tượng phát hiện và thực hiện lệnh `Read Request` để lấy toàn bộ 150 byte của tệp `information.txt`.

![SMB Auth & Tree Connect](PCAP_SMB_Auth_TreeConnect_Enumeration.png)

Trích xuất và giải mã gói tin `Read Response`, thu được nội dung:
> *"This server setup is under development. We are trying to link the web server with SMB..."*

Nội dung này xác nhận lỗ hổng kiến trúc nghiêm trọng: **Thư mục SMB được map thẳng với IIS Webroot.**

![Decoded Info File](Evidence_Decoded_information_txt_Content.png)

### Giai đoạn 3: Triển khai Web Shell & C2
**MITRE ATT&CK:** *Web Shell (T1505.003), Non-Standard Port (T1571)*

Biết được thư mục SMB cho phép thực thi mã web, kẻ tấn công gửi lệnh SMB `Create` và `Write` để đẩy tệp **`shell.aspx`** lên thư mục `\Documents`.

![Webshell Upload](PCAP_SMB_Webshell_Upload_shell_aspx.png)

Ngay sau đó, một HTTP GET request (`GET /Documents/shell.aspx`) được gửi đến cổng 80 nhằm kích hoạt mã độc. Máy chủ IIS lập tức trả về `200 OK` và chủ động mở một kết nối **Reverse Shell** ngược lại IP kẻ tấn công tại cổng **`4443`**.

![HTTP Trigger & Reverse Shell](PCAP_HTTP_Trigger_Reverse_Shell_Port4443.png)

---

## 4. Pháp y Bộ nhớ (Memory Forensics)
**MITRE ATT&CK:** *Boot or Logon Autostart Execution (T1547.001)*

Sử dụng **Volatility 3** để phân tích file `memdump.mem` (Kernel Base: `0xf80079213000`). Quá trình phân tích cây tiến trình (`windows.pslist`) phát hiện sự bất thường: Tiến trình Worker của IIS `w3wp.exe` (PID 4332) đã sinh ra một tiến trình con lạ là **`updatenow.exe` (PID 900)**.

![Volatility Process Tree](Volatility_Process_Tree_w3wp_updatenow.png)

Kiểm tra tham số dòng lệnh của PID 900 (`windows.cmdline`), phát hiện mã độc đã tự sao chép vào thư mục **Startup** dùng chung của hệ thống để duy trì quyền điều khiển mỗi khi máy tính khởi động.

![Volatility Startup Persistence](Volatility_Persistence_Startup_Path_PID900.png)

---

## 5. Phân tích Mã độc (Malware Analysis)
**MITRE ATT&CK:** *Software Packing (T1027.002)*

Trích xuất tệp `updatenow.exe` và phân tích chuỗi tĩnh (`strings`), nhận thấy các section header `UPX0`, `UPX1`, xác nhận tệp bị nén làm rối bằng trình đóng gói **UPX phiên bản 3.91**.

![UPX Signatures](Malware_Strings_UPX_Packer_Signature.png)

Đoạn mã XML Application Manifest đính kèm bên trong tệp được cấu hình `requestedExecutionLevel level="asInvoker"`. Cơ chế này cho phép mã độc qua mặt cảnh báo UAC (User Account Control) của Windows để chạy ngầm hoàn toàn lén lút.

![UAC Manifest](Malware_Manifest_UAC_Bypass_Analysis.png)

Dựa trên mã băm SHA-256 (`c25a6673a24d...`), dữ liệu từ VirusTotal (57/71 detections) xác nhận đây là mã độc gián điệp/RAT thuộc họ **AgentTesla** (bọc qua AutoIt). Dữ liệu hành vi mạng của mẫu mã độc này chỉ ra tên miền C2 (Command & Control) là **`cp8nl.hyperhost.ua`**.

![AgentTesla Detection](VT_Detection_Malware_Family_AgentTesla.png)
![C2 Domain](VT_Network_C2_Contacted_Domains.png)

---

## 6. Chỉ số Thỏa hiệp (IoCs)

| Phân loại | Giá trị IoC | Ngữ cảnh thực thi |
| :--- | :--- | :--- |
| **Attacker IP** | `10.0.2.4` | IP thực hiện Port scan, SMB exploit và nhận Reverse Shell |
| **Victim IP** | `10.0.2.15` | Máy chủ Windows IIS bị xâm nhập |
| **C2 Domain** | `cp8nl.hyperhost.ua` | Máy chủ nhận dữ liệu đánh cắp từ AgentTesla |
| **Malware Hash** | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` | SHA-256 của `updatenow.exe` (AgentTesla/UPX 3.91) |
| **Web Shell** | `\Documents\shell.aspx` | Tệp mã độc kích hoạt RCE qua giao thức HTTP |
| **Persistence Path** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` | Vị trí lưu trữ mã độc tự khởi động |
| **Network Ports** | TCP `445`, TCP `80`, TCP `4443` | Cổng SMB, HTTP và Listener Port của Reverse Shell |

---

## 7. Khuyến nghị Khắc phục (Remediation)

1. **Cô lập & Loại bỏ (Containment & Eradication):**
   * Ngắt kết nối mạng máy chủ `10.0.2.15`, đưa tên miền `cp8nl.hyperhost.ua` vào blocklist trên hệ thống DNS/Firewall nội bộ.
   * Kill tiến trình PID `900` (`updatenow.exe`) và khởi động lại Application Pool của IIS.
   * Xóa vĩnh viễn file `shell.aspx` và tệp mã độc trong thư mục Startup.

2. **Khắc phục cấu hình & Quản lý danh tính (Hardening):**
   * **Tuyệt đối không** liên kết thư mục chia sẻ tệp SMB (có quyền ghi) với các Virtual Directory của Web Server.
   * Vô hiệu hóa quyền thực thi script (`Execute Permissions: None`) trên các thư mục cho phép người dùng upload tệp.
   * Đổi mật khẩu ngay lập tức cho tài khoản `root` và các tài khoản quản trị cục bộ khác (AgentTesla có khả năng đánh cắp thông tin đăng nhập trong bộ nhớ và trình duyệt).
   * Triển khai rules tường lửa chặn toàn bộ luồng mạng outbound đi ra các cổng không tiêu chuẩn (ví dụ: `4443`).
