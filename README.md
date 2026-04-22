# AegisFlow - NextGen DevSecOps Control Plane (ASPM)
**Phiên bản:** 2.0 (Modernized 2026) | **Tác giả:** Lê Tuấn Lương

AegisFlow là nền tảng **Application Security Posture Management (ASPM)** tiên phong tích hợp trí tuệ nhân tạo (Llama-3.3/4) để tự động hóa toàn bộ quy trình từ Quét lỗ hổng, Triage (Phân loại) đến Real-World Impact Analysis.

## 🌟 Tính năng đột phá (2026 Edition)

- **Interactive Security Control**: Điều khiển trực tiếp từ Dashboard. Nhập Target Path và API Key ngay trên giao diện để kích hoạt quét.
- **Penta-Core Scanner Engine**: Hợp nhất 5 "ông lớn" bảo mật: **Semgrep** (SAST), **Trivy** (SCA), **Gitleaks** (Secrets), **Checkov** (IaC), và **Nuclei** (DAST).
- **Parallel AI Triage (Multi-threaded)**: Phân tích hàng trăm lỗ hổng cùng lúc bằng AI với tốc độ "bàn thờ", giảm thời gian triage từ phút xuống giây.
- **Real Business Impact Analysis**: AI đọc hiểu logic dự án để đưa ra ảnh hưởng thực tế (ví dụ: "Lộ dữ liệu khách hàng", "Bypass đăng nhập") thay vì các mô tả lý thuyết.
- **OWASP Top 10: 2025 Ready**: Hỗ trợ đầy đủ các danh mục bảo mật mới nhất của năm 2025.

## 🚀 Quick Start (3 Phút)

### 1. Khởi chạy Backend & Dashboard
AegisFlow sử dụng server backend chuyên dụng để điều khiển hệ thống:
```bash
python3 server.py
```
Mở trình duyệt tại: [http://localhost:58082](http://localhost:58082)

### 2. Thực hiện Quét (Self-Service)
1. Truy cập tab **Scanner Control** trên Dashboard.
2. Nhập **Target Folder Path** (Vd: `./test-target-app`).
3. Nhập **Groq API Key** của bạn.
4. Nhấn **"Start Penta-Core Scan"** và theo dõi kết quả nhảy số theo thời gian thực.

### 3. Phân tích & Vá lỗi
- **Action Center**: Xem phân tích **Real Impact** cho từng lỗ hổng.
- **Developer Portal**: Lấy mã code đã được AI vá sẵn (Before/After) để áp dụng vào dự án.

---
**Organization**: CMC TSSG - DevSecOps Excellence Center
