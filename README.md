# AegisFlow - Enterprise ASPM & DevSecOps Control Plane
**Tác giả:** Lê Tuấn Lương

AegisFlow là nền tảng **Application Security Posture Management (ASPM)** chuẩn doanh nghiệp, tích hợp trí tuệ nhân tạo (Llama-3.3) để tự động hóa toàn bộ quy trình từ thu thập dữ liệu (Ingestion), Phân loại (Triage) đến Đề xuất sửa lỗi (Remediation).

## 🌟 Tính năng đột phá (2026 Enterprise Edition)

- **100% DevSecOps Coverage (8/8 Mảng)**: Bao phủ toàn diện ma trận bảo mật: SAST (Code), SCA (Thư viện), IaC (Hạ tầng), Secrets (Thông tin nhạy cảm), DAST (Web Runtime), Container (Image), Network (Hệ thống mạng), API (Fuzzing) và cả Manual Pentest.
- **Zero-Config Dynamic Ingestion**: Kiến trúc "Hố đen" dữ liệu. Bạn không cần cấu hình API hay biến môi trường rườm rà. Chỉ cần các công cụ quét xuất ra file JSON và ném vào thư mục `ingest/`, AegisFlow sẽ tự động nhận diện (Heuristics) và tổng hợp lên Dashboard.
- **AI Deep Context Analysis**: Không chỉ đọc báo cáo, AI đọc hiểu 20 dòng code xung quanh lỗ hổng để loại bỏ lỗi ảo (False Positives) và đánh giá tác động kinh doanh thực tế (Business Impact) với độ chính xác >95%.
- **OWASP Top 10 & MITRE ATT&CK**: Hệ thống tự động map các lỗ hổng theo các tiêu chuẩn quốc tế mới nhất.

## 🚀 Quick Start (3 Phút)

### 1. Cơ chế Drop-in (Zero-Config)
Cách đơn giản nhất để sử dụng AegisFlow là dùng các công cụ bảo mật của bạn (Trivy, Semgrep, Nmap, Restler...) quét dự án và lưu file kết quả `*.json` vào thư mục `ingest/`. Sau đó chạy báo cáo:
```bash
./pipeline/run_pipeline.sh
```

### 2. Chế độ Quét thật Tự Động (Real-World Scan)
Nếu bạn đã có sẵn mã nguồn, AegisFlow có thể tự gọi các công cụ (Semgrep, Trivy, Gitleaks, Checkov, Nuclei) để quét:
```bash
export GROQ_API_KEY="gsk_..."
./pipeline/run_real_scanners.sh /đường/dẫn/dự/án/của/bạn
```

### 3. Khởi chạy Giao Diện
Sau khi có kết quả, khởi động máy chủ UI để quản lý trực quan:
```bash
python3 server.py
# Truy cập: http://localhost:58082
```

## 📊 Dashboard Preview
Hệ thống sử dụng thiết kế **Glassmorphism** sang trọng, cung cấp góc nhìn toàn cảnh (Single Pane of Glass) cho Giám đốc Bảo mật (CISO) và các kỹ sư DevSecOps:
- Điểm số sức khỏe dự án (Security Score).
- Phân luồng ưu tiên theo 8 nhóm kiểm thử (Automated vs Manual Intel).
- Mã vá lỗi (Patch) do AI tạo ra sẵn sàng copy-paste.

---
**Organization**: CMC TSSG - DevSecOps Excellence Center
