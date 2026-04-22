# AegisFlow - DevSecOps Enterprise Control Plane (ASPM)
**Tác giả:** Lê Tuấn Lương

AegisFlow là nền tảng **Application Security Posture Management (ASPM)** tiên phong tích hợp trí tuệ nhân tạo (Llama-3.3) để tự động hóa toàn bộ quy trình từ Quét lỗ hổng, Triage (Phân loại) đến Auto-Remediation (Tự động sửa lỗi).

## 🌟 Tính năng đột phá (2026 Edition)

- **AI Deep Context Analysis**: Không chỉ quét mã nguồn, AI còn đọc hiểu 20 dòng code xung quanh lỗ hổng để loại bỏ lỗi ảo (False Positives) với độ chính xác >95%.
- **OWASP Top 10: 2025 Ready**: Hệ thống đầu tiên hỗ trợ đầy đủ các danh mục bảo mật mới nhất của năm 2025 (Supply Chain, Exceptional Conditions...).
- **Quad-Core Scanner Engine**: Hợp nhất 4 "ông lớn" bảo mật: **Semgrep** (SAST), **Trivy** (SCA/SBOM), **Gitleaks 8.30.1** (Secrets), và **Checkov** (IaC).
- **Autonomous Remediation**: AI tự động đề xuất và thiết kế các bản vá (Patch) sẵn sàng để copy-paste.
- **Shift-Left Enforcement**: Tích hợp sẵn Gitleaks pre-commit hook ngăn chặn lộ secret ngay từ máy dev.

## 🚀 Quick Start (3 Phút)

### 1. Chế độ Demo (Simulation)
Dùng để trải nghiệm nhanh không cần cài đặt công cụ:
```bash
cd pipeline
./run_pipeline.sh
```

### 2. Chế độ Quét thật (Real-World Scan)
Quét trực tiếp ứng dụng của bạn với sức mạnh của Llama-4:
```bash
export GROQ_API_KEY="gsk_..."
./pipeline/run_real_scanners.sh /đường/dẫn/dự/án/của/bạn
```

### 3. Xem Dashboard
Sau khi quét, mở Dashboard để quản lý lỗ hổng:
- **URL**: [http://localhost:58080](http://localhost:58080)
- **Báo cáo HTML**: `DevSecOps_CaseStudy_Report.html`

## 📊 Dashboard Preview
Hệ thống sử dụng thiết kế **Glassmorphism** hiện đại, hiển thị trực quan:
- Điểm số sức khỏe dự án (Security Score).
- Bản đồ nhiệt lỗ hổng theo MITRE ATT&CK.
- Danh sách ưu tiên xử lý theo SLA thời gian thực.

---
**Organization**: CMC TSSG - DevSecOps Excellence Center
