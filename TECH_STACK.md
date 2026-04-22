# AegisFlow - Technical Stack & Methodology (2026)

Tài liệu này chi tiết hóa các công nghệ cốt lõi và phương pháp luận bảo mật được áp dụng trong nền tảng AegisFlow ASPM.

## 1. Hệ thống Quét Penta-Core (Scanner Layer)
AegisFlow sử dụng mô hình "Orchestrator" để điều phối 5 lớp bảo mật chuyên sâu:

- **SAST (Semgrep 1.160+)**: Phân tích tĩnh mã nguồn, phát hiện các mẫu logic không an toàn.
- **SCA (Trivy 0.70+)**: Phân tích thư viện bên thứ ba và quản lý Software Supply Chain.
- **Secrets (Gitleaks 8.30.1)**: Sử dụng các Regex nâng cao và phân tích Entropy để tìm kiếm thông tin nhạy cảm.
- **IaC (Checkov 3.2+)**: Quét cấu hình Docker, Kubernetes, Terraform để đảm bảo hạ tầng an toàn.
- **DAST (Nuclei 3.3+)**: [NEW] Quét động lớp ứng dụng, bắt các lỗ hổng runtime và endpoint lộ thiên.

## 2. AI Triage Engine (Intelligence Layer)
Đây là "bộ não" của AegisFlow, sử dụng mô hình **Meta Llama-3.3-70B** thông qua Groq Cloud API.

### Kỹ thuật Parallel AI Analysis (Đa luồng)
AegisFlow áp dụng thuật toán phân tích song song:
1. **Multi-threading**: Sử dụng `ThreadPoolExecutor` để gọi AI cho nhiều lỗ hổng cùng lúc (mặc định 3-5 luồng).
2. **Context Enrichment**: AI được cung cấp 20 dòng code xung quanh vị trí lỗi để đánh giá Impact.
3. **Real Impact Extraction**: AI không chỉ phân loại (TP/FP) mà còn phải mô tả ảnh hưởng cụ thể đến Business Logic của ứng dụng mục tiêu.

## 3. Tiêu chuẩn & Giao diện (Frontend Layer)
- **Interactive Control**: Dashboard v2.0 cho phép gửi POST requests tới Backend để thực thi Bash scripts.
- **Real-time Data Binding**: Sử dụng cơ chế polling 5 giây để cập nhật điểm số (Security Score) và biểu đồ OWASP 2025 ngay khi AI có kết quả.
- **Glassmorphism Aesthetic**: Thiết kế cao cấp, tối ưu trải nghiệm CISO và Developer.

---
**Author:** Lê Tuấn Lương
**Updated:** 23/04/2026
