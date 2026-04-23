# AegisFlow - Technical Stack & Methodology (2026)

Tài liệu này chi tiết hóa các công nghệ cốt lõi và phương pháp luận bảo mật được áp dụng trong nền tảng AegisFlow ASPM chuẩn Enterprise.

## 1. Hệ thống Quét Toàn Diện 8 Lớp (DevSecOps Matrix Coverage)
AegisFlow đạt độ bao phủ 100% các kỹ thuật kiểm thử trong vòng đời phát triển phần mềm (SDLC):

- **SAST (Semgrep 1.160+)**: Phân tích tĩnh mã nguồn.
- **SCA (Trivy 0.70+)**: Phân tích lỗ hổng thư viện bên thứ ba và SBOM.
- **Secrets (Gitleaks 8.30.1)**: Phân tích Regex và Entropy tìm thông tin nhạy cảm.
- **IaC (Checkov 3.2+)**: Quét cấu hình Docker, Kubernetes, Terraform.
- **DAST (Nuclei 3.3+)**: Quét động lớp ứng dụng web.
- **Container Scanning**: Quét Docker Image tìm lỗ hổng OS.
- **Network Scanning**: Quét cổng và dịch vụ hệ thống (VD: Nmap).
- **API Fuzzing**: Quét lỗi logic API (VD: Restler).
- **Manual Intel**: Tích hợp báo cáo Pentest/Threat Model từ con người.

## 2. Kiến trúc Zero-Config Dynamic Ingestion
AegisFlow áp dụng mô hình **Data Lake "Hố đen"**:
- **Thư mục `ingest/`**: Đóng vai trò là điểm tập kết dữ liệu duy nhất. Không cần biến môi trường hay API trung gian.
- **Heuristic Auto-Discovery**: Core Engine (`report_generator.py`) sử dụng các thuật toán heuristic để tự động nội soi cấu trúc JSON (như nhận diện schema `SARIF`, key `ArtifactType` của Trivy, hoặc list `failed_checks` của Checkov) để tự động định tuyến parser mà không cần người dùng cấu hình loại báo cáo.

## 3. AI Triage Engine (Intelligence Layer)
"Bộ não" của AegisFlow sử dụng mô hình **Meta Llama-3.3-70B** thông qua Groq Cloud API.

### Kỹ thuật Parallel AI Analysis (Đa luồng)
AegisFlow áp dụng thuật toán phân tích song song:
1. **Multi-threading**: Sử dụng `ThreadPoolExecutor` để gọi AI cho nhiều lỗ hổng cùng lúc, tối ưu hóa tốc độ.
2. **Context Enrichment**: AI được cung cấp 20 dòng code xung quanh vị trí lỗi để đánh giá Impact thực tế.
3. **Real Impact Extraction**: AI loại bỏ False Positives và giải thích chi tiết lỗ hổng ảnh hưởng đến Business Logic của doanh nghiệp như thế nào.

## 4. Tiêu chuẩn & Giao diện (Frontend Layer)
- **Real-time Engine**: Giao diện Dashboard được kết nối với Backend Python cho phép kích hoạt các shell script phân tích trực tiếp từ UI.
- **Enterprise UI/UX**: Thiết kế Glassmorphism cùng hệ thống Badges/Indicators phân biệt rõ dữ liệu tự động (Automated) và dữ liệu con người (Manual Intel).

---
**Author:** Lê Tuấn Lương
**Updated:** 23/04/2026
