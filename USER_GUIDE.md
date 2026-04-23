# AegisFlow - User Guide (Hướng dẫn sử dụng)

Chào mừng bạn đến với AegisFlow ASPM. Hướng dẫn này giúp bạn vận hành hệ thống tập trung dữ liệu bảo mật (Control Plane) của doanh nghiệp một cách nhanh chóng nhất.

## 🏁 1. Chuẩn bị môi trường
- **Yêu cầu**: Máy Mac/Linux đã cài Python 3.11+.
- **API Key**: Lấy mã API tại [Groq Cloud](https://console.groq.com/keys) để cấp nguồn cho AI Triage Engine.

## ⚡ 2. Quy trình Quét và Thu Thập Dữ Liệu (Data Ingestion)

Bạn có hai cách để đưa dữ liệu lỗ hổng vào AegisFlow:

### Cách 1: Tự động hoàn toàn (Auto-Scanning)
Nếu bạn có mã nguồn dự án trên máy, hãy để AegisFlow tự động gọi các công cụ cài sẵn (Trivy, Semgrep, Gitleaks, Nuclei, Checkov):
```bash
# Trỏ đến thư mục dự án của bạn
./pipeline/run_real_scanners.sh /path/to/your/project
```
Script sẽ tự quét và đẩy toàn bộ kết quả vào thư mục `ingest/`.

### Cách 2: Sử dụng cơ chế Zero-Config (Cho CI/CD hoặc Tool Ngoài)
Đây là sức mạnh cốt lõi của AegisFlow. Bất kỳ máy chủ CI/CD nào hoặc công cụ độc lập nào của bạn (như Nmap, API Fuzzer, báo cáo Pentest thủ công) chỉ cần:
1. Xuất kết quả dưới dạng file JSON.
2. Thả file đó vào thư mục `ingest/` ở gốc dự án.
3. Chạy `python3 pipeline/report_generator.py` để hệ thống tự động nhận dạng file và tổng hợp.

Không cần cấu hình biến môi trường, không giới hạn số lượng file!

## 📊 3. Khởi chạy Giao diện Quản lý (Dashboard)

1. **Khởi chạy Aegis Server**:
   ```bash
   python3 server.py
   ```
2. **Truy cập Dashboard**: Mở trình duyệt tại [http://localhost:58082](http://localhost:58082).
3. **Phân tích Dashboard**:
   - Theo dõi biểu đồ phân bổ theo 8 nhóm DevSecOps (Container, Network, API, SAST...).
   - Vào tab **Action Center**, click vào từng lỗ hổng để xem AI đánh giá "True Positive" và mô tả tác động thực tế (Impact).
   - Truy cập **Developer Portal** để lấy mã nguồn (Patch) đã được AI viết lại an toàn.

## 📄 4. Xuất báo cáo Enterprise
Sau mỗi chu kỳ quét, báo cáo định dạng HTML (`DevSecOps_CaseStudy_Report.html`) và JSON tổng hợp (`mock-data/full_report_triaged.json`) sẽ tự động được sinh ra để nộp cho ban kiểm toán (Compliance Audit).

---
**Hỗ trợ kỹ thuật**: Liên hệ AppSec Team / Lê Tuấn Lương.
