# AegisFlow - User Guide (Hướng dẫn sử dụng)

Chào mừng bạn đến với AegisFlow v2.0. Hướng dẫn này giúp bạn làm chủ hệ thống ASPM hiện đại chỉ trong vài bước đơn giản.

## 🏁 1. Chuẩn bị môi trường
- **Yêu cầu**: Máy Mac/Linux đã cài Python 3.11+.
- **API Key**: Lấy mã API tại [Groq Cloud](https://console.groq.com/keys).

## ⚡ 2. Quy trình quét bảo mật (Dashboard Control)

AegisFlow hiện đại hóa quy trình quét thông qua giao diện kéo-thả và nhập liệu trực tiếp:

1. **Khởi chạy Aegis Server**:
   ```bash
   python3 server.py
   ```
2. **Truy cập Dashboard**: Mở trình duyệt tại [http://localhost:58082](http://localhost:58082).
3. **Kích hoạt Quét (Scanner Control)**:
   - Chuyển sang tab **Scanner Control**.
   - Nhập đường dẫn dự án cần quét (Vd: `./test-target-app`).
   - Dán **Groq API Key** của bạn.
   - Nhấn **"Start Penta-Core Scan"**.

## 📊 3. Quản lý kết quả (Action Center)

1. **Theo dõi trạng thái**: Dashboard sẽ hiện chữ **"Scanning..."** và tự động cập nhật biểu đồ khi hoàn tất.
2. **Phân tích Real Impact**: Vào tab **Action Center**, click vào từng lỗ hổng để xem AI giải thích ảnh hưởng thực tế đến kinh doanh.
3. **Lấy mã vá lỗi**: Vào tab **Developer Portal** để xem mã nguồn "Before" và "After" đã được AI tối ưu.
4. **Kiểm tra SLA**: Theo dõi đồng hồ đếm ngược thời gian cần khắc phục cho các lỗi Critical và High.

## 📄 4. Xuất báo cáo Enterprise
Báo cáo HTML chuyên nghiệp vẫn được tạo tự động sau mỗi lần quét tại:
`dashboard/data/full_report_triaged.json` (Dữ liệu gốc) và file báo cáo tổng hợp.

---
**Hỗ trợ kỹ thuật**: Liên hệ AppSec Team/Lê Tuấn Lương.
