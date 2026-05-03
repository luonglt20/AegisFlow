# 📘 Thực chiến AI Skills Handbook

Tài liệu này là cẩm nang thực dụng giúp bạn biết **"khi nào dùng skill nào"** cho dự án **AgeisFlow**. Thay vì liệt kê mọi thứ, đây là bản đồ chỉ đường nhanh nhất.

---

## 🎯 Mục đích và Nguyên tắc chọn Skill
- **Đúng Thuốc Đúng Bệnh**: Mỗi loại công việc (như thiết kế UI, tối ưu Backend, hoặc Fix Bug) cần một bộ skill riêng. Đừng áp dụng đại trà.
- **Không nhồi nhét**: Khuyên dùng tối đa 1-2 skills cùng lúc để AI không bị "loạn" ngữ cảnh.
- **Tập trung vào giải pháp**: Hãy dùng skill như một công cụ để giải quyết một tình huống cụ thể, không phải để làm màu.

---

## ⚡ Nhóm Skill nên dùng thường xuyên (Dành riêng cho dự án này)
Hệ thống đã tự động chọn ra các kỹ năng phù hợp nhất dựa trên kiến trúc dự án của bạn:

- **🗺️ AI Skill Selector**: Đây là bản đồ dành cho AI Agent để tự tìm kiếm kỹ năng. (Hệ thống tự động dùng, bạn không cần quan tâm).
- **🛠️ Bug Fix Protocol**: Mỗi khi dự án có bug, lỗi biên dịch hoặc test tạch. TUYỆT ĐỐI không để Agent sửa mò. Hãy bảo Agent: 'Đang có lỗi XYZ, bắt buộc phải làm theo từng bước của BUG_FIX_PROTOCOL.md để điều tra'.
- **⚙️ Standard Configurations**: Các file thiết lập môi trường mặc định (Cursorrules, Rules). (Hệ thống tự động dùng).
- **⚙️ Common AI Prompts**: Dùng cho các tác vụ viết code, Docker, tối ưu hóa DevOps cơ bản. Hãy bảo Agent: 'Dùng skill tối ưu hóa để viết lại hàm này cho chạy nhanh hơn'.
- **🌲 Plugin Architecture Engine**: Dùng khi bạn muốn xây dựng hệ thống có thể mở rộng liên tục (Plug & Play). Hãy bảo Agent: 'Thiết kế tính năng mới này thành một plugin riêng biệt theo chuẩn Plugin Architecture'.
- **🧠 Project Intelligence Engine**: Dùng khi bạn đối mặt với một codebase lớn và phức tạp. Hãy bảo Agent: 'Chạy logic analyzer để vẽ sơ đồ chức năng (Call Graph) cho module này'.
- **🎨 UI/UX Design Skills**: Dùng khi bạn cần thiết kế giao diện Web hiện đại (Glassmorphism, animations, dark mode). Hãy bảo Agent: 'Sử dụng ui_ux_skills để thiết kế lại trang này cho thật đẹp và xịn sò'.

---

## 📋 Bảng: Tình huống ➔ Skill nên dùng

| Tình huống thực tế | Skill nên kích hoạt |
| :--- | :--- |
| Terminal báo lỗi hệ thống sập / Compile lỗi | `BUG_FIX_PROTOCOL.md` |
| Muốn vẽ sơ đồ cấu trúc code để hiểu dự án | `project_intelligence` |
| Bắt đầu thiết kế hoặc sửa giao diện UI/UX | `ui_ux_skills` |
| Muốn phân tách tính năng thành các module độc lập | `plugin_architecture_engine` |
| Cần rà soát lỗ hổng hoặc viết code bảo mật | `security_skill` |
| Cần AI hỗ trợ code chung chung, tối ưu hóa | `ai_optimized_skills/common` |

---

## 🔄 Workflow gợi ý cho các loại việc phổ biến

### 1. Workflow: Sửa Bug (Troubleshooting)
- **Bước 1**: Dừng mọi thao tác, gọi ngay `BUG_FIX_PROTOCOL.md`.
- **Bước 2**: Copy nguyên văn dòng lỗi ở Terminal đưa cho AI. Không để AI sửa mò.
- **Bước 3**: Yêu cầu AI làm theo từng bước (Identify -> Isolate -> Fix).

### 2. Workflow: Thiết kế / Chỉnh sửa Giao diện
- **Bước 1**: Gọi `ui_ux_skills` để định hình phong cách (vd: Glassmorphism, Dark mode).
- **Bước 2**: Yêu cầu AI đưa ra cấu trúc Component trước khi viết code chi tiết.

### 3. Workflow: Code chức năng Backend lớn
- **Bước 1**: Dùng `project_intelligence` (nếu có) để phân tích xem chức năng mới ảnh hưởng tới đâu.
- **Bước 2**: Gọi `plugin_architecture_engine` để đảm bảo code được viết dưới dạng module cắm-rút (plug & play).

---

## ⚠️ Những Skill chỉ nên dùng chọn lọc
- **`plugin_architecture_engine`**: Rất mạnh nhưng cấu trúc phức tạp. Chỉ dùng khi xây hệ thống lớn cần mở rộng liên tục. Cấm dùng khi chỉ fix bug lặt vặt.
- **`chat_prompts` (Persona Đặc thù)**: Chỉ dùng khi cần AI đóng một vai trò rất ngách (vd: Chuyên gia SQL, Hacker Pentest), không dùng khi đang code tính năng thông thường.

---

## ⌨️ Ví dụ Prompt mẫu để kích hoạt đúng skill

**Kích hoạt Bug Fix:**
> "Tôi đang gặp lỗi `[dán lỗi terminal vào đây]`. Tuyệt đối không đoán mò. Hãy áp dụng `BUG_FIX_PROTOCOL.md` để điều tra nguyên nhân tận gốc."

**Kích hoạt UI/UX Design:**
> "Tôi muốn làm một màn hình `[tên màn hình]`. Hãy sử dụng `ui_ux_skills` để thiết kế nó theo phong cách hiện đại, ưu tiên cấu trúc component rõ ràng."

**Kích hoạt Plugin Architecture:**
> "Tôi cần viết tính năng `[tên tính năng]`. Hãy dùng `plugin_architecture_engine` để thiết kế nó thành một plugin độc lập, không phá vỡ core hiện tại."
