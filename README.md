# AdGuard Certificate Copier

<div align="center">

![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/kotlin-%237F52FF.svg?style=for-the-badge&logo=kotlin&logoColor=white)
![Root Required](https://img.shields.io/badge/Root-Required-red?style=for-the-badge)
![API](https://img.shields.io/badge/API-24+-green?style=for-the-badge)

**Công cụ cài đặt chứng chỉ CA tự động cho thiết bị Android đã root**

</div>

## 📖 Mô tả

AdGuard Certificate Copier là một ứng dụng Android giúp người dùng dễ dàng cài đặt chứng chỉ CA (Certificate Authority) vào hệ thống Android đã root. Ứng dụng đặc biệt hữu ích cho việc cài đặt chứng chỉ từ các công cụ như Burp Suite, OWASP ZAP, hoặc các proxy tool khác để thực hiện penetration testing và phân tích bảo mật.

## ✨ Tính năng

### 🔧 Cài đặt chứng chỉ
- **Hỗ trợ nhiều định dạng**: PEM, DER, PKCS#12 (.p12/.pfx)
- **Tự động chuyển đổi**: Chuyển tất cả định dạng về PEM
- **Ưu tiên CA**: Tự động chọn Certificate Authority nếu có nhiều chứng chỉ

### 🌐 Tải chứng chỉ từ Burp Suite
- **Kết nối trực tiếp**: Tải chứng chỉ CA từ Burp Suite qua HTTP
- **Cấu hình linh hoạt**: Hỗ trợ IP và Port tùy chỉnh
- **Endpoint chuẩn**: Tự động truy cập `http://IP:PORT/cert`
- **Network Security**: Hỗ trợ cleartext traffic cho development

### 📚 Quản lý chứng chỉ đã lưu
- **Lưu trữ**: Lưu chứng chỉ với tên tùy chỉnh để tái sử dụng
- **Tìm kiếm**: Tìm kiếm real-time không phân biệt hoa thường
- **Sắp xếp**: Danh sách tự động sắp xếp A-Z
- **Cuộn mượt**: Hỗ trợ cuộn cho danh sách dài
- **Quản lý đầy đủ**: Cài đặt hoặc xóa chứng chỉ đã lưu
- **Xác nhận an toàn**: Dialog xác nhận trước khi xóa

### 🔄 Tự động hóa
- **Reboot tự động**: Đếm ngược 3 giây và khởi động lại sau cài đặt
- **Thông báo rõ ràng**: Hiển thị trạng thái và lỗi chi tiết

## 📱 Yêu cầu hệ thống

- **Android**: API Level 24+ (Android 7.0+)
- **Root**: Thiết bị phải đã root (Magisk khuyến nghị)
- **Module Magisk**: `adguardcert-v2.1.zip` phải được cài đặt trước
- **Quyền**: Internet, Network State
- **Storage**: Minimal (~10MB)

### 📦 Cài đặt Module Magisk

**⚠️ Quan trọng**: Trước khi sử dụng ứng dụng, bạn phải cài đặt module Magisk `adguardcert-v2.1.zip`:

1. **Mở Magisk Manager** trên thiết bị
2. **Chọn Modules**
3. **Chọn "Install from storage"** (hoặc nút +)
4. **Tìm file** `adguardcert-v2.1.zip`
5. **Chọn và cài đặt** module
6. **Khởi động lại** thiết bị khi được yêu cầu
7. **Xác nhận** module đã được cài (sẽ xuất hiện trong danh sách modules)

**Module này cung cấp:**
- Thư mục `/data/adb/modules/adguardcert/system/etc/security/cacerts/` để lưu chứng chỉ
- Tích hợp với hệ thống Magisk để quản lý chứng chỉ hệ thống

## 🚀 Cài đặt và Sử dụng

### Cài đặt
1. **Tải APK** từ [Releases](../../releases) hoặc build từ source
2. **Cài đặt** APK trên thiết bị đã root
3. **Cấp quyền root** khi ứng dụng yêu cầu

### Sử dụng

#### 📁 Cài từ file
1. Mở ứng dụng và chọn **"Chọn chứng chỉ"** hoặc **"Chọn PKCS#12"**
2. Chọn file chứng chỉ từ bộ nhớ
3. Nhập mật khẩu nếu là file PKCS#12
4. Chờ ứng dụng xử lý và cài đặt
5. Chọn lưu chứng chỉ để sử dụng sau (tùy chọn)
6. Ứng dụng sẽ **đếm ngược 3 giây** và **khởi động lại** thiết bị tự động

#### 🌐 Tải từ Burp Suite
1. **Khởi động Burp Suite** và bật Proxy listener
2. Chọn **"Tải cert từ Burp Suite"**
3. Nhập **IP Address** (mặc định: 192.168.4.100)
4. Nhập **Port** (mặc định: 8080)
5. Nhấn **"Tải"** để tải chứng chỉ CA
6. Ứng dụng sẽ **đếm ngược 3 giây** và **khởi động lại** thiết bị tự động

#### 🗂️ Quản lý chứng chỉ đã lưu
1. Chọn **"Quản lý chứng chỉ đã lưu"**
2. **Tìm kiếm**: Gõ tên chứng chỉ vào ô search
3. **Cuộn**: Vuốt lên/xuống nếu danh sách dài
4. **Click chứng chỉ**: Chọn "Cài đặt" hoặc "Xóa"
5. **Xác nhận**: Confirm khi xóa chứng chỉ
6. **Cài đặt**: Ứng dụng sẽ **đếm ngược 3 giây** và **khởi động lại** thiết bị tự động

## 🏗️ Build từ Source

### Yêu cầu
- **Android Studio**: Arctic Fox trở lên
- **JDK**: 11 hoặc 17
- **Gradle**: 7.0+
- **SDK**: Android 24+

### Các bước build
```bash
# Clone repository
git clone https://github.com/vn-ncvinh/AdGuardCertCopier.git
cd AdGuardCertCopier

# Mở bằng Android Studio
# Hoặc build từ command line:
./gradlew assembleDebug

# APK sẽ được tạo tại:
# app/build/outputs/apk/debug/app-debug.apk
```

### Dependencies chính
- **libsu**: Root access và shell commands
- **OkHttp**: HTTP client cho Burp Suite integration
- **Coroutines**: Async operations
- **ViewBinding**: Type-safe view binding

## 🔧 Troubleshooting

### Lỗi thường gặp

#### "Cleartext traffic not permitted"
- **Nguyên nhân**: Android chặn HTTP traffic
- **Giải pháp**: Ứng dụng đã config network security để cho phép

#### "Cannot connect to Burp Suite"
- **Kiểm tra**: Burp Suite đang chạy
- **Kiểm tra**: IP và Port đúng
- **Kiểm tra**: Proxy listener đã bật
- **Kiểm tra**: Thiết bị và Burp Suite cùng mạng

#### "Root access denied"
- **Kiểm tra**: Thiết bị đã root
- **Kiểm tra**: Cấp quyền root cho app
- **Thử**: Khởi động lại Magisk hoặc SuperSU

#### "Certificate installation failed"
- **Kiểm tra**: File chứng chỉ hợp lệ
- **Kiểm tra**: Đủ quyền ghi vào system partition
- **Thử**: Cài đặt lại từ file khác

## 🛡️ Bảo mật

⚠️ **Cảnh báo quan trọng**:
- Chỉ cài đặt chứng chỉ từ **nguồn tin cậy**
- **Không sử dụng** trên thiết bị production
- **Chỉ dành cho** testing và development
- **Có thể ảnh hưởng** đến bảo mật TLS/SSL

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Vui lòng:

1. **Fork** repository
2. Tạo **feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** branch (`git push origin feature/amazing-feature`)
5. Tạo **Pull Request**

## 📄 License

Dự án này được phân phối dưới **MIT License**. Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

## 🙏 Acknowledgments

- **[AdguardTeam/adguardcert](https://github.com/AdguardTeam/adguardcert)** - Magisk module that allows using AdGuard's HTTPS filtering for all apps
- **[topjohnwu/libsu](https://github.com/topjohnwu/libsu)** - Root access library

## 📞 Liên hệ

- **Author**: [vn-ncvinh](https://github.com/vn-ncvinh)
- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)

---

<div align="center">

**⭐ Nếu dự án hữu ích, hãy cho một star! ⭐**

Made with ❤️ for the Android Security Community

</div>
