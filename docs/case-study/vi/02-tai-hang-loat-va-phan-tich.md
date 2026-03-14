# Tải Hàng Loạt & Phân Tích Offline

Tải WordPress plugin/theme hàng loạt để review code offline, phân tích tĩnh, hoặc lưu trữ.

---

## Duyệt và Tải Plugin Phổ Biến

```bash
lazywp top --count 50 --download                    # top 50 plugin phổ biến
lazywp top --browse new --count 20 --download       # 20 plugin mới nhất
```

## Tìm Kiếm và Tải

```bash
lazywp search "ecommerce" --count 10
lazywp search "security" --count 20
lazywp download woocommerce elementor akismet
```

## Tải Từ File Danh Sách

Tạo `plugins.txt` (mỗi dòng một slug, tuỳ chọn pin version bằng `:`):

```
akismet
contact-form-7:6.1.5
elementor
woocommerce
```

```bash
lazywp download --list plugins.txt
lazywp download --list plugins.txt --force   # ép tải lại
```

## Xem Danh Sách Đã Tải

```bash
lazywp list
```

---

## Làm Việc Với Theme

Tất cả lệnh tải đều hỗ trợ theme qua `-t theme`:

```bash
lazywp top -t theme --count 20
lazywp search "developer" -t theme
lazywp download flavor flavor -t theme
```

---

## Kịch Bản Thực Tế

### Xây Dựng Kho Plugin

Tải top 100 plugin phổ biến để phân tích tĩnh offline:

```bash
lazywp top --count 100 --download
```

File lưu tại `downloads/plugins/<slug>/<version>/` kèm metadata.

### Tải Version Cố Định

Pin version cụ thể cho môi trường audit có thể tái tạo:

```
# audit-targets.txt
elementor:3.20.0
contact-form-7:6.1.2
woocommerce:8.5.0
```

```bash
lazywp download --list audit-targets.txt
```

### Tiếp Tục Tải Khi Bị Gián Đoạn

Nếu tải bị gián đoạn (mất mạng, Ctrl+C), chạy lại lệnh — lazywp tự động tiếp tục từ chỗ dừng, bỏ qua plugin đã tải:

```bash
lazywp download --list large-list.txt    # gián đoạn ở #45
lazywp download --list large-list.txt    # tiếp tục từ #46
```
