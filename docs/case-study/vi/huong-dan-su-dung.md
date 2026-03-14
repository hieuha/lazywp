# lazywp - Hướng Dẫn Sử Dụng

## Giới Thiệu

lazywp là công cụ CLI dành cho các nhà nghiên cứu bảo mật, giúp tải hàng loạt plugin/theme WordPress và đối chiếu với các cơ sở dữ liệu lỗ hổng (Wordfence, WPScan, NVD).

---

## 1. Tìm Plugin Có Nhiều Lỗ Hổng Nhất

Tìm top 10 plugin có nhiều lỗ hổng SQL injection:

```bash
lazywp vuln --top 10 --cwe-type sqli
```

Xem chi tiết từng CVE của mỗi plugin:

```bash
lazywp vuln --top 10 --cwe-type sqli --detail
```

Lọc theo mức độ nghiêm trọng:

```bash
lazywp vuln --top 10 --severity critical
lazywp vuln --top 5 --severity high --cwe-type xss
```

Lọc theo thời gian:

```bash
lazywp vuln --top 10 --cwe-type rce --year 2025 --month 3
```

---

## 2. Tra Cứu Lỗ Hổng Của Một Plugin Cụ Thể

Tra cứu tất cả lỗ hổng đã biết của một plugin:

```bash
lazywp vuln --slug contact-form-7
lazywp vuln --slug contest-gallery
```

Chỉ tra cứu từ một nguồn cụ thể:

```bash
lazywp vuln --slug akismet --source wordfence
lazywp vuln --slug akismet --source nvd
```

---

## 3. Tải Hàng Loạt Plugin Để Phân Tích

### Tải top plugin phổ biến

```bash
lazywp top --count 50 --download
```

### Tải plugin mới nhất

```bash
lazywp top --browse new --count 20 --download
```

### Tìm kiếm và tải

```bash
lazywp search "ecommerce" --count 10
```

### Tải từ danh sách file

Tạo file `plugins.txt`:

```
akismet
contact-form-7:6.1.5
elementor
```

Chạy lệnh:

```bash
lazywp download --list plugins.txt
```

### Ép tải lại dù đã tồn tại

```bash
lazywp top --count 10 --download --force
```

---

## 4. Tải Plugin Có Lỗ Hổng Để Kiểm Thử

Tìm và tải các plugin có lỗ hổng SQL injection:

```bash
lazywp vuln --top 20 --cwe-type sqli --download
```

Tải một plugin cụ thể sau khi xem CVE:

```bash
lazywp vuln --slug contest-gallery --download
```

---

## 5. Quét Lỗ Hổng Trên Thư Mục Plugin/Theme Cục Bộ

Tính năng `scan` cho phép quét một thư mục chứa plugin hoặc theme WordPress đã cài, phát hiện slug + phiên bản, rồi đối chiếu với cơ sở dữ liệu lỗ hổng.

### Quét thư mục plugins

```bash
lazywp scan /var/www/html/wp-content/plugins -t plugin
```

### Quét thư mục themes

```bash
lazywp scan /var/www/html/wp-content/themes -t theme
```

Kết quả mẫu:

```
Scanning: /var/www/html/wp-content/plugins (12 plugins found)

  3 plugins found in cache, 9 need API lookup

contact-form-7                  12/12 [==============================] 100%

VULNERABLE (2):
  contact-form-7@6.1.2           2 CVEs (max CVSS 9.8, fixed in 6.1.5)
  elementor@3.20.0               1 CVE  (CVSS 7.5, fixed in 3.21.0)

SAFE (10):
  akismet@5.3.1                  0 CVEs
  ...

Summary: 12 scanned, 2 vulnerable, 10 safe
```

### Chỉ quét từ một nguồn

```bash
lazywp scan ./plugins -t plugin --source wordfence
```

### Bỏ qua cache, ép truy vấn trực tuyến

```bash
lazywp scan ./plugins -t plugin --no-cache
```

Khi dùng `--no-cache`, dữ liệu vẫn được lưu cache cho lần quét sau.

### Xuất kết quả quét

```bash
lazywp scan ./plugins -t plugin -f json > ket-qua-quet.json
lazywp scan ./plugins -t plugin -f csv > ket-qua-quet.csv
```

### Cách phát hiện phiên bản

- **Plugin**: Đọc `readme.txt` (Stable tag), nếu không có thì quét header `Version:` trong file `.php`
- **Theme**: Đọc header `Version:` trong `style.css`, nếu không có thì thử `readme.txt`

### Tự động tắt nguồn lỗi

Nếu một nguồn (vd: WPScan) trả lỗi thiếu API key, nguồn đó sẽ tự động bị tắt cho các plugin còn lại để tránh lặp lỗi.

---

## 6. Xuất Dữ Liệu Để Báo Cáo

### Xuất JSON để xử lý bằng script

```bash
lazywp vuln --top 10 --cwe-type sqli -f json > bao-cao-vuln.json
lazywp vuln --top 5 --detail -f json > bao-cao-chi-tiet.json
```

### Xuất CSV để mở bằng Excel

```bash
lazywp vuln --slug contest-gallery -f csv > contest-gallery-vulns.csv
lazywp top --count 100 -f csv > top-plugins.csv
```

### Kết hợp với jq để lọc dữ liệu

```bash
lazywp vuln --top 10 -f json | jq '.[].slug'
lazywp vuln --slug akismet -f json | jq '[.[] | select(.cvss >= 7.0)]'
```

---

## 7. Quản Lý Cache

### Xem trạng thái cache

```bash
lazywp cache status
```

Kết quả:

```
Cache directory: ./cache
Cache TTL: 24h

  wordfence     cached at 2026-03-14 11:33:31  (age: 2h15m, size: 127.8MB, status: valid)
  wpscan        no cache
  nvd           cached at 2026-03-14 11:33:31  (age: 2h15m, size: 45.2KB, status: valid)
```

### Cập nhật lại dữ liệu lỗ hổng

```bash
lazywp cache update
```

### Xóa cache

```bash
lazywp cache clear --source wordfence
lazywp cache clear  # xóa tất cả
```

---

## 8. Làm Việc Với Theme

Tất cả lệnh đều hỗ trợ theme qua `--type theme` (`-t theme`):

```bash
lazywp top -t theme --count 20
lazywp search "developer" -t theme
lazywp vuln --slug flavor -t theme
```

---

## 9. Cấu Hình

### Khởi tạo config

```bash
cp config.yaml.example config.yaml
# Sửa config.yaml, thêm API key của bạn
```

### Xem cấu hình hiện tại

```bash
lazywp config list
```

### Thay đổi cấu hình

```bash
lazywp config set concurrency 10
lazywp config set cache_ttl 12h
lazywp config set output_dir /data/wp-downloads
```

### Sử dụng file config khác

```bash
lazywp --config /đường-dẫn/config.yaml vuln --top 10
```

---

## 10. Xoay Nhiều API Key Tự Động

Cấu hình nhiều API key để tự động xoay khi bị giới hạn:

```yaml
# config.yaml
wordfence_keys:
  - KEY_1
  - KEY_2
  - KEY_3
wpscan_keys:
  - WPSCAN_KEY_1
  - WPSCAN_KEY_2
```

Khi một key bị 429 (rate limit), lazywp tự động chuyển sang key tiếp theo và thử lại.

---

## Mẹo Sử Dụng

- Dùng `-q` (quiet) để ẩn thông tin cache/query, output gọn hơn
- Dùng `-f json` để lấy output dạng máy đọc được (không lẫn text)
- Đặt `title_max_len: 0` trong config để hiển thị đầy đủ tiêu đề lỗ hổng
- Wordfence bulk feed (~128MB) được cache tại máy, các truy vấn sau là tức thì
- NVD truy vấn theo từng plugin và cache riêng
- Dùng `--force` để tải lại plugin đã có
- Xem phiên bản: `lazywp version`
