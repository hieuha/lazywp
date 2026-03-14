# Quét Thư Mục Cục Bộ

Quét plugin/theme WordPress đã cài trên máy, phát hiện phiên bản, và đối chiếu lỗ hổng.

---

## Quét Cơ Bản

Trỏ lazywp vào thư mục `wp-content/plugins` hoặc `wp-content/themes`:

```bash
lazywp scan /var/www/html/wp-content/plugins -t plugin
lazywp scan /var/www/html/wp-content/themes -t theme
```

Kết quả mẫu:

```
Scanning: /var/www/html/wp-content/plugins (12 plugins found)

VULNERABLE (2):
  contact-form-7@6.1.2       2 CVEs (max CVSS 9.8, update to 6.1.5)
  elementor@3.20.0            1 CVE  (CVSS 7.5, update to 3.21.0)

SAFE (10):
  akismet@5.3.1               0 CVEs
  ...

Summary: 12 scanned, 2 vulnerable, 10 safe
```

## Tuỳ Chọn Quét

```bash
lazywp scan ./plugins -t plugin --source wordfence   # chỉ 1 nguồn
lazywp scan ./plugins -t plugin --no-cache            # ép truy vấn online
lazywp scan ./plugins -t plugin --check-exploit       # thêm dữ liệu PoC/KEV/Nuclei
```

## Xuất Kết Quả

```bash
lazywp scan ./plugins -t plugin -f json -o scan.json
lazywp scan ./plugins -t plugin -f csv -o scan.csv
```

---

## Cách Phát Hiện Phiên Bản

- **Plugin**: Đọc `readme.txt` (Stable tag), fallback `Version:` trong file `.php`
- **Theme**: Đọc `Version:` trong `style.css`, fallback `readme.txt`

## Tự Động Tắt Nguồn Lỗi

Nếu một nguồn (vd: WPScan) trả lỗi API key, nguồn đó tự động bị tắt cho các plugin còn lại.

---

## Kịch Bản Thực Tế

### Điều Tra Sau Khi Bị Hack

Sau khi tiếp cận WordPress site bị hack, quét plugin để xác định attack vector:

```bash
lazywp scan /var/www/html/wp-content/plugins -t plugin --check-exploit
```

`--check-exploit` bổ sung thông tin PoC — giúp xác định CVE nào có khả năng đã bị khai thác.

### Audit WordPress Cho Khách Hàng

Quét và tạo báo cáo JSON cho deliverable pentest:

```bash
lazywp scan /client/wp-content/plugins -t plugin -f json -o client-scan.json
lazywp scan /client/wp-content/themes -t theme -f json -o client-themes.json
```

### So Sánh Staging vs Production

Quét cả hai môi trường và diff kết quả:

```bash
lazywp scan /staging/wp-content/plugins -t plugin -f json -o staging.json
lazywp scan /prod/wp-content/plugins -t plugin -f json -o prod.json
diff <(jq -r '.[].slug' staging.json | sort) <(jq -r '.[].slug' prod.json | sort)
```
