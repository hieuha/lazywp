# Nghiên Cứu Lỗ Hổng

Phát hiện, phân tích và ưu tiên xử lý lỗ hổng WordPress plugin/theme từ nhiều nguồn CVE.

---

## Tìm Plugin Có Nhiều Lỗ Hổng Nhất

Tìm top 10 plugin có nhiều lỗ hổng SQL injection:

```bash
lazywp vuln --top 10 --cwe-type sqli
lazywp vuln --top 10 --cwe-type sqli --detail    # xem chi tiết từng CVE
```

Lọc theo mức độ nghiêm trọng và loại CWE:

```bash
lazywp vuln --top 10 --severity critical
lazywp vuln --top 5 --severity high --cwe-type xss
lazywp vuln --top 10 --cwe-type rce --year 2025 --month 3
```

Tải luôn các plugin có lỗ hổng để phân tích:

```bash
lazywp vuln --top 20 --cwe-type sqli --download
```

---

## Tra Cứu Plugin Cụ Thể

Tra cứu tất cả CVE đã biết từ tất cả nguồn:

```bash
lazywp vuln --slug contact-form-7
lazywp vuln --slug contest-gallery
```

Chỉ truy vấn từ một nguồn:

```bash
lazywp vuln --slug akismet --source wordfence
lazywp vuln --slug akismet --source nvd
lazywp vuln --slug akismet --source wpscan
```

Tải plugin sau khi xem CVE:

```bash
lazywp vuln --slug contest-gallery --download
```

---

## Kiểm Tra Hàng Loạt

Kiểm tra nhiều plugin cùng lúc từ file (`slugs.txt`, mỗi dòng một slug):

```bash
lazywp vuln --list slugs.txt
lazywp vuln --list slugs.txt --download           # tải luôn plugin có lỗ hổng
lazywp vuln --list slugs.txt -f json > batch.json  # xuất JSON
```

---

## Kịch Bản Thực Tế

### Bug Bounty Recon

Tìm plugin phổ biến có lỗ hổng RCE/SQLi nghiêm trọng:

```bash
lazywp vuln --top 20 --cwe-type rce --severity critical --detail
lazywp vuln --top 20 --cwe-type sqli --severity critical --detail
```

### Báo Cáo Lỗ Hổng Hàng Tháng

Tạo báo cáo CVE nghiêm trọng mới phát hiện trong tháng:

```bash
lazywp vuln --top 50 --severity critical --year 2026 --month 3 -f json > thang3-critical.json
```

### So Sánh Nguồn Dữ Liệu

Đối chiếu số lượng lỗ hổng giữa các database:

```bash
lazywp vuln --slug elementor --source wordfence
lazywp vuln --slug elementor --source wpscan
lazywp vuln --slug elementor --source nvd
```
