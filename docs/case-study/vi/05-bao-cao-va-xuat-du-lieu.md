# Báo Cáo & Xuất Dữ Liệu

Chuyển đổi, lọc, và xuất kết quả quét ở nhiều định dạng.

---

## Báo Cáo HTML

Tạo báo cáo HTML khép kín từ kết quả quét:

```bash
lazywp report scan.json
lazywp report scan.json -o report.html
```

Báo cáo gồm: tóm tắt tổng quan, biểu đồ CVSS, exploit intelligence, chi tiết CVE từng plugin.

---

## Convert & Lọc Kết Quả Quét

Đọc lại file JSON từ `lazywp scan`, áp dụng bộ lọc, xuất lại:

```bash
# Xem dạng bảng chi tiết
lazywp convert scan.json -f table --detail

# Xuất CSV
lazywp convert scan.json -f csv -o report.csv

# Lọc theo slug
lazywp convert scan.json --slug elementor --detail

# Lọc theo CVSS
lazywp convert scan.json --vuln-only --min-cvss 7.0
lazywp convert scan.json --max-cvss 5.9 --safe-only

# Lọc theo CVE cụ thể
lazywp convert scan.json --cve CVE-2024-1234

# Chỉ plugin có exploit (PoC, KEV, hoặc Nuclei)
lazywp convert scan.json --exploitable -f csv -o critical.csv

# Lọc theo trạng thái
lazywp convert scan.json --status vulnerable -f csv -o vulnerable.csv
```

---

## Xuất JSON & CSV

Bất kỳ lệnh nào đều hỗ trợ `-f json` hoặc `-f csv`:

```bash
lazywp vuln --top 10 --cwe-type sqli -f json > vuln-report.json
lazywp vuln --slug contest-gallery -f csv > contest-gallery.csv
lazywp top --count 100 -f csv > top-plugins.csv
```

### Kết Hợp jq

```bash
lazywp vuln --top 10 -f json | jq '.[].slug'
lazywp vuln --slug akismet -f json | jq '[.[] | select(.cvss >= 7.0)]'
```

---

## Kịch Bản Thực Tế

### Báo Cáo Cho Lãnh Đạo

Quét rồi tạo báo cáo HTML:

```bash
lazywp scan /client/wp-content/plugins -t plugin --check-exploit -f json -o scan.json
lazywp report scan.json -o danh-gia-lo-hong.html
```

### Trích Xuất CVE Nghiêm Trọng

Chỉ lấy CVE critical vào spreadsheet:

```bash
lazywp convert scan.json --vuln-only --min-cvss 9.0 -f csv -o critical-vulns.csv
```

### Báo Cáo Cho Nhiều Đối Tượng

```bash
# Cho developer: plugin có lỗ hổng kèm version fix
lazywp convert scan.json --vuln-only -f table --detail

# Cho quản lý: chỉ critical/exploitable
lazywp convert scan.json --exploitable --min-cvss 7.0 -f csv -o action-items.csv

# Cho security team: exploit intelligence đầy đủ
lazywp exploit --file scan.json -f json -o full-intel.json
```
