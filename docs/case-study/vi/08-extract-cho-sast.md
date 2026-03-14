# Giải Nén Plugin Để Chạy SAST

Giải nén file zip plugin/theme đã tải để chạy phân tích mã nguồn tĩnh (SAST) với Semgrep, CodeQL, Grep, v.v.

---

## Giải Nén Tất Cả Plugin Đã Tải

```bash
lazywp extract
```

Mặc định giải nén vào `./extracted/` với cấu trúc:

```
extracted/
├── akismet/
│   └── 5.0.1/
│       └── akismet/
│           ├── akismet.php
│           └── ...
├── contact-form-7/
│   └── 6.1.5/
│       └── ...
```

## Giải Nén Plugin Cụ Thể

```bash
lazywp extract --slug akismet
lazywp extract --slug elementor --output-dir ./audit
```

## Giải Nén Từ File Danh Sách

```bash
lazywp extract --list targets.txt
```

## Giải Nén Theme

```bash
lazywp extract -t theme
lazywp extract -t theme --slug flavor
```

---

## Kịch Bản Thực Tế

### Tải + Giải Nén + Chạy Semgrep

Quy trình hoàn chỉnh từ tải plugin đến phát hiện lỗ hổng:

```bash
# Bước 1: Tải top plugin có lỗ hổng
lazywp vuln --top 20 --severity critical --download

# Bước 2: Giải nén
lazywp extract --clean

# Bước 3: Chạy SAST
semgrep --config p/php ./extracted/
```

### Audit Batch Với CodeQL

```bash
lazywp download --list audit-targets.txt
lazywp extract --list audit-targets.txt --output-dir ./codeql-src
codeql database create codeql-db --language=php --source-root=./codeql-src
codeql database analyze codeql-db php-security-queries
```

### Grep Thủ Công Tìm Pattern Nguy Hiểm

```bash
lazywp extract --slug contact-form-7
grep -rn "eval\|exec\|system\|passthru" ./extracted/contact-form-7/
grep -rn "\\$_GET\|\\$_POST\|\\$_REQUEST" ./extracted/contact-form-7/
```

### Xoá Và Giải Nén Lại

Dùng `--clean` để xoá thư mục extracted trước khi giải nén (hữu ích khi tải lại version mới):

```bash
lazywp download --list plugins.txt --force
lazywp extract --clean
```
