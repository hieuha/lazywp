# Cấu Hình & Vận Hành

Thiết lập API key, quản lý cache, xoay key tự động, và tinh chỉnh hiệu năng.

---

## Thiết Lập Ban Đầu

```bash
cp config.yaml.example config.yaml
# Sửa config.yaml, thêm API key
```

## Xem và Thay Đổi Cấu Hình

```bash
lazywp config list
lazywp config set concurrency 10
lazywp config set cache_ttl 12h
lazywp config set output_dir /data/wp-downloads
```

Dùng file config khác:

```bash
lazywp --config /duong-dan/config.yaml vuln --top 10
```

---

## Xoay Nhiều API Key

Cấu hình nhiều key mỗi nguồn để tự động xoay khi bị rate limit (429/401):

```yaml
wordfence_keys:
  - KEY_1
  - KEY_2
  - KEY_3
wpscan_keys:
  - WPSCAN_KEY_1
  - WPSCAN_KEY_2
nvd_keys:
  - NVD_KEY_1
projectdiscovery_api_keys:
  - PD_KEY_1
  - PD_KEY_2
key_rotation: round-robin
```

Khi một key bị rate limit, lazywp tự động chuyển sang key tiếp theo và thử lại.

---

## Quản Lý Cache

### Xem trạng thái

```bash
lazywp cache status
```

```
Cache directory: ./cache
Cache TTL: 24h

  wordfence     cached at 2026-03-14 11:33:31  (age: 2h15m, size: 127.8MB, status: valid)
  wpscan        no cache
  nvd           cached at 2026-03-14 11:33:31  (age: 2h15m, size: 45.2KB, status: valid)
```

### Cập nhật và xoá

```bash
lazywp cache update                   # làm mới tất cả nguồn
lazywp cache clear --source wordfence # xoá một nguồn
lazywp cache clear                    # xoá tất cả
```

---

## Rate Limiting

Giới hạn request mỗi domain để tránh bị throttle:

```yaml
rate_limits:
  api.wordpress.org: 5        # 5 req/s
  wpscan.com: 1               # 1 req/s
  services.nvd.nist.gov: 0.16 # 1 req/6s
  www.wordfence.com: 0.1      # 1 req/10s
retry_max: 3
retry_base_delay: 1s
```

---

## Mẹo Sử Dụng

- Dùng `-q` (quiet) để ẩn thông tin cache/query, output gọn hơn
- Dùng `-f json` để lấy output máy đọc được
- Đặt `title_max_len: 0` để hiện đầy đủ tiêu đề lỗ hổng
- Wordfence bulk feed (~128MB) cache tại máy, truy vấn sau là tức thì
- NVD truy vấn theo từng plugin và cache riêng
- Dùng `--force` để tải lại plugin đã có
- Xem phiên bản: `lazywp version`
