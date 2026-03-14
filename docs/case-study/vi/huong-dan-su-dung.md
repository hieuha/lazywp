# lazywp - Huong Dan Su Dung

## Gioi Thieu

lazywp la cong cu CLI danh cho cac nha nghien cuu bao mat, giup tai hang loat plugin/theme WordPress va doi chieu voi cac co so du lieu lo hong (Wordfence, WPScan, NVD).

---

## 1. Tim Plugin Co Nhieu Lo Hong Nhat

Tim top 10 plugin co nhieu lo hong SQL injection:

```bash
lazywp vuln --top 10 --cwe-type sqli
```

Xem chi tiet tung CVE cua moi plugin:

```bash
lazywp vuln --top 10 --cwe-type sqli --detail
```

Loc theo muc do nghiem trong:

```bash
lazywp vuln --top 10 --severity critical
lazywp vuln --top 5 --severity high --cwe-type xss
```

Loc theo thoi gian:

```bash
lazywp vuln --top 10 --cwe-type rce --year 2025 --month 3
```

---

## 2. Tra Cuu Lo Hong Cua Mot Plugin Cu The

Tra cuu tat ca lo hong da biet cua mot plugin:

```bash
lazywp vuln --slug contact-form-7
lazywp vuln --slug contest-gallery
```

Chi tra cuu tu mot nguon cu the:

```bash
lazywp vuln --slug akismet --source wordfence
lazywp vuln --slug akismet --source nvd
```

---

## 3. Tai Hang Loat Plugin De Phan Tich

### Tai top plugin pho bien

```bash
lazywp top --count 50 --download
```

### Tai plugin moi nhat

```bash
lazywp top --browse new --count 20 --download
```

### Tim kiem va tai

```bash
lazywp search "ecommerce" --count 10
```

### Tai tu danh sach file

Tao file `plugins.txt`:

```
akismet
contact-form-7:6.1.5
elementor
```

Chay lenh:

```bash
lazywp download --list plugins.txt
```

### Ep tai lai du da ton tai

```bash
lazywp top --count 10 --download --force
```

---

## 4. Tai Plugin Co Lo Hong De Kiem Thu

Tim va tai cac plugin co lo hong SQL injection:

```bash
lazywp vuln --top 20 --cwe-type sqli --download
```

Tai mot plugin cu the sau khi xem CVE:

```bash
lazywp vuln --slug contest-gallery --download
```

---

## 5. Xuat Du Lieu De Bao Cao

### Xuat JSON de xu ly bang script

```bash
lazywp vuln --top 10 --cwe-type sqli -f json > bao-cao-vuln.json
lazywp vuln --top 5 --detail -f json > bao-cao-chi-tiet.json
```

### Xuat CSV de mo bang Excel

```bash
lazywp vuln --slug contest-gallery -f csv > contest-gallery-vulns.csv
lazywp top --count 100 -f csv > top-plugins.csv
```

### Ket hop voi jq de loc du lieu

```bash
lazywp vuln --top 10 -f json | jq '.[].slug'
lazywp vuln --slug akismet -f json | jq '[.[] | select(.cvss >= 7.0)]'
```

---

## 6. Quan Ly Cache

### Xem trang thai cache

```bash
lazywp cache status
```

Ket qua:

```
Cache directory: ./cache
Cache TTL: 24h

  wordfence     cached at 2026-03-14 11:33:31  (age: 2h15m, size: 127.8MB, status: valid)
  wpscan        no cache
  nvd           cached at 2026-03-14 11:33:31  (age: 2h15m, size: 45.2KB, status: valid)
```

### Cap nhat lai du lieu lo hong

```bash
lazywp cache update
```

### Xoa cache

```bash
lazywp cache clear --source wordfence
lazywp cache clear  # xoa tat ca
```

---

## 7. Lam Viec Voi Theme

Tat ca lenh deu ho tro theme qua `--type theme` (`-t theme`):

```bash
lazywp top -t theme --count 20
lazywp search "developer" -t theme
lazywp vuln --slug flavor -t theme
```

---

## 8. Cau Hinh

### Khoi tao config

```bash
cp config.yaml.example config.yaml
# Sua config.yaml, them API key cua ban
```

### Xem cau hinh hien tai

```bash
lazywp config list
```

### Thay doi cau hinh

```bash
lazywp config set concurrency 10
lazywp config set cache_ttl 12h
lazywp config set output_dir /data/wp-downloads
```

### Su dung file config khac

```bash
lazywp --config /duong-dan/config.yaml vuln --top 10
```

---

## 9. Xoay Nhieu API Key Tu Dong

Cau hinh nhieu API key de tu dong xoay khi bi gioi han:

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

Khi mot key bi 429 (rate limit), lazywp tu dong chuyen sang key tiep theo va thu lai.

---

## Meo Su Dung

- Dung `-q` (quiet) de an thong tin cache/query, output gon hon
- Dung `-f json` de lay output dang may doc duoc (khong lan text)
- Dat `title_max_len: 0` trong config de hien thi day du tieu de lo hong
- Wordfence bulk feed (~128MB) duoc cache tai may, cac truy van sau la tuc thi
- NVD truy van theo tung plugin va cache rieng
- Dung `--force` de tai lai plugin da co
- Xem phien ban: `lazywp version`
