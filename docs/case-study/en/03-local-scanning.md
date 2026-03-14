# Local Directory Scanning

Scan installed WordPress plugins/themes on disk, detect versions, and cross-reference against vulnerability databases.

---

## Basic Scanning

Point lazywp at a `wp-content/plugins` or `wp-content/themes` directory:

```bash
lazywp scan /var/www/html/wp-content/plugins -t plugin
lazywp scan /var/www/html/wp-content/themes -t theme
```

Output example:

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

## Scan Options

```bash
lazywp scan ./plugins -t plugin --source wordfence   # single source
lazywp scan ./plugins -t plugin --no-cache            # force online lookup
lazywp scan ./plugins -t plugin --check-exploit       # enrich with PoC/KEV/Nuclei data
```

## Export Scan Results

```bash
lazywp scan ./plugins -t plugin -f json -o scan.json
lazywp scan ./plugins -t plugin -f csv -o scan.csv
```

---

## How Version Detection Works

- **Plugins**: Reads `readme.txt` (Stable tag), falls back to `Version:` header in `.php` files
- **Themes**: Reads `Version:` header in `style.css`, falls back to `readme.txt`

## Auto-Disable Failing Sources

If a source (e.g., WPScan) returns API key errors, lazywp automatically disables it for remaining plugins to avoid repeated failures.

---

## Example Scenarios

### Post-Compromise Forensics

After gaining access to a compromised WordPress site, scan installed plugins to identify the attack vector:

```bash
lazywp scan /var/www/html/wp-content/plugins -t plugin --check-exploit
```

The `--check-exploit` flag enriches results with PoC availability — helping identify which CVEs were likely exploited.

### Client WordPress Audit

Scan a client's WordPress installation and generate a JSON report for your pentest deliverable:

```bash
lazywp scan /client/wp-content/plugins -t plugin -f json -o client-scan.json
lazywp scan /client/wp-content/themes -t theme -f json -o client-themes.json
```

### Staging vs Production Comparison

Scan both environments and diff the results:

```bash
lazywp scan /staging/wp-content/plugins -t plugin -f json -o staging.json
lazywp scan /prod/wp-content/plugins -t plugin -f json -o prod.json
diff <(jq -r '.[].slug' staging.json | sort) <(jq -r '.[].slug' prod.json | sort)
```
