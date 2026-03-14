# Configuration & Operations

Set up API keys, manage caching, configure multi-key rotation, and tune performance.

---

## Initial Setup

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys
```

## View and Modify Config

```bash
lazywp config list
lazywp config set concurrency 10
lazywp config set cache_ttl 12h
lazywp config set output_dir /data/wp-downloads
```

Use a custom config path:

```bash
lazywp --config /path/to/config.yaml vuln --top 10
```

---

## Multi-Key Rotation

Configure multiple API keys per source for automatic rotation on rate limits (429/401):

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

When a key hits rate limit, lazywp automatically rotates to the next key and retries.

---

## Cache Management

### Check status

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

### Update and clear

```bash
lazywp cache update                   # refresh all sources
lazywp cache clear --source wordfence # clear one source
lazywp cache clear                    # clear all
```

---

## Rate Limiting

Per-domain rate limits prevent API throttling:

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

## Tips

- Use `-q` (quiet) to suppress cache/query info for cleaner output
- Use `-f json` for machine-readable output
- Set `title_max_len: 0` to show full vulnerability titles (0 = no truncation)
- Wordfence bulk feed (~128MB) is cached locally, subsequent queries are instant
- NVD queries are per-slug and cached individually
- Use `--force` to re-download plugins you already have
- Check version: `lazywp version`
