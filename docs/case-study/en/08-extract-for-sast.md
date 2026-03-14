# Extract Plugins for SAST

Extract downloaded plugin/theme zip files for static application security testing (SAST) with Semgrep, CodeQL, grep, etc.

---

## Extract All Downloaded Plugins

```bash
lazywp extract
```

Default output to `./extracted/` with structure:

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

## Extract Specific Plugin

```bash
lazywp extract --slug akismet
lazywp extract --slug elementor --output-dir ./audit
```

## Extract From List File

```bash
lazywp extract --list targets.txt
```

## Extract Themes

```bash
lazywp extract -t theme
lazywp extract -t theme --slug flavor
```

---

## Real-World Scenarios

### Download + Extract + Run Semgrep

Full pipeline from download to vulnerability detection:

```bash
# Step 1: Download top vulnerable plugins
lazywp vuln --top 20 --severity critical --download

# Step 2: Extract
lazywp extract --clean

# Step 3: Run SAST
semgrep --config p/php ./extracted/
```

### Batch Audit With CodeQL

```bash
lazywp download --list audit-targets.txt
lazywp extract --list audit-targets.txt --output-dir ./codeql-src
codeql database create codeql-db --language=php --source-root=./codeql-src
codeql database analyze codeql-db php-security-queries
```

### Manual Grep for Dangerous Patterns

```bash
lazywp extract --slug contact-form-7
grep -rn "eval\|exec\|system\|passthru" ./extracted/contact-form-7/
grep -rn "\\$_GET\|\\$_POST\|\\$_REQUEST" ./extracted/contact-form-7/
```

### Clean and Re-extract

Use `--clean` to remove the extracted directory before extracting (useful after re-downloading newer versions):

```bash
lazywp download --list plugins.txt --force
lazywp extract --clean
```
