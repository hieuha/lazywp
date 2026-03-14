# Bulk Download & Offline Analysis

Download WordPress plugins and themes in bulk for offline code review, static analysis, or archive building.

---

## Browse and Download Popular Plugins

```bash
lazywp top --count 50 --download           # top 50 popular plugins
lazywp top --browse new --count 20 --download  # newest 20 plugins
```

## Search and Download

```bash
lazywp search "ecommerce" --count 10
lazywp search "security" --count 20
lazywp download woocommerce elementor akismet
```

## Download from a List File

Create `plugins.txt` (one slug per line, optional version pinning with `:`):

```
akismet
contact-form-7:6.1.5
elementor
woocommerce
```

```bash
lazywp download --list plugins.txt
lazywp download --list plugins.txt --force   # re-download existing
```

## List Downloaded Items

```bash
lazywp list
```

---

## Working with Themes

All download commands support themes via `-t theme`:

```bash
lazywp top -t theme --count 20
lazywp search "developer" -t theme
lazywp download flavor flavor -t theme
```

---

## Example Scenarios

### Build a Plugin Archive

Download the top 100 most popular plugins for offline static analysis:

```bash
lazywp top --count 100 --download
```

Files are stored in `downloads/plugins/<slug>/<version>/` with metadata.

### Version-Pinned Downloads

Pin specific versions for reproducible audit environments:

```
# audit-targets.txt
elementor:3.20.0
contact-form-7:6.1.2
woocommerce:8.5.0
```

```bash
lazywp download --list audit-targets.txt
```

### Resume Interrupted Downloads

If a batch download is interrupted (network issue, Ctrl+C), simply re-run the same command — lazywp automatically resumes from where it stopped, skipping already-downloaded items.

```bash
lazywp download --list large-list.txt    # interrupted at #45
lazywp download --list large-list.txt    # resumes from #46
```
