# AD Network Change & Check Fix

Sync Active Directory computer NetworkType values to SMAX CIs. Two-network workflow: export AD computers on one network, sync to SMAX on another.

## Architecture

- **ad_export.py** — Runs on Network A. Queries AD via LDAP, exports computers to CSV. Supports incremental export (only modified/created since last run).
- **ad_network_sync.py** — Runs on Network B. Reads CSV from Network A + queries its own AD. Assigns different NetworkType labels per source, updates SMAX CIs.

## Install

```bash
pip install ldap3 requests urllib3
```

For offline install, see `download_pkg_windows.bat` and `install_pkg_windows.bat`.

## Config

Copy `config.template.json` to `config.json` and fill in:

```json
{
  "active_directory": {"server": "dc01.example.com", "domain": "EXAMPLE", "username": "svc_account", "password": "...", "base_dn": "DC=example,DC=com", "use_ssl": true},
  "smax": {"base_url": "https://smax.example.com", "tenant_id": "123", "username": "admin", "password": "..."},
  "sync": {"csv_input_path": "ad_computers.csv", "csv_network_type": "Network1", "ad_network_type": "Network2", "dry_run": false}
}
```

## Usage

### Network A (AD Export)

```bash
# First run - full export
python ad_export.py export --config config.json --output ad_computers.csv --full

# Subsequent runs - incremental (only modified/created since last run)
python ad_export.py export --config config.json --output ad_computers.csv

# Export with name filtering
python ad_export.py export --config config.json --names "SRV*" "WS-*" --output filtered.csv

# Test AD connection
python ad_export.py test --config config.json
```

### Network B (Sync to SMAX)

```bash
# Test connections
python ad_network_sync.py test --config config.json

# Dry run
python ad_network_sync.py sync --config config.json --dry-run

# Full sync (first run)
python ad_network_sync.py sync --config config.json --full

# Incremental sync
python ad_network_sync.py sync --config config.json

# CSV source only (no local AD query)
python ad_network_sync.py sync --config config.json --csv-only

# Save report
python ad_network_sync.py sync --config config.json --output report.json

# View previous report
python ad_network_sync.py report --input report.json
```

## Workflow

1. **Network A**: `ad_export.py` exports AD computers to CSV (full or incremental)
2. Transfer CSV to Network B
3. **Network B**: `ad_network_sync.py` reads CSV + queries local AD, updates SMAX
   - CSV computers get `csv_network_type` label (e.g., "Network1")
   - Local AD computers get `ad_network_type` label (e.g., "Network2")
   - If same computer in both sources, live AD takes precedence
   - Computers not found in SMAX are listed in the report (not created)

## Output

```
============================================================
AD Network Type Sync Report
============================================================
Start Time: 2026-02-19 10:00:00
End Time: 2026-02-19 10:02:00
Duration: 120.00 seconds
Sources: csv:ad_computers.csv, ad_live
------------------------------------------------------------
Summary:
  Total computers processed: 250
  Successfully synced: 30
  Already synced (no change): 180
  Not found in SMAX: 25
  Failed: 0
============================================================

COMPUTERS NOT FOUND IN SMAX:
------------------------------------------------------------
  [csv] OLD-SERVER-01 (would assign: Network1)
  [ad_live] NEW-PC-05 (would assign: Network2)
------------------------------------------------------------
```
