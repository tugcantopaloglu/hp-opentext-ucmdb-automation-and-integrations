# UCMDB Duplicate CI Merger

Detects and merges duplicate CIs between UCMDB and SMAX.

## Problem

When both UCMDB discovery and SMAX create CIs for the same server, duplicate entries appear with the same name and `_NetworkType`. Each has different relationships:
- **SMAX-sourced CI**: Created by SMAX, has requests/incidents attached — **cannot be deleted**
- **UCMDB-sourced CI**: Created by UCMDB discovery, has software/agents attached — **will be merged and deleted**

## Solution

This tool:
1. Identifies duplicate pairs by matching `(name, _NetworkType)`
2. Determines source by checking the `createdby` field for the `"Updated-By-SMAX"` marker
3. Migrates all relations (software, agents, etc.) from the UCMDB CI to the SMAX CI
4. Copies any missing properties from the UCMDB CI to the SMAX CI
5. Deletes the UCMDB CI

## Requirements

- Python 3.6+
- `requests` and `urllib3` packages

## Installation

### Online
```bash
pip install -r requirements.txt
```

### Offline (Windows)
1. On a machine with internet, run `download_pkg_windows.bat`
2. Copy the `offline_packages` folder and scripts to the target machine
3. Run `install_pkg_windows.bat`

## Configuration

Copy `config.template.json` to `config.json` and update with your environment values:

```bash
python duplicate_ci_merge.py generate-config --output config.json
```

### Config Fields

| Section | Field | Description |
|---------|-------|-------------|
| `ucmdb.base_url` | UCMDB REST API URL | e.g., `https://ucmdb:8443/rest-api` |
| `ucmdb.username` | UCMDB admin username | |
| `ucmdb.password` | UCMDB admin password | |
| `ucmdb.client_context` | UCMDB client context | Default: `1` |
| `smax.base_url` | SMAX base URL | e.g., `https://smax.example.com` |
| `smax.tenant_id` | SMAX tenant ID | |
| `merge.ci_type` | UCMDB CI type to scan | Default: `node` |
| `merge.smax_created_by_marker` | Marker in `createdby` field | Default: `Updated-By-SMAX` |
| `merge.skip_composition_children` | Skip composition relations | Default: `true` (safety) |
| `merge.dry_run` | Global dry run flag | Default: `false` |

## Usage

### 1. Test Connections
```bash
python duplicate_ci_merge.py test --config config.json
```

### 2. Detect Duplicates
```bash
python duplicate_ci_merge.py detect --config config.json
python duplicate_ci_merge.py detect --config config.json --output duplicates.json
```

### 3. Dry Run Merge
```bash
python duplicate_ci_merge.py merge --config config.json --dry-run
python duplicate_ci_merge.py merge --config config.json --dry-run --ci-names "SERVER01"
```

### 4. Actual Merge
```bash
python duplicate_ci_merge.py merge --config config.json
python duplicate_ci_merge.py merge --config config.json --ci-names "SERVER01" "SERVER02"
python duplicate_ci_merge.py merge --config config.json --output merge_report.json
```

### 5. View Report
```bash
python duplicate_ci_merge.py report --input merge_report.json
```

## Safety Rules

1. **SMAX-sourced CI is never deleted** — the `DuplicatePair` structure enforces this
2. **Composition relations are skipped by default** — deleting a parent can cascade-delete children
3. **If any relation migration fails, the UCMDB CI is NOT deleted** — status becomes `PARTIAL`
4. **Dry run mode** — test before making real changes
5. **Detect and merge are separate commands** — operator reviews duplicates first
6. **Both CIs are verified to still exist** before merge begins (race condition protection)

## Merge Algorithm

```
UCMDB CI (to be deleted)          SMAX CI (to keep)
├── Software A ──DELETE──┐
├── Software B ──DELETE──┤        ├── Request 1 (untouched)
├── Scan Agent ──DELETE──┤        ├── Request 2 (untouched)
└── IP Address ──DELETE──┘        │
                                  ├── Software A ──CREATE
                                  ├── Software B ──CREATE
                                  ├── Scan Agent ──CREATE
                                  └── IP Address ──CREATE

Properties: Copy missing ones from UCMDB CI → SMAX CI
Final step: Delete UCMDB CI
```

## Merge Statuses

| Status | Meaning |
|--------|---------|
| `SUCCESS` | All relations migrated, properties copied, UCMDB CI deleted |
| `PARTIAL` | Some operations failed, UCMDB CI NOT deleted |
| `FAILED` | Merge could not proceed (CI missing, error) |
| `SKIPPED` | Pair skipped (filtered out) |
| `SKIPPED_SAFETY` | Skipped due to safety rules |
