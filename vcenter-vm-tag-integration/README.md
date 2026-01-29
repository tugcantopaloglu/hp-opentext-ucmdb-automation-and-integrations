# VMware-SMAX Bridge (Multi-vCenter)

Sync VMware VM owner tags to SMAX CI ownership. Supports **multiple vCenters**.

## Features

- Multi-vCenter support (array config)
- Backward compatible (single object config)
- Text report output with untagged VM list
- Dry run mode
- Caching for large environments

## Install

```bash
pip install pyVmomi requests
```

## Config

Copy `config.template.json` to `config.json`:

```json
{
  "vmware": [
    {"name": "prod", "host": "vcenter-prod.example.com", "username": "admin@vsphere.local", "password": "..."},
    {"name": "dev", "host": "vcenter-dev.example.com", "username": "admin@vsphere.local", "password": "..."}
  ],
  "smax": {"base_url": "https://smax.example.com", "tenant_id": "123", "username": "admin", "password": "..."},
  "sync": {"owner_tag_category": "Owner", "dry_run": false}
}
```

Single vCenter (legacy) also works:
```json
{"vmware": {"host": "vcenter.example.com", ...}, ...}
```

## Usage

```bash
# Test connections
python main.py test --config config.json

# Dry run
python main.py sync --config config.json --dry-run

# Sync all
python main.py sync --config config.json

# Save reports
python main.py sync --config config.json --output report.json --report-file report.txt

# List tags
python main.py list-tags --config config.json
```

## Output

```
============================================================
VMware-SMAX Synchronization Report
============================================================
Start Time: 2026-01-29 10:00:00
End Time: 2026-01-29 10:05:00
Duration: 300.00 seconds
vCenters: vcenter-prod, vcenter-dev
------------------------------------------------------------
Summary:
  Total VMs processed: 500
  Successfully synced: 45
  Already synced: 320
  No owner tag: 75
  ...
============================================================

VMs WITHOUT OWNER TAG:
------------------------------------------------------------
  [vcenter-prod] web-server-01
  [vcenter-dev] test-vm-03
------------------------------------------------------------
```
