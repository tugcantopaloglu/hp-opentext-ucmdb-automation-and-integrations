# OpenText UCMDB and SMAX Integrations

Independent Python command-line integrations for OpenText UCMDB/SMAX, Active Directory, and VMware vCenter. Each module keeps its own configuration and dependencies so it can be prepared and operated separately in a restricted network.

## Modules

| Directory | Entry points | Purpose |
| --- | --- | --- |
| `vcenter-vm-tag-integration` | `vm_ware_tag_exporter.py`, `vmware_smax_bridge.py` | Export VM tags and synchronize selected data with SMAX |
| `network-change-and-check-fix` | `ad_export.py`, `ad_network_sync.py` | Export AD network data and compare or synchronize it with SMAX |
| `duplicate-ci-with-custom-arragements` | `duplicate_ci_merge.py` | Inspect and handle duplicate configuration items |
| `ad-member-server-ip-sync` | `ad_server_export.py`, `ad_server_ip_sync.py` | Export AD member servers and synchronize server IP information |
| `ad-os-type-sync` | `ad_os_export.py`, `ad_os_sync.py` | Export AD operating-system information and synchronize it with SMAX |

Existing module documentation is available for [vCenter integration](vcenter-vm-tag-integration/README.md), [network synchronization](network-change-and-check-fix/README.md), and [duplicate CI handling](duplicate-ci-with-custom-arragements/README.md).

## Setup

Use a separate virtual environment for the module you intend to operate. For example, from the repository root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\vcenter-vm-tag-integration\requirements.txt
Copy-Item .\vcenter-vm-tag-integration\config.template.json .\vcenter-vm-tag-integration\config.json
.\.venv\Scripts\python.exe .\vcenter-vm-tag-integration\vm_ware_tag_exporter.py --help
.\.venv\Scripts\python.exe .\vcenter-vm-tag-integration\vmware_smax_bridge.py --help
```

Run the equivalent installation for another module's `requirements.txt`. Keep actual tenant identifiers, bind accounts, passwords, session tokens, reports, and exports out of source control. Local `config.json` files are ignored; committed `config.template.json` files remain available as templates.

Python 3.10 or later is the practical baseline for the scripts' type syntax. Dependency requirements use lower bounds rather than a lockfile. Resolve, review, and record the versions used in your deployment environment; an offline wheel bundle should be prepared for the same Python version and platform as its destination.

## Offline preparation

Each module includes `download_pkg_windows.bat` and `install_pkg_windows.bat`. Review their paths before running them. Alternatively, download an explicit wheel bundle on a connected machine:

```powershell
python -m pip download --dest .\wheelhouse -r .\vcenter-vm-tag-integration\requirements.txt
```

Transfer the module and wheel directory, then install on the matching target environment:

```powershell
python -m pip install --no-index --find-links .\wheelhouse -r .\vcenter-vm-tag-integration\requirements.txt
```

Offline dependency installation does not remove the need for network connectivity to AD, vCenter, or SMAX when a synchronization command is run.

## Operation and verification

Start with an entry point's `--help` output to confirm its command names and options. Some synchronization commands support `--dry-run`; that can still read remote data and requires endpoint connectivity. Commands named `test`, export, lookup, or comparison may also contact external systems. Perform initial acceptance with a test account, a bounded set of records, and reviewed configuration before applying writes to production.

Trust the required internal certificates and keep TLS verification enabled. Several templates or generated configuration paths currently disable verification, so review those values for the selected module before authentication. Existing claims that an individual module was previously used in production are not a current acceptance test for your environment.

For a local syntax-only check that does not load configuration or contact services:

```powershell
python -m compileall -q .\vcenter-vm-tag-integration .\network-change-and-check-fix .\duplicate-ci-with-custom-arragements .\ad-member-server-ip-sync .\ad-os-type-sync
```

After installing `network-change-and-check-fix/requirements.txt`, run the isolated export configuration/state regressions:

```powershell
python -m unittest discover -s tests -v
```

These tests use local temporary files and do not connect to Active Directory. A syntax check and CLI help check establish import/argument-parser readiness only. There is no repository-wide automated integration suite or CI workflow. Real acceptance must verify authenticated reads, matched record identity, proposed changes, write authorization, audit output, retry behavior, and recoverability against the designated AD/vCenter/SMAX environment.

## License

See [LICENSE](LICENSE).
