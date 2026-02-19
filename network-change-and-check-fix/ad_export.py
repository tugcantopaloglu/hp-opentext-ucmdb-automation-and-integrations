#!/usr/bin/env python3
"""
Active Directory Computer Export
Exports AD computer objects to CSV with optional name pattern filtering
and incremental export support (modified-date limiting via state file).

Usage:
    python ad_export.py export --config config.json --output ad_computers.csv
    python ad_export.py export --config config.json --output ad_computers.csv --full
    python ad_export.py export --config config.json --output filtered.csv --names "SRV*" "WS-*"
    python ad_export.py test --config config.json
    python ad_export.py generate-config --output config.json
"""

import argparse
import csv
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from ldap3 import ALL, NTLM, SIMPLE, Connection, Server

__version__ = "1.0.0"

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class ADConfig:
    """Active Directory connection configuration"""
    server: str
    domain: str
    username: str
    password: str
    base_dn: str
    use_ssl: bool = True


@dataclass
class ExportConfig:
    """Export filtering and output configuration"""
    name_patterns: List[str] = field(default_factory=list)
    csv_output_path: str = "ad_computers.csv"
    state_file_path: str = ".ad_export_state.json"


@dataclass
class AppConfig:
    """Main application configuration"""
    active_directory: ADConfig
    export: ExportConfig


# =============================================================================
# DATA MODEL
# =============================================================================


@dataclass
class ADComputer:
    """Represents an Active Directory computer object"""
    name: str
    distinguished_name: str
    dns_hostname: Optional[str] = None
    operating_system: Optional[str] = None
    when_changed: Optional[str] = None
    when_created: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    description: Optional[str] = None
    enabled: bool = True


# =============================================================================
# STATE MANAGER
# =============================================================================


def load_state(path: str) -> Dict:
    """Load state from JSON file. Returns dict with 'last_run' ISO timestamp or None."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_run": None}


def save_state(path: str, timestamp: datetime) -> None:
    """Save current run timestamp to state file."""
    state = {"last_run": timestamp.isoformat()}
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
    logger.info(f"State saved to {path}: last_run={timestamp.isoformat()}")


# =============================================================================
# AD CLIENT
# =============================================================================


class ADClient:
    """Client for interacting with Active Directory via LDAP"""

    def __init__(self, config: ADConfig):
        self.config = config
        self.connection = None

    def connect(self) -> None:
        """Bind to Active Directory"""
        server = Server(
            self.config.server,
            use_ssl=self.config.use_ssl,
            get_info=ALL,
        )

        # Use NTLM auth with DOMAIN\\username format
        user = f"{self.config.domain}\\{self.config.username}"
        auth = NTLM

        # Fall back to SIMPLE if domain is empty
        if not self.config.domain:
            user = self.config.username
            auth = SIMPLE

        self.connection = Connection(
            server,
            user=user,
            password=self.config.password,
            authentication=auth,
            auto_bind=True,
        )

        logger.info(f"Successfully connected to AD: {self.config.server}")

    def disconnect(self) -> None:
        """Unbind from Active Directory"""
        if self.connection:
            self.connection.unbind()
            logger.info("Disconnected from AD")

    def search_computers(
        self,
        name_filter: Optional[List[str]] = None,
        modified_after: Optional[datetime] = None,
    ) -> List[ADComputer]:
        """
        Search for computer objects in AD with optional filters.

        Args:
            name_filter: List of name patterns (e.g., ["SRV*", "WS-*"])
            modified_after: Only return computers modified or created after this timestamp
        """
        # Build LDAP filter
        filter_parts = ["(objectClass=computer)"]

        # Name pattern filter
        if name_filter:
            if len(name_filter) == 1:
                filter_parts.append(f"(cn={name_filter[0]})")
            else:
                name_clauses = "".join(f"(cn={p})" for p in name_filter)
                filter_parts.append(f"(|{name_clauses})")

        # Modified-date or created-date filter
        if modified_after:
            # LDAP generalized time format: YYYYMMDDHHmmss.0Z
            ldap_time = modified_after.strftime("%Y%m%d%H%M%S.0Z")
            filter_parts.append(
                f"(|(whenChanged>={ldap_time})(whenCreated>={ldap_time}))"
            )

        if len(filter_parts) == 1:
            ldap_filter = filter_parts[0]
        else:
            ldap_filter = "(&" + "".join(filter_parts) + ")"

        logger.info(f"LDAP search filter: {ldap_filter}")
        logger.info(f"Search base: {self.config.base_dn}")

        attributes = [
            "cn",
            "distinguishedName",
            "dNSHostName",
            "operatingSystem",
            "whenChanged",
            "whenCreated",
            "description",
            "userAccountControl",
        ]

        computers = []
        entry_generator = self.connection.extend.standard.paged_search(
            search_base=self.config.base_dn,
            search_filter=ldap_filter,
            attributes=attributes,
            paged_size=500,
            generator=True,
        )

        for entry in entry_generator:
            if entry.get("type") != "searchResEntry":
                continue
            try:
                computer = self._parse_computer(entry)
                computers.append(computer)
            except Exception as e:
                logger.warning(f"Failed to parse computer entry: {e}")
                continue

        logger.info(f"Found {len(computers)} computer(s)")
        return computers

    def _parse_computer(self, entry: Dict) -> ADComputer:
        """Extract attributes from an LDAP entry into an ADComputer dataclass"""
        attrs = entry.get("attributes", {})

        # Parse name
        name = attrs.get("cn", "")
        if isinstance(name, list):
            name = name[0] if name else ""

        # Parse distinguished name
        dn = attrs.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""

        # Parse DNS hostname
        dns_hostname = attrs.get("dNSHostName", None)
        if isinstance(dns_hostname, list):
            dns_hostname = dns_hostname[0] if dns_hostname else None

        # Parse operating system
        os_name = attrs.get("operatingSystem", None)
        if isinstance(os_name, list):
            os_name = os_name[0] if os_name else None

        # Parse timestamps
        when_changed = attrs.get("whenChanged", None)
        if isinstance(when_changed, list):
            when_changed = when_changed[0] if when_changed else None
        if isinstance(when_changed, datetime):
            when_changed = when_changed.isoformat()
        elif when_changed:
            when_changed = str(when_changed)

        when_created = attrs.get("whenCreated", None)
        if isinstance(when_created, list):
            when_created = when_created[0] if when_created else None
        if isinstance(when_created, datetime):
            when_created = when_created.isoformat()
        elif when_created:
            when_created = str(when_created)

        # Parse description
        description = attrs.get("description", None)
        if isinstance(description, list):
            description = description[0] if description else None

        # Parse enabled status from userAccountControl
        uac = attrs.get("userAccountControl", 0)
        if isinstance(uac, list):
            uac = uac[0] if uac else 0
        try:
            uac = int(uac)
        except (ValueError, TypeError):
            uac = 0
        # Bit 0x0002 = ACCOUNTDISABLE
        enabled = not bool(uac & 0x0002)

        return ADComputer(
            name=name,
            distinguished_name=dn,
            dns_hostname=dns_hostname,
            operating_system=os_name,
            when_changed=when_changed,
            when_created=when_created,
            ip_addresses=[],
            description=description,
            enabled=enabled,
        )

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# CSV EXPORTER
# =============================================================================


def export_to_csv(computers: List[ADComputer], output_path: str) -> None:
    """Write AD computers to CSV file."""
    headers = [
        "Name",
        "DistinguishedName",
        "DNSHostName",
        "OperatingSystem",
        "WhenChanged",
        "WhenCreated",
        "IPAddresses",
        "Description",
        "Enabled",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for c in computers:
            writer.writerow([
                c.name,
                c.distinguished_name,
                c.dns_hostname or "",
                c.operating_system or "",
                c.when_changed or "",
                c.when_created or "",
                ";".join(c.ip_addresses),
                c.description or "",
                str(c.enabled),
            ])

    logger.info(f"Exported {len(computers)} computers to {output_path}")


# =============================================================================
# CLI
# =============================================================================


def setup_logging(verbose: bool = False, log_file: str = None) -> None:
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


def load_config_from_file(config_path: str) -> AppConfig:
    """Load configuration from a JSON file"""
    with open(config_path, "r") as f:
        data = json.load(f)

    ad_data = data.get("active_directory", {})
    export_data = data.get("export", {})

    return AppConfig(
        active_directory=ADConfig(
            server=ad_data.get("server", ""),
            domain=ad_data.get("domain", ""),
            username=ad_data.get("username", ""),
            password=ad_data.get("password", ""),
            base_dn=ad_data.get("base_dn", ""),
            use_ssl=ad_data.get("use_ssl", True),
        ),
        export=ExportConfig(
            name_patterns=export_data.get("name_patterns", []),
            csv_output_path=export_data.get("csv_output_path", "ad_computers.csv"),
            state_file_path=export_data.get("state_file_path", ".ad_export_state.json"),
        ),
    )


def generate_config_template(output_path: str) -> None:
    """Generate a configuration template file"""
    template = {
        "active_directory": {
            "server": "dc01.example.com",
            "domain": "EXAMPLE",
            "username": "svc_account",
            "password": "your-password",
            "base_dn": "DC=example,DC=com",
            "use_ssl": True,
        },
        "export": {
            "name_patterns": [],
            "csv_output_path": "ad_computers.csv",
            "state_file_path": ".ad_export_state.json",
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connection(config: AppConfig) -> None:
    """Test AD connection"""
    print(f"\nTesting AD connection to {config.active_directory.server}...")
    try:
        with ADClient(config.active_directory) as client:
            # Run a minimal search to verify
            computers = client.search_computers(name_filter=["*"], modified_after=None)
            print(f"  Connected successfully - Found {len(computers)} computer(s)")
    except Exception as e:
        print(f"  Connection failed: {e}")
        sys.exit(1)


def run_export(config: AppConfig, args) -> None:
    """Run the AD computer export"""
    output_path = args.output or config.export.csv_output_path
    full_export = args.full
    name_patterns = args.names if args.names else config.export.name_patterns

    # Determine modified_after from state
    modified_after = None
    if not full_export:
        state = load_state(config.export.state_file_path)
        last_run = state.get("last_run")
        if last_run:
            modified_after = datetime.fromisoformat(last_run)
            logger.info(f"Incremental export: only computers modified after {last_run}")
        else:
            logger.info("No previous state found - performing full export")

    # Record start time for state
    run_timestamp = datetime.now()

    with ADClient(config.active_directory) as client:
        computers = client.search_computers(
            name_filter=name_patterns if name_patterns else None,
            modified_after=modified_after,
        )

    if not computers:
        print("No computers found matching the criteria.")
        # Still save state so next incremental picks up from now
        save_state(config.export.state_file_path, run_timestamp)
        return

    export_to_csv(computers, output_path)
    save_state(config.export.state_file_path, run_timestamp)

    # Print summary
    print("\n" + "=" * 60)
    print("AD Computer Export Report")
    print("=" * 60)
    print(f"  Mode: {'Full' if full_export or modified_after is None else 'Incremental'}")
    if modified_after:
        print(f"  Modified after: {modified_after.isoformat()}")
    if name_patterns:
        print(f"  Name patterns: {name_patterns}")
    print(f"  Computers exported: {len(computers)}")
    print(f"  Output file: {output_path}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Computer Export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full export
  python ad_export.py export --config config.json --output ad_computers.csv --full

  # Incremental export (only modified since last run)
  python ad_export.py export --config config.json --output ad_computers.csv

  # Export with name filtering
  python ad_export.py export --config config.json --names "SRV*" "WS-*" --output filtered.csv

  # Test AD connection
  python ad_export.py test --config config.json

  # Generate config template
  python ad_export.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export AD computers to CSV")
    export_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    export_parser.add_argument("--output", "-o", help="Output CSV file path (overrides config)")
    export_parser.add_argument("--full", action="store_true", help="Full export (ignore state, export all)")
    export_parser.add_argument("--names", nargs="+", help="Ad-hoc name patterns (overrides config)")
    export_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    export_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test AD connection")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Generate config command
    template_parser = subparsers.add_parser("generate-config", help="Generate a config template")
    template_parser.add_argument("--output", "-o", default="config.json", help="Output file path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-config":
        generate_config_template(args.output)
        return

    verbose = getattr(args, "verbose", False)
    log_file = getattr(args, "log_file", None)
    setup_logging(verbose, log_file)

    try:
        config = load_config_from_file(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    if args.command == "test":
        test_connection(config)
    elif args.command == "export":
        run_export(config, args)


if __name__ == "__main__":
    main()
