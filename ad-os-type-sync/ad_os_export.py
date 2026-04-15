#!/usr/bin/env python3
"""
AD Server OS Type Export
Exports server objects from Active Directory to CSV with their operating system
information, classifying each as Windows or Unix.

Usage:
    python ad_os_export.py export --config config.json --output ad_os_servers.csv
    python ad_os_export.py export --config config.json --output ad_os_servers.csv --full
    python ad_os_export.py export --config config.json --names "SRV*" "WS-*"
    python ad_os_export.py test --config config.json
    python ad_os_export.py generate-config --output config.json
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
    csv_output_path: str = "ad_os_servers.csv"
    state_file_path: str = ".ad_os_export_state.json"


@dataclass
class AppConfig:
    """Main application configuration"""
    active_directory: ADConfig
    export: ExportConfig


# =============================================================================
# DATA MODEL
# =============================================================================


@dataclass
class ServerInfo:
    """Represents a server from Active Directory with OS information"""
    name: str
    operating_system: str
    os_type: str  # "Windows" or "Unix"
    distinguished_name: str = ""


# =============================================================================
# OS CLASSIFICATION
# =============================================================================


WINDOWS_KEYWORDS = ["windows"]
UNIX_KEYWORDS = ["linux", "ubuntu", "debian", "centos", "red hat", "rhel",
                  "suse", "fedora", "oracle linux", "unix", "solaris",
                  "aix", "hp-ux", "freebsd"]


OU_WINDOWS_KEYWORDS = ["windows"]
OU_UNIX_KEYWORDS = ["lunix", "linux", "unix"]


def classify_os(operating_system: str, distinguished_name: str = "") -> str:
    """
    Classify an operating system string as 'Windows' or 'Unix'.
    Falls back to OU path in distinguishedName if operatingSystem is empty.
    e.g. OU=LUNIX,OU=MemberServers,... -> Unix
         OU=WINDOWS,OU=MemberServers,... -> Windows
    """
    # Primary: check operatingSystem attribute
    if operating_system:
        os_lower = operating_system.lower()

        for keyword in WINDOWS_KEYWORDS:
            if keyword in os_lower:
                return "Windows"

        for keyword in UNIX_KEYWORDS:
            if keyword in os_lower:
                return "Unix"

    # Fallback: check OU names in distinguishedName
    if distinguished_name:
        # Extract OU components: "OU=LUNIX", "OU=WINDOWS", etc.
        dn_lower = distinguished_name.lower()
        ou_parts = [
            part.split("=", 1)[1]
            for part in dn_lower.split(",")
            if part.strip().startswith("ou=")
        ]

        for ou in ou_parts:
            for keyword in OU_WINDOWS_KEYWORDS:
                if keyword in ou:
                    return "Windows"
            for keyword in OU_UNIX_KEYWORDS:
                if keyword in ou:
                    return "Unix"

    return ""


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

        user = f"{self.config.domain}\\{self.config.username}"
        auth = NTLM

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

    def search_servers(
        self,
        name_filter: Optional[List[str]] = None,
        modified_after: Optional[datetime] = None,
    ) -> List[ServerInfo]:
        """
        Search for computer objects under the configured OU,
        fetch their operatingSystem attribute.
        """
        filter_parts = ["(objectClass=computer)"]

        if name_filter:
            if len(name_filter) == 1:
                filter_parts.append(f"(cn={name_filter[0]})")
            else:
                name_clauses = "".join(f"(cn={p})" for p in name_filter)
                filter_parts.append(f"(|{name_clauses})")

        if modified_after:
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
            "operatingSystem",
            "distinguishedName",
            "whenChanged",
            "whenCreated",
        ]

        servers = []
        classified_count = 0

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
                server = self._parse_server(entry)
                if server:
                    if server.os_type:
                        classified_count += 1
                    servers.append(server)
            except Exception as e:
                logger.warning(f"Failed to parse server entry: {e}")
                continue

        unclassified = len(servers) - classified_count
        logger.info(
            f"Found {len(servers)} server(s) - "
            f"Classified: {classified_count}, Unclassified: {unclassified}"
        )
        return servers

    def _parse_server(self, entry: Dict) -> Optional[ServerInfo]:
        """Extract attributes from an LDAP entry"""
        attrs = entry.get("attributes", {})

        name = attrs.get("cn", "")
        if isinstance(name, list):
            name = name[0] if name else ""

        if not name:
            return None

        operating_system = attrs.get("operatingSystem", "")
        if isinstance(operating_system, list):
            operating_system = operating_system[0] if operating_system else ""

        dn = attrs.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""

        os_type = classify_os(operating_system, dn)

        return ServerInfo(
            name=name,
            operating_system=operating_system or "",
            os_type=os_type,
            distinguished_name=dn,
        )

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# CSV EXPORTER
# =============================================================================


def export_to_csv(servers: List[ServerInfo], output_path: str) -> None:
    """Write server OS info to CSV file."""
    headers = [
        "Name",
        "OperatingSystem",
        "OsType",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for s in servers:
            writer.writerow([
                s.name,
                s.operating_system,
                s.os_type,
            ])

    logger.info(f"Exported {len(servers)} servers to {output_path}")


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
            csv_output_path=export_data.get("csv_output_path", "ad_os_servers.csv"),
            state_file_path=export_data.get("state_file_path", ".ad_os_export_state.json"),
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
            "base_dn": "OU=MemberServers,DC=example,DC=com",
            "use_ssl": True,
        },
        "export": {
            "name_patterns": [],
            "csv_output_path": "ad_os_servers.csv",
            "state_file_path": ".ad_os_export_state.json",
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connection(config: AppConfig) -> None:
    """Test AD connection and OS attribute retrieval"""
    print(f"\nTesting AD connection to {config.active_directory.server}...")
    print(f"  Search base: {config.active_directory.base_dn}")
    try:
        with ADClient(config.active_directory) as client:
            servers = client.search_servers(name_filter=["*"], modified_after=None)
            windows = sum(1 for s in servers if s.os_type == "Windows")
            unix = sum(1 for s in servers if s.os_type == "Unix")
            unknown = sum(1 for s in servers if not s.os_type)
            print(f"  Connected successfully - Found {len(servers)} server(s)")
            print(f"  Windows: {windows}, Unix: {unix}, Unclassified: {unknown}")

            if servers:
                print("\n  Sample entries:")
                for s in servers[:5]:
                    print(f"    {s.name}: {s.operating_system} -> {s.os_type or '?'}")
    except Exception as e:
        print(f"  Connection failed: {e}")
        sys.exit(1)


def run_export(config: AppConfig, args) -> None:
    """Run the AD OS export"""
    output_path = args.output or config.export.csv_output_path
    full_export = args.full
    name_patterns = args.names if args.names else config.export.name_patterns

    modified_after = None
    if not full_export:
        state = load_state(config.export.state_file_path)
        last_run = state.get("last_run")
        if last_run:
            modified_after = datetime.fromisoformat(last_run)
            logger.info(f"Incremental export: only servers modified after {last_run}")
        else:
            logger.info("No previous state found - performing full export")

    run_timestamp = datetime.now()

    with ADClient(config.active_directory) as client:
        servers = client.search_servers(
            name_filter=name_patterns if name_patterns else None,
            modified_after=modified_after,
        )

    if not servers:
        print("No servers found matching the criteria.")
        save_state(config.export.state_file_path, run_timestamp)
        return

    export_to_csv(servers, output_path)
    save_state(config.export.state_file_path, run_timestamp)

    windows = sum(1 for s in servers if s.os_type == "Windows")
    unix = sum(1 for s in servers if s.os_type == "Unix")
    unknown = sum(1 for s in servers if not s.os_type)

    print("\n" + "=" * 60)
    print("AD Server OS Type Export Report")
    print("=" * 60)
    print(f"  Mode: {'Full' if full_export or modified_after is None else 'Incremental'}")
    if modified_after:
        print(f"  Modified after: {modified_after.isoformat()}")
    if name_patterns:
        print(f"  Name patterns: {name_patterns}")
    print(f"  Servers exported: {len(servers)}")
    print(f"  Windows: {windows}")
    print(f"  Unix: {unix}")
    print(f"  Unclassified: {unknown}")
    print(f"  Output file: {output_path}")
    print("=" * 60)

    if unknown > 0:
        print("\nSERVERS WITH UNCLASSIFIED OS:")
        print("-" * 60)
        for s in servers:
            if not s.os_type:
                print(f"  {s.name} (OS: {s.operating_system or 'N/A'})")
        print("-" * 60)
    print("")


def main():
    parser = argparse.ArgumentParser(
        description="AD Server OS Type Export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full export
  python ad_os_export.py export --config config.json --output ad_os_servers.csv --full

  # Incremental export (only modified since last run)
  python ad_os_export.py export --config config.json

  # Export with name filtering
  python ad_os_export.py export --config config.json --names "SRV*" "WS-*"

  # Test AD connection
  python ad_os_export.py test --config config.json

  # Generate config template
  python ad_os_export.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    export_parser = subparsers.add_parser("export", help="Export AD servers with OS type to CSV")
    export_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    export_parser.add_argument("--output", "-o", help="Output CSV file path (overrides config)")
    export_parser.add_argument("--full", action="store_true", help="Full export (ignore state, export all)")
    export_parser.add_argument("--names", nargs="+", help="Ad-hoc name patterns (overrides config)")
    export_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    export_parser.add_argument("--log-file", help="Log to file in addition to console")

    test_parser = subparsers.add_parser("test", help="Test AD connection and OS retrieval")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

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
