#!/usr/bin/env python3
"""
AD Member Server Export with IP Resolution
Exports server objects from the MemberServers OU in Active Directory to CSV,
resolving IP addresses via DNS lookup from dNSHostName attribute.

Usage:
    python ad_server_export.py export --config config.json --output ad_servers.csv
    python ad_server_export.py export --config config.json --output ad_servers.csv --full
    python ad_server_export.py export --config config.json --names "SRV*" "WS-*"
    python ad_server_export.py test --config config.json
    python ad_server_export.py generate-config --output config.json
"""

import argparse
import csv
import json
import logging
import socket
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
    csv_output_path: str = "ad_servers.csv"
    state_file_path: str = ".ad_server_export_state.json"


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
    """Represents a server from Active Directory with resolved IP"""
    name: str
    ip_address: str
    dns_hostname: str
    distinguished_name: str


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
# DNS RESOLVER
# =============================================================================


def resolve_ip(dns_hostname: str) -> Optional[str]:
    """
    Resolve a DNS hostname to an IPv4 address using socket.getaddrinfo.
    Returns the first resolved IPv4 address, or None on failure.
    """
    if not dns_hostname:
        return None

    try:
        results = socket.getaddrinfo(dns_hostname, None, socket.AF_INET)
        if results:
            # results[0][4][0] is the IP address string
            ip = results[0][4][0]
            logger.debug(f"Resolved {dns_hostname} -> {ip}")
            return ip
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {dns_hostname}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error resolving {dns_hostname}: {e}")

    return None


# =============================================================================
# AD CLIENT
# =============================================================================


class ADClient:
    """Client for interacting with Active Directory via LDAP"""

    def __init__(self, config: ADConfig):
        self.config = config
        self.connection = None
        self._dns_suffix = self._build_dns_suffix()

    def _build_dns_suffix(self) -> str:
        """Build DNS suffix from base_dn DC components (e.g. DC=example,DC=com -> example.com)"""
        parts = [
            p.split("=", 1)[1]
            for p in self.config.base_dn.split(",")
            if p.strip().upper().startswith("DC=")
        ]
        return ".".join(parts) if parts else ""

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

    def search_servers(
        self,
        name_filter: Optional[List[str]] = None,
        modified_after: Optional[datetime] = None,
    ) -> List[ServerInfo]:
        """
        Search for computer objects under the MemberServers OU,
        resolve their IP addresses via DNS.

        Args:
            name_filter: List of name patterns (e.g., ["SRV*", "WS-*"])
            modified_after: Only return servers modified or created after this timestamp
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
            "dNSHostName",
            "distinguishedName",
            "whenChanged",
            "whenCreated",
        ]

        servers = []
        resolved_count = 0
        failed_count = 0

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
                    if server.ip_address:
                        resolved_count += 1
                    else:
                        failed_count += 1
                    servers.append(server)
            except Exception as e:
                logger.warning(f"Failed to parse server entry: {e}")
                continue

        logger.info(
            f"Found {len(servers)} server(s) - "
            f"IP resolved: {resolved_count}, IP failed: {failed_count}"
        )
        return servers

    def _parse_server(self, entry: Dict) -> Optional[ServerInfo]:
        """Extract attributes from an LDAP entry, resolve IP via DNS"""
        attrs = entry.get("attributes", {})

        name = attrs.get("cn", "")
        if isinstance(name, list):
            name = name[0] if name else ""

        if not name:
            return None

        dns_hostname = attrs.get("dNSHostName", "")
        if isinstance(dns_hostname, list):
            dns_hostname = dns_hostname[0] if dns_hostname else ""

        dn = attrs.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""

        # Try multiple resolution strategies:
        # 1. dNSHostName from AD (FQDN)
        # 2. cn (computer name) alone
        # 3. cn + domain suffix as FQDN
        ip_address = None

        if dns_hostname:
            ip_address = resolve_ip(dns_hostname)

        if not ip_address:
            logger.debug(f"dNSHostName resolution failed for {name}, trying cn...")
            ip_address = resolve_ip(name)

        if not ip_address and self._dns_suffix:
            fqdn = f"{name}.{self._dns_suffix}"
            logger.debug(f"cn resolution failed for {name}, trying FQDN: {fqdn}")
            ip_address = resolve_ip(fqdn)

        if not ip_address:
            logger.warning(f"Could not resolve IP for server: {name} (dNSHostName: {dns_hostname})")

        return ServerInfo(
            name=name,
            ip_address=ip_address or "",
            dns_hostname=dns_hostname or "",
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
    """Write server info to CSV file."""
    headers = [
        "Name",
        "IPAddress",
        "DNSHostName",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for s in servers:
            writer.writerow([
                s.name,
                s.ip_address,
                s.dns_hostname,
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
            csv_output_path=export_data.get("csv_output_path", "ad_servers.csv"),
            state_file_path=export_data.get("state_file_path", ".ad_server_export_state.json"),
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
            "csv_output_path": "ad_servers.csv",
            "state_file_path": ".ad_server_export_state.json",
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connection(config: AppConfig) -> None:
    """Test AD connection and DNS resolution"""
    print(f"\nTesting AD connection to {config.active_directory.server}...")
    print(f"  Search base: {config.active_directory.base_dn}")
    try:
        with ADClient(config.active_directory) as client:
            servers = client.search_servers(name_filter=["*"], modified_after=None)
            resolved = sum(1 for s in servers if s.ip_address)
            print(f"  Connected successfully - Found {len(servers)} server(s)")
            print(f"  IP resolved: {resolved}, IP failed: {len(servers) - resolved}")
    except Exception as e:
        print(f"  Connection failed: {e}")
        sys.exit(1)


def run_export(config: AppConfig, args) -> None:
    """Run the AD server export"""
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
            logger.info(f"Incremental export: only servers modified after {last_run}")
        else:
            logger.info("No previous state found - performing full export")

    # Record start time for state
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

    # Print summary
    resolved = sum(1 for s in servers if s.ip_address)

    print("\n" + "=" * 60)
    print("AD Member Server Export Report")
    print("=" * 60)
    print(f"  Mode: {'Full' if full_export or modified_after is None else 'Incremental'}")
    if modified_after:
        print(f"  Modified after: {modified_after.isoformat()}")
    if name_patterns:
        print(f"  Name patterns: {name_patterns}")
    print(f"  Servers exported: {len(servers)}")
    print(f"  IP resolved: {resolved}")
    print(f"  IP failed: {len(servers) - resolved}")
    print(f"  Output file: {output_path}")
    print("=" * 60)

    if len(servers) - resolved > 0:
        print("\nSERVERS WITH UNRESOLVED IP:")
        print("-" * 60)
        for s in servers:
            if not s.ip_address:
                print(f"  {s.name} (dNSHostName: {s.dns_hostname or 'N/A'})")
        print("-" * 60)
    print("")


def main():
    parser = argparse.ArgumentParser(
        description="AD Member Server Export with IP Resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full export
  python ad_server_export.py export --config config.json --output ad_servers.csv --full

  # Incremental export (only modified since last run)
  python ad_server_export.py export --config config.json --output ad_servers.csv

  # Export with name filtering
  python ad_server_export.py export --config config.json --names "SRV*" "WS-*"

  # Test AD connection and DNS resolution
  python ad_server_export.py test --config config.json

  # Generate config template
  python ad_server_export.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export AD servers to CSV with IP")
    export_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    export_parser.add_argument("--output", "-o", help="Output CSV file path (overrides config)")
    export_parser.add_argument("--full", action="store_true", help="Full export (ignore state, export all)")
    export_parser.add_argument("--names", nargs="+", help="Ad-hoc name patterns (overrides config)")
    export_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    export_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test AD connection and DNS resolution")
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
