#!/usr/bin/env python3
"""
AD Member Server IP Sync to SMAX
Reads server IPs from CSV (ad_server_export.py output from Network A) AND
live AD query with DNS resolution (Network B), merges both sources
(live AD takes precedence), and updates the target field on matching SMAX CIs.

Usage:
    python ad_server_ip_sync.py sync --config config.json
    python ad_server_ip_sync.py sync --config config.json --dry-run
    python ad_server_ip_sync.py sync --config config.json --csv-only
    python ad_server_ip_sync.py sync --config config.json --ad-only --full
    python ad_server_ip_sync.py sync --config config.json --names "SRV*" "WS-*"
    python ad_server_ip_sync.py test --config config.json
    python ad_server_ip_sync.py generate-config --output config.json
    python ad_server_ip_sync.py report --input sync_report.json
"""

import argparse
import csv
import fnmatch
import json
import logging
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
from ldap3 import ALL, NTLM, SIMPLE, Connection, Server
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
class SMAXConfig:
    """SMAX connection configuration"""
    base_url: str
    tenant_id: str
    username: str
    password: str
    api_token: Optional[str] = None


@dataclass
class SyncConfig:
    """Synchronization configuration"""
    csv_input_path: str = "ad_servers.csv"
    smax_ci_type: str = "Server"
    smax_matching_field: str = "DisplayLabel"
    smax_alt_matching_field: str = "PrimaryIP"
    smax_target_field: str = "AgBiosAdi"
    name_patterns: List[str] = field(default_factory=list)
    state_file_path: str = ".server_ip_sync_state.json"
    dry_run: bool = False
    batch_size: int = 50


@dataclass
class AppConfig:
    """Main application configuration"""
    active_directory: ADConfig
    smax: SMAXConfig
    sync: SyncConfig


# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class ServerInfo:
    """Represents a server with resolved IP address"""
    name: str
    ip_address: str
    dns_hostname: str = ""


@dataclass
class CIRecord:
    """Represents a Configuration Item in SMAX"""
    id: str
    display_label: str
    ci_type: str
    target_field_value: Optional[str] = None
    primary_ip: Optional[str] = None
    dns_name: Optional[str] = None
    properties: Dict[str, Any] = None

    def __post_init__(self):
        if self.properties is None:
            self.properties = {}


class SyncStatus(Enum):
    """Status of a sync operation"""
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_FOUND_IN_SMAX = "not_found_in_smax"
    ALREADY_SYNCED = "already_synced"
    NO_IP = "no_ip"


@dataclass
class SyncResult:
    """Result of syncing a single server"""
    server_name: str
    source: str  # "csv" or "ad_live"
    ip_address: str
    status: SyncStatus
    message: str
    ci_id: Optional[str] = None


@dataclass
class SyncReport:
    """Aggregated sync report"""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_servers: int = 0
    synced: int = 0
    skipped: int = 0
    failed: int = 0
    not_found: int = 0
    already_synced: int = 0
    no_ip: int = 0
    results: List[SyncResult] = field(default_factory=list)
    not_found_report: List[Dict[str, str]] = field(default_factory=list)
    no_ip_report: List[Dict[str, str]] = field(default_factory=list)
    sources_processed: List[str] = field(default_factory=list)

    def add_result(self, result: SyncResult) -> None:
        """Add a sync result and update counters"""
        self.results.append(result)
        status_map = {
            SyncStatus.SUCCESS: "synced",
            SyncStatus.SKIPPED: "skipped",
            SyncStatus.FAILED: "failed",
            SyncStatus.NOT_FOUND_IN_SMAX: "not_found",
            SyncStatus.ALREADY_SYNCED: "already_synced",
            SyncStatus.NO_IP: "no_ip",
        }
        attr = status_map.get(result.status)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

        if result.status == SyncStatus.NOT_FOUND_IN_SMAX:
            self.not_found_report.append({
                "server_name": result.server_name,
                "source": result.source,
                "ip_address": result.ip_address,
            })

        if result.status == SyncStatus.NO_IP:
            self.no_ip_report.append({
                "server_name": result.server_name,
                "source": result.source,
            })

    def finalize(self) -> None:
        """Mark the report as complete"""
        self.end_time = datetime.now()

    def to_dict(self) -> Dict:
        """Convert report to dictionary"""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (
                (self.end_time - self.start_time).total_seconds()
                if self.end_time else None
            ),
            "sources_processed": self.sources_processed,
            "summary": {
                "total_servers": self.total_servers,
                "synced": self.synced,
                "skipped": self.skipped,
                "failed": self.failed,
                "not_found_in_smax": self.not_found,
                "already_synced": self.already_synced,
                "no_ip": self.no_ip,
            },
            "not_found_in_smax": self.not_found_report,
            "no_ip_servers": self.no_ip_report,
            "results": [
                {
                    "server_name": r.server_name,
                    "source": r.source,
                    "ip_address": r.ip_address,
                    "status": r.status.value,
                    "message": r.message,
                    "ci_id": r.ci_id,
                }
                for r in self.results
            ],
        }

    def print_summary(self) -> None:
        """Print a human-readable summary"""
        print("\n" + "=" * 60)
        print("AD Member Server IP Sync Report")
        print("=" * 60)
        print(f"Start Time: {self.start_time}")
        print(f"End Time: {self.end_time}")
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            print(f"Duration: {duration:.2f} seconds")
        if self.sources_processed:
            print(f"Sources: {', '.join(self.sources_processed)}")
        print("-" * 60)
        print("Summary:")
        print(f"  Total servers processed: {self.total_servers}")
        print(f"  Successfully synced: {self.synced}")
        print(f"  Already synced (no change): {self.already_synced}")
        print(f"  Skipped (dry run): {self.skipped}")
        print(f"  Not found in SMAX: {self.not_found}")
        print(f"  No IP resolved: {self.no_ip}")
        print(f"  Failed: {self.failed}")
        print("=" * 60)

        if self.not_found_report:
            print("\nSERVERS NOT FOUND IN SMAX:")
            print("-" * 60)
            for entry in self.not_found_report:
                print(f"  [{entry['source']}] {entry['server_name']} "
                      f"(IP: {entry['ip_address'] or 'N/A'})")
            print("-" * 60)

        if self.no_ip_report:
            print("\nSERVERS WITH NO IP RESOLVED:")
            print("-" * 60)
            for entry in self.no_ip_report:
                print(f"  [{entry['source']}] {entry['server_name']}")
            print("-" * 60)
        print("")


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
        Search for computer objects under the MemberServers OU,
        resolve their IP addresses via DNS.
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
            "dNSHostName",
            "distinguishedName",
            "whenChanged",
            "whenCreated",
        ]

        servers = []
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
                    servers.append(server)
            except Exception as e:
                logger.warning(f"Failed to parse server entry: {e}")
                continue

        logger.info(f"Found {len(servers)} server(s)")
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

        ip_address = resolve_ip(dns_hostname) if dns_hostname else None

        if not ip_address:
            logger.warning(f"Could not resolve IP for: {name} (dNSHostName: {dns_hostname})")

        return ServerInfo(
            name=name,
            ip_address=ip_address or "",
            dns_hostname=dns_hostname or "",
        )

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# CSV READER
# =============================================================================


def read_servers_from_csv(
    path: str,
    name_patterns: Optional[List[str]] = None,
) -> List[ServerInfo]:
    """
    Read servers from CSV file (ad_server_export.py output).
    Optionally filter by name patterns using fnmatch.
    """
    servers = []

    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                name = row.get("Name", "").strip()
                if not name:
                    continue

                # Apply name pattern filter
                if name_patterns:
                    matched = any(
                        fnmatch.fnmatch(name.upper(), p.upper())
                        for p in name_patterns
                    )
                    if not matched:
                        continue

                servers.append(ServerInfo(
                    name=name,
                    ip_address=row.get("IPAddress", "").strip(),
                    dns_hostname=row.get("DNSHostName", "").strip(),
                ))

        logger.info(f"Read {len(servers)} servers from CSV: {path}")
    except FileNotFoundError:
        logger.warning(f"CSV file not found: {path}")
    except Exception as e:
        logger.error(f"Failed to read CSV file {path}: {e}")

    return servers


# =============================================================================
# SMAX CLIENT
# =============================================================================


class SMAXClient:
    """Client for interacting with SMAX REST API"""

    def __init__(self, config: SMAXConfig):
        self.config = config
        self.session = None
        self.base_url = f"{config.base_url}/rest/{config.tenant_id}"
        self._token = None
        self._token_expiry = 0

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic"""
        session = requests.Session()
        session.verify = False

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def connect(self) -> None:
        """Authenticate with SMAX and obtain access token"""
        self.session = self._create_session()

        if self.config.api_token:
            self._token = self.config.api_token
            self.session.headers.update({
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            })
            logger.info("Using API token authentication")
        else:
            self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate using username and password"""
        auth_url = (
            f"{self.config.base_url}/auth/authentication-endpoint"
            f"/authenticate/token?TENANTID={self.config.tenant_id}"
        )

        payload = {"Login": self.config.username, "Password": self.config.password}
        headers = {"Content-Type": "application/json"}

        response = self.session.post(auth_url, json=payload, headers=headers)
        response.raise_for_status()

        self._token = response.text.strip().strip('"')

        if not self._token:
            raise Exception("Failed to obtain authentication token from SMAX")

        self.session.headers.update({
            "Cookie": f"LWSSO_COOKIE_KEY={self._token}; TENANTID={self.config.tenant_id}",
            "Content-Type": "application/json",
        })

        self._token_expiry = time.time() + 3600
        logger.info("Successfully authenticated with SMAX")

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid authentication token"""
        if not self.config.api_token and time.time() >= self._token_expiry - 300:
            logger.info("Token expiring soon, re-authenticating...")
            self._authenticate()

    def _escape_query(self, value: str) -> str:
        """Escape special characters in query values"""
        return value.replace("'", "''")

    def get_ci_by_name(
        self,
        name: str,
        ci_type: str = "Server",
        target_field: str = "AgBiosAdi",
    ) -> Optional[CIRecord]:
        """Search for a CI by its display label (name)"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": f"Id,DisplayLabel,PrimaryIP,DnsName,{target_field}",
            "filter": f"(DisplayLabel = '{self._escape_query(name)}')",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            entities = data.get("entities", [])

            if entities:
                entity = entities[0]
                props = entity.get("properties", {})

                return CIRecord(
                    id=entity.get("entity_type", "") + "/" + str(props.get("Id")),
                    display_label=props.get("DisplayLabel", ""),
                    ci_type=ci_type,
                    target_field_value=props.get(target_field),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def get_ci_by_ip(
        self,
        ip_address: str,
        ci_type: str = "Server",
        target_field: str = "AgBiosAdi",
    ) -> Optional[CIRecord]:
        """Search for a CI by its IP address"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": f"Id,DisplayLabel,PrimaryIP,DnsName,{target_field}",
            "filter": f"(PrimaryIP = '{self._escape_query(ip_address)}')",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            entities = data.get("entities", [])

            if entities:
                entity = entities[0]
                props = entity.get("properties", {})

                return CIRecord(
                    id=entity.get("entity_type", "") + "/" + str(props.get("Id")),
                    display_label=props.get("DisplayLabel", ""),
                    ci_type=ci_type,
                    target_field_value=props.get(target_field),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def search_cis(
        self,
        ci_type: str = "Server",
        filter_query: Optional[str] = None,
        layout: str = "Id,DisplayLabel,PrimaryIP,DnsName",
        skip: int = 0,
        size: int = 100,
    ) -> List[CIRecord]:
        """Search for CIs with optional filtering"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {"layout": layout, "skip": skip, "size": size}

        if filter_query:
            params["filter"] = filter_query

        response = self.session.get(url, params=params)

        if not response.ok:
            logger.error(f"CI search failed: {response.status_code}")
            return []

        data = response.json()
        entities = data.get("entities", [])

        cis = []
        for entity in entities:
            props = entity.get("properties", {})
            cis.append(
                CIRecord(
                    id=entity.get("entity_type", "") + "/" + str(props.get("Id")),
                    display_label=props.get("DisplayLabel", ""),
                    ci_type=ci_type,
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )
            )

        return cis

    def get_all_cis(
        self,
        ci_type: str = "Server",
        target_field: str = "AgBiosAdi",
    ) -> List[CIRecord]:
        """Get all CIs of a specific type (handles pagination)"""
        layout = f"Id,DisplayLabel,PrimaryIP,DnsName,{target_field}"
        all_cis = []
        skip = 0
        size = 100

        while True:
            batch = self.search_cis(ci_type=ci_type, layout=layout, skip=skip, size=size)
            if not batch:
                break

            # Populate target_field_value from properties
            for ci in batch:
                ci.target_field_value = ci.properties.get(target_field)

            all_cis.extend(batch)

            if len(batch) < size:
                break

            skip += size

            if skip > 50000:
                logger.warning("Reached 50,000 CIs limit, stopping pagination")
                break

            if skip % 1000 == 0:
                logger.info(f"Loaded {skip} CIs so far...")

        logger.info(f"Retrieved {len(all_cis)} CIs of type {ci_type}")
        return all_cis

    def update_ci_field(
        self,
        ci_id: str,
        value: str,
        field_name: str = "AgBiosAdi",
    ) -> bool:
        """Update a field on a CI using bulk update endpoint"""
        self._ensure_authenticated()

        parts = ci_id.split("/")
        if len(parts) != 2:
            logger.error(f"Invalid CI ID format: {ci_id}")
            return False

        ci_type, record_id = parts

        url = f"{self.base_url}/ems/bulk"
        payload = {
            "entities": [
                {
                    "entity_type": ci_type,
                    "properties": {
                        "Id": record_id,
                        field_name: value,
                    },
                }
            ],
            "operation": "UPDATE",
        }

        logger.debug(f"Updating CI via bulk endpoint: {url}")
        response = self.session.post(url, json=payload)

        if response.ok:
            data = response.json()
            results = data.get("entity_result_list", [])
            if results and results[0].get("completion_status") == "OK":
                logger.info(f"Successfully updated {field_name} for CI {ci_id}")
                return True
            else:
                logger.error(f"Bulk update returned unexpected result: {data}")
                return False

        logger.error(
            f"Failed to update CI {ci_id}: {response.status_code} - {response.text[:300]}"
        )
        return False

    def disconnect(self) -> None:
        """Close the session"""
        if self.session:
            self.session.close()
            logger.info("Disconnected from SMAX")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# SMAX SERVICE (CACHING LAYER)
# =============================================================================


class SMAXService:
    """High-level service for SMAX operations with caching"""

    def __init__(self, config: SMAXConfig):
        self.client = SMAXClient(config)
        self._ci_cache: Dict[str, CIRecord] = {}

    def connect(self) -> None:
        self.client.connect()

    def disconnect(self) -> None:
        self.client.disconnect()

    def find_ci_for_server(
        self,
        name: str,
        ip: Optional[str] = None,
        ci_type: str = "Server",
        target_field: str = "AgBiosAdi",
    ) -> Optional[CIRecord]:
        """Find a CI that matches a server by name, fallback by IP"""
        # Check cache by display_label
        cache_key = name.lower()
        if cache_key in self._ci_cache:
            return self._ci_cache[cache_key]

        # Check cache by IP
        if ip:
            ip_key = ip.lower()
            if ip_key in self._ci_cache:
                return self._ci_cache[ip_key]

        # Search SMAX by name
        ci = self.client.get_ci_by_name(name, ci_type, target_field)

        # Fallback: search by IP
        if not ci and ip:
            ci = self.client.get_ci_by_ip(ip, ci_type, target_field)

        if ci:
            self._ci_cache[cache_key] = ci
            if ci.primary_ip:
                self._ci_cache[ci.primary_ip.lower()] = ci

        return ci

    def load_all_cis(
        self,
        ci_type: str = "Server",
        target_field: str = "AgBiosAdi",
    ) -> None:
        """Pre-load all CIs into cache for faster lookups"""
        cis = self.client.get_all_cis(ci_type, target_field)

        for ci in cis:
            if ci.display_label:
                self._ci_cache[ci.display_label.lower()] = ci
            if ci.primary_ip:
                self._ci_cache[ci.primary_ip.lower()] = ci

        logger.info(f"Loaded {len(cis)} CIs into cache")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# SERVER IP SYNC SERVICE
# =============================================================================


class ServerIPSyncService:
    """Service to sync AD member server IPs to SMAX CIs"""

    def __init__(self, config: AppConfig):
        self.config = config
        self.ad_client = ADClient(config.active_directory)
        self.smax_service = SMAXService(config.smax)
        self.sync_config = config.sync

    def connect(self) -> None:
        """Connect to AD and SMAX, pre-load CI cache"""
        logger.info("Connecting to AD...")
        self.ad_client.connect()

        logger.info("Connecting to SMAX...")
        self.smax_service.connect()

        logger.info("Loading CIs from SMAX...")
        self.smax_service.load_all_cis(
            ci_type=self.sync_config.smax_ci_type,
            target_field=self.sync_config.smax_target_field,
        )

    def disconnect(self) -> None:
        """Disconnect from all services"""
        self.ad_client.disconnect()
        self.smax_service.disconnect()

    def _load_csv_servers(self) -> List[Tuple[ServerInfo, str]]:
        """Load servers from CSV, tag each with source 'csv'."""
        servers = read_servers_from_csv(
            self.sync_config.csv_input_path,
            name_patterns=self.sync_config.name_patterns if self.sync_config.name_patterns else None,
        )
        return [(s, "csv") for s in servers]

    def _load_ad_servers(
        self,
        modified_after: Optional[datetime] = None,
    ) -> List[Tuple[ServerInfo, str]]:
        """Load servers from live AD query with DNS resolution, tag each with source 'ad_live'."""
        servers = self.ad_client.search_servers(
            name_filter=self.sync_config.name_patterns if self.sync_config.name_patterns else None,
            modified_after=modified_after,
        )
        return [(s, "ad_live") for s in servers]

    def sync_server(
        self,
        server: ServerInfo,
        source: str,
    ) -> SyncResult:
        """
        Sync a single server's IP to the target SMAX field.

        1. Check if server has a resolved IP
        2. Find CI by name, fallback by IP
        3. If not found -> NOT_FOUND_IN_SMAX
        4. Compare current field value with new IP
        5. If already matches -> ALREADY_SYNCED
        6. If dry_run -> SKIPPED
        7. Else -> update and return SUCCESS or FAILED
        """
        if not server.ip_address:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address="",
                status=SyncStatus.NO_IP,
                message=f"No IP resolved for server '{server.name}'",
            )

        ci = self.smax_service.find_ci_for_server(
            name=server.name,
            ip=server.ip_address,
            ci_type=self.sync_config.smax_ci_type,
            target_field=self.sync_config.smax_target_field,
        )

        if not ci:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address=server.ip_address,
                status=SyncStatus.NOT_FOUND_IN_SMAX,
                message=f"No CI found in SMAX matching '{server.name}'",
            )

        # Check current value
        current_value = str(ci.target_field_value) if ci.target_field_value else None
        if current_value == server.ip_address:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address=server.ip_address,
                status=SyncStatus.ALREADY_SYNCED,
                message=f"Field already set to '{server.ip_address}'",
                ci_id=ci.id,
            )

        if self.sync_config.dry_run:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address=server.ip_address,
                status=SyncStatus.SKIPPED,
                message=f"[DRY RUN] Would update from "
                        f"'{current_value}' to '{server.ip_address}'",
                ci_id=ci.id,
            )

        success = self.smax_service.client.update_ci_field(
            ci_id=ci.id,
            value=server.ip_address,
            field_name=self.sync_config.smax_target_field,
        )

        if success:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address=server.ip_address,
                status=SyncStatus.SUCCESS,
                message=f"Updated from '{current_value}' to '{server.ip_address}'",
                ci_id=ci.id,
            )
        else:
            return SyncResult(
                server_name=server.name,
                source=source,
                ip_address=server.ip_address,
                status=SyncStatus.FAILED,
                message="Failed to update field in SMAX",
                ci_id=ci.id,
            )

    def sync_all(
        self,
        full: bool = False,
        csv_only: bool = False,
        ad_only: bool = False,
        name_overrides: Optional[List[str]] = None,
    ) -> SyncReport:
        """
        Run the full sync pipeline.

        1. Load CSV servers (from Network A export)
        2. Load AD live servers with DNS resolution (Network B)
        3. Merge & deduplicate (live AD takes precedence)
        4. Apply name pattern filters
        5. Process each server
        6. Generate report
        7. Save state
        """
        report = SyncReport(start_time=datetime.now())

        # Override name patterns if provided via CLI
        if name_overrides:
            self.sync_config.name_patterns = name_overrides

        # Determine modified_after for live AD query
        modified_after = None
        if not full:
            state = load_state(self.sync_config.state_file_path)
            last_run = state.get("last_run")
            if last_run:
                modified_after = datetime.fromisoformat(last_run)
                logger.info(f"Incremental mode: AD servers modified after {last_run}")
            else:
                logger.info("No previous state found - full AD scan")

        # Load from CSV source
        csv_servers: List[Tuple[ServerInfo, str]] = []
        if not ad_only:
            logger.info(f"Loading servers from CSV: {self.sync_config.csv_input_path}")
            csv_servers = self._load_csv_servers()
            report.sources_processed.append(f"csv:{self.sync_config.csv_input_path}")
            logger.info(f"Loaded {len(csv_servers)} servers from CSV")

        # Load from live AD source
        ad_servers: List[Tuple[ServerInfo, str]] = []
        if not csv_only:
            logger.info("Querying live AD for servers and resolving IPs...")
            ad_servers = self._load_ad_servers(modified_after=modified_after)
            report.sources_processed.append("ad_live")
            logger.info(f"Loaded {len(ad_servers)} servers from live AD")

        # Merge: build dict keyed by lowercase name, AD live overrides CSV
        merged: Dict[str, Tuple[ServerInfo, str]] = {}

        for server, source in csv_servers:
            key = server.name.lower()
            merged[key] = (server, source)

        for server, source in ad_servers:
            key = server.name.lower()
            merged[key] = (server, source)  # AD overrides CSV

        # Apply name filters
        all_items = list(merged.values())
        if name_overrides:
            all_items = [
                (s, src) for s, src in all_items
                if any(fnmatch.fnmatch(s.name.upper(), p.upper()) for p in name_overrides)
            ]

        report.total_servers = len(all_items)
        logger.info(f"Processing {len(all_items)} servers from {len(report.sources_processed)} source(s)...")

        # Process each server
        for i, (server, source) in enumerate(all_items, 1):
            if i % self.sync_config.batch_size == 0:
                logger.info(f"Progress: {i}/{len(all_items)} servers processed")

            try:
                result = self.sync_server(server, source)
                report.add_result(result)

                if result.status == SyncStatus.SUCCESS:
                    logger.info(f"[SYNCED] [{source}] {server.name}: {result.message}")
                elif result.status == SyncStatus.FAILED:
                    logger.warning(f"[FAILED] [{source}] {server.name}: {result.message}")
                elif result.status == SyncStatus.NOT_FOUND_IN_SMAX:
                    logger.debug(f"[NOT FOUND] [{source}] {server.name}: {result.message}")
                elif result.status == SyncStatus.NO_IP:
                    logger.warning(f"[NO IP] [{source}] {server.name}: {result.message}")
                else:
                    logger.debug(f"[{result.status.value.upper()}] [{source}] {server.name}: {result.message}")

            except Exception as e:
                logger.error(f"Error processing {server.name}: {e}")
                report.add_result(SyncResult(
                    server_name=server.name,
                    source=source,
                    ip_address=server.ip_address,
                    status=SyncStatus.FAILED,
                    message=str(e),
                ))

        report.finalize()

        # Save state with current timestamp
        save_state(self.sync_config.state_file_path, report.start_time)

        return report

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


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
    smax_data = data.get("smax", {})
    sync_data = data.get("sync", {})

    return AppConfig(
        active_directory=ADConfig(
            server=ad_data.get("server", ""),
            domain=ad_data.get("domain", ""),
            username=ad_data.get("username", ""),
            password=ad_data.get("password", ""),
            base_dn=ad_data.get("base_dn", ""),
            use_ssl=ad_data.get("use_ssl", True),
        ),
        smax=SMAXConfig(
            base_url=smax_data.get("base_url", ""),
            tenant_id=smax_data.get("tenant_id", ""),
            username=smax_data.get("username", ""),
            password=smax_data.get("password", ""),
            api_token=smax_data.get("api_token"),
        ),
        sync=SyncConfig(
            csv_input_path=sync_data.get("csv_input_path", "ad_servers.csv"),
            smax_ci_type=sync_data.get("smax_ci_type", "Server"),
            smax_matching_field=sync_data.get("smax_matching_field", "DisplayLabel"),
            smax_alt_matching_field=sync_data.get("smax_alt_matching_field", "PrimaryIP"),
            smax_target_field=sync_data.get("smax_target_field", "AgBiosAdi"),
            name_patterns=sync_data.get("name_patterns", []),
            state_file_path=sync_data.get("state_file_path", ".server_ip_sync_state.json"),
            dry_run=sync_data.get("dry_run", False),
            batch_size=sync_data.get("batch_size", 50),
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
        "smax": {
            "base_url": "https://smax.example.com",
            "tenant_id": "your-tenant-id",
            "username": "admin",
            "password": "your-password",
            "api_token": None,
        },
        "sync": {
            "csv_input_path": "ad_servers.csv",
            "smax_ci_type": "Server",
            "smax_matching_field": "DisplayLabel",
            "smax_alt_matching_field": "PrimaryIP",
            "smax_target_field": "AgBiosAdi",
            "name_patterns": [],
            "state_file_path": ".server_ip_sync_state.json",
            "dry_run": False,
            "batch_size": 50,
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connections(config: AppConfig) -> None:
    """Test AD and SMAX connections"""
    print(f"\nTesting AD connection to {config.active_directory.server}...")
    print(f"  Search base: {config.active_directory.base_dn}")
    try:
        with ADClient(config.active_directory) as client:
            servers = client.search_servers(name_filter=["*"])
            resolved = sum(1 for s in servers if s.ip_address)
            print(f"  AD connection successful - Found {len(servers)} server(s)")
            print(f"  IP resolved: {resolved}, IP failed: {len(servers) - resolved}")
    except Exception as e:
        print(f"  AD connection failed: {e}")

    print(f"\nTesting SMAX connection to {config.smax.base_url}...")
    try:
        with SMAXService(config.smax) as smax:
            cis = smax.client.search_cis(ci_type=config.sync.smax_ci_type, size=1)
            print(f"  SMAX connection successful - CI type '{config.sync.smax_ci_type}' accessible")
    except Exception as e:
        print(f"  SMAX connection failed: {e}")


def display_report(report_path: str) -> None:
    """Read and display a previous sync report from JSON file"""
    try:
        with open(report_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read report: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("AD Member Server IP Sync Report")
    print("=" * 60)
    print(f"Start Time: {data.get('start_time')}")
    print(f"End Time: {data.get('end_time')}")
    if data.get("duration_seconds"):
        print(f"Duration: {data['duration_seconds']:.2f} seconds")
    if data.get("sources_processed"):
        print(f"Sources: {', '.join(data['sources_processed'])}")

    summary = data.get("summary", {})
    print("-" * 60)
    print("Summary:")
    print(f"  Total servers: {summary.get('total_servers', 0)}")
    print(f"  Synced: {summary.get('synced', 0)}")
    print(f"  Already synced: {summary.get('already_synced', 0)}")
    print(f"  Skipped (dry run): {summary.get('skipped', 0)}")
    print(f"  Not found in SMAX: {summary.get('not_found_in_smax', 0)}")
    print(f"  No IP resolved: {summary.get('no_ip', 0)}")
    print(f"  Failed: {summary.get('failed', 0)}")
    print("=" * 60)

    not_found = data.get("not_found_in_smax", [])
    if not_found:
        print("\nSERVERS NOT FOUND IN SMAX:")
        print("-" * 60)
        for entry in not_found:
            print(f"  [{entry.get('source', '?')}] {entry.get('server_name', '?')} "
                  f"(IP: {entry.get('ip_address', 'N/A')})")
        print("-" * 60)

    no_ip = data.get("no_ip_servers", [])
    if no_ip:
        print("\nSERVERS WITH NO IP RESOLVED:")
        print("-" * 60)
        for entry in no_ip:
            print(f"  [{entry.get('source', '?')}] {entry.get('server_name', '?')}")
        print("-" * 60)

    print("")


def run_sync_command(config: AppConfig, args) -> None:
    """Run the sync command"""
    with ServerIPSyncService(config) as service:
        report = service.sync_all(
            full=args.full,
            csv_only=args.csv_only,
            ad_only=args.ad_only,
            name_overrides=args.names if args.names else None,
        )

    report.print_summary()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"JSON report saved to {args.output}")

    if report.failed > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AD Member Server IP Sync to SMAX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync from both CSV and live AD
  python ad_server_ip_sync.py sync --config config.json

  # Dry run (no changes)
  python ad_server_ip_sync.py sync --config config.json --dry-run

  # Full sync (ignore state, process all)
  python ad_server_ip_sync.py sync --config config.json --full

  # CSV source only (Network A data)
  python ad_server_ip_sync.py sync --config config.json --csv-only

  # Live AD source only (Network B)
  python ad_server_ip_sync.py sync --config config.json --ad-only

  # Ad-hoc name filtering
  python ad_server_ip_sync.py sync --config config.json --names "SRV*" "WS-*"

  # Save report to JSON
  python ad_server_ip_sync.py sync --config config.json --output report.json

  # Test connections
  python ad_server_ip_sync.py test --config config.json

  # View a previous report
  python ad_server_ip_sync.py report --input report.json

  # Generate config template
  python ad_server_ip_sync.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync server IPs to SMAX")
    sync_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    sync_parser.add_argument("--dry-run", "-n", action="store_true", help="Dry run (no changes)")
    sync_parser.add_argument("--full", action="store_true", help="Full sync (ignore state)")
    sync_parser.add_argument("--csv-only", action="store_true", help="Only process CSV source")
    sync_parser.add_argument("--ad-only", action="store_true", help="Only process live AD source")
    sync_parser.add_argument("--names", nargs="+", help="Ad-hoc name patterns (overrides config)")
    sync_parser.add_argument("--output", "-o", help="Output JSON report file")
    sync_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    sync_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test AD and SMAX connections")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Generate config command
    template_parser = subparsers.add_parser("generate-config", help="Generate a config template")
    template_parser.add_argument("--output", "-o", default="config.json", help="Output file path")

    # Report command
    report_parser = subparsers.add_parser("report", help="Display a previous sync report")
    report_parser.add_argument("--input", "-i", required=True, help="Path to JSON report file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-config":
        generate_config_template(args.output)
        return

    if args.command == "report":
        display_report(args.input)
        return

    verbose = getattr(args, "verbose", False)
    log_file = getattr(args, "log_file", None)
    setup_logging(verbose, log_file)

    try:
        config = load_config_from_file(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    if args.command == "sync" and args.dry_run:
        config.sync.dry_run = True
        logger.info("DRY RUN MODE: No actual changes will be made")

    if args.command == "test":
        test_connections(config)
    elif args.command == "sync":
        run_sync_command(config, args)


if __name__ == "__main__":
    main()
