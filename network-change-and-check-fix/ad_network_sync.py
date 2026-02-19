#!/usr/bin/env python3
"""
AD Network Type Sync to SMAX
Reads AD computers from CSV (ad_export.py output) AND live AD query,
assigns configurable NetworkType labels per source, and updates the
NetworkType field on matching SMAX CIs.

Usage:
    python ad_network_sync.py sync --config config.json
    python ad_network_sync.py sync --config config.json --dry-run
    python ad_network_sync.py sync --config config.json --csv-only
    python ad_network_sync.py sync --config config.json --ad-only --full
    python ad_network_sync.py sync --config config.json --names "SRV*" "WS-*"
    python ad_network_sync.py test --config config.json
    python ad_network_sync.py generate-config --output config.json
    python ad_network_sync.py report --input sync_report.json
"""

import argparse
import csv
import fnmatch
import json
import logging
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
    csv_input_path: str = "ad_computers.csv"
    csv_network_type: str = "Network1"
    ad_network_type: str = "Network2"
    smax_ci_type: str = "Device"
    smax_matching_field: str = "DisplayLabel"
    smax_alt_matching_field: str = "PrimaryIP"
    smax_network_type_field: str = "NetworkType"
    name_patterns: List[str] = field(default_factory=list)
    state_file_path: str = ".sync_state.json"
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


@dataclass
class CIRecord:
    """Represents a Configuration Item in SMAX"""
    id: str
    display_label: str
    ci_type: str
    network_type: Optional[str] = None
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
    NO_CHANGE = "no_change"


@dataclass
class SyncResult:
    """Result of syncing a single computer"""
    computer_name: str
    source: str  # "csv" or "ad_live"
    network_type: str
    status: SyncStatus
    message: str
    ci_id: Optional[str] = None


@dataclass
class SyncReport:
    """Aggregated sync report"""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_computers: int = 0
    synced: int = 0
    skipped: int = 0
    failed: int = 0
    not_found: int = 0
    already_synced: int = 0
    no_change: int = 0
    results: List[SyncResult] = field(default_factory=list)
    not_found_report: List[Dict[str, str]] = field(default_factory=list)
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
            SyncStatus.NO_CHANGE: "no_change",
        }
        attr = status_map.get(result.status)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

        if result.status == SyncStatus.NOT_FOUND_IN_SMAX:
            self.not_found_report.append({
                "computer_name": result.computer_name,
                "source": result.source,
                "network_type": result.network_type,
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
                "total_computers": self.total_computers,
                "synced": self.synced,
                "skipped": self.skipped,
                "failed": self.failed,
                "not_found_in_smax": self.not_found,
                "already_synced": self.already_synced,
                "no_change": self.no_change,
            },
            "not_found_in_smax": self.not_found_report,
            "results": [
                {
                    "computer_name": r.computer_name,
                    "source": r.source,
                    "network_type": r.network_type,
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
        print("AD Network Type Sync Report")
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
        print(f"  Total computers processed: {self.total_computers}")
        print(f"  Successfully synced: {self.synced}")
        print(f"  Already synced (no change): {self.already_synced}")
        print(f"  Skipped (dry run): {self.skipped}")
        print(f"  Not found in SMAX: {self.not_found}")
        print(f"  No change needed: {self.no_change}")
        print(f"  Failed: {self.failed}")
        print("=" * 60)

        if self.not_found_report:
            print("\nCOMPUTERS NOT FOUND IN SMAX:")
            print("-" * 60)
            for entry in self.not_found_report:
                print(f"  [{entry['source']}] {entry['computer_name']} "
                      f"(would assign: {entry['network_type']})")
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
        filter_parts = ["(objectClass=computer)"]

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

        name = attrs.get("cn", "")
        if isinstance(name, list):
            name = name[0] if name else ""

        dn = attrs.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""

        dns_hostname = attrs.get("dNSHostName", None)
        if isinstance(dns_hostname, list):
            dns_hostname = dns_hostname[0] if dns_hostname else None

        os_name = attrs.get("operatingSystem", None)
        if isinstance(os_name, list):
            os_name = os_name[0] if os_name else None

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

        description = attrs.get("description", None)
        if isinstance(description, list):
            description = description[0] if description else None

        uac = attrs.get("userAccountControl", 0)
        if isinstance(uac, list):
            uac = uac[0] if uac else 0
        try:
            uac = int(uac)
        except (ValueError, TypeError):
            uac = 0
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
# CSV READER
# =============================================================================


def read_computers_from_csv(
    path: str,
    name_patterns: Optional[List[str]] = None,
) -> List[ADComputer]:
    """
    Read AD computers from CSV file (ad_export.py output).
    Optionally filter by name patterns using fnmatch.
    """
    computers = []

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

                ip_str = row.get("IPAddresses", "")
                ip_addresses = [ip.strip() for ip in ip_str.split(";") if ip.strip()]

                enabled_str = row.get("Enabled", "True").strip()
                enabled = enabled_str.lower() in ("true", "1", "yes")

                computers.append(ADComputer(
                    name=name,
                    distinguished_name=row.get("DistinguishedName", ""),
                    dns_hostname=row.get("DNSHostName") or None,
                    operating_system=row.get("OperatingSystem") or None,
                    when_changed=row.get("WhenChanged") or None,
                    when_created=row.get("WhenCreated") or None,
                    ip_addresses=ip_addresses,
                    description=row.get("Description") or None,
                    enabled=enabled,
                ))

        logger.info(f"Read {len(computers)} computers from CSV: {path}")
    except FileNotFoundError:
        logger.warning(f"CSV file not found: {path}")
    except Exception as e:
        logger.error(f"Failed to read CSV file {path}: {e}")

    return computers


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
        ci_type: str = "Device",
        network_type_field: str = "NetworkType",
    ) -> Optional[CIRecord]:
        """Search for a CI by its display label (name)"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": f"Id,DisplayLabel,PrimaryIP,DnsName,{network_type_field}",
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
                    network_type=props.get(network_type_field),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def get_ci_by_ip(
        self,
        ip_address: str,
        ci_type: str = "Device",
        network_type_field: str = "NetworkType",
    ) -> Optional[CIRecord]:
        """Search for a CI by its IP address"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": f"Id,DisplayLabel,PrimaryIP,DnsName,{network_type_field}",
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
                    network_type=props.get(network_type_field),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def search_cis(
        self,
        ci_type: str = "Device",
        filter_query: Optional[str] = None,
        layout: str = "Id,DisplayLabel,PrimaryIP,DnsName,NetworkType",
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
                    network_type=props.get("NetworkType"),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )
            )

        return cis

    def get_all_cis(
        self,
        ci_type: str = "Device",
        network_type_field: str = "NetworkType",
    ) -> List[CIRecord]:
        """Get all CIs of a specific type (handles pagination)"""
        layout = f"Id,DisplayLabel,PrimaryIP,DnsName,{network_type_field}"
        all_cis = []
        skip = 0
        size = 100

        while True:
            batch = self.search_cis(ci_type=ci_type, layout=layout, skip=skip, size=size)
            if not batch:
                break

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

    def update_ci_network_type(
        self,
        ci_id: str,
        network_type: str,
        field_name: str = "NetworkType",
    ) -> bool:
        """Update the NetworkType field on a CI using bulk update endpoint"""
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
                        field_name: network_type,
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

    def find_ci_for_computer(
        self,
        name: str,
        ip: Optional[str] = None,
        ci_type: str = "Device",
        network_type_field: str = "NetworkType",
    ) -> Optional[CIRecord]:
        """Find a CI that matches a computer by name, fallback by IP"""
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
        ci = self.client.get_ci_by_name(name, ci_type, network_type_field)

        # Fallback: search by IP
        if not ci and ip:
            ci = self.client.get_ci_by_ip(ip, ci_type, network_type_field)

        if ci:
            self._ci_cache[cache_key] = ci
            if ci.primary_ip:
                self._ci_cache[ci.primary_ip.lower()] = ci

        return ci

    def load_all_cis(
        self,
        ci_type: str = "Device",
        network_type_field: str = "NetworkType",
    ) -> None:
        """Pre-load all CIs into cache for faster lookups"""
        cis = self.client.get_all_cis(ci_type, network_type_field)

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
# NETWORK SYNC SERVICE
# =============================================================================


class NetworkSyncService:
    """Service to sync AD computer NetworkType values to SMAX CIs"""

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
            network_type_field=self.sync_config.smax_network_type_field,
        )

    def disconnect(self) -> None:
        """Disconnect from all services"""
        self.ad_client.disconnect()
        self.smax_service.disconnect()

    def _load_csv_computers(self) -> List[Tuple[ADComputer, str]]:
        """Load computers from CSV, tag each with csv_network_type."""
        computers = read_computers_from_csv(
            self.sync_config.csv_input_path,
            name_patterns=self.sync_config.name_patterns if self.sync_config.name_patterns else None,
        )
        return [(c, self.sync_config.csv_network_type) for c in computers]

    def _load_ad_computers(
        self,
        modified_after: Optional[datetime] = None,
    ) -> List[Tuple[ADComputer, str]]:
        """Load computers from live AD query, tag each with ad_network_type."""
        computers = self.ad_client.search_computers(
            name_filter=self.sync_config.name_patterns if self.sync_config.name_patterns else None,
            modified_after=modified_after,
        )
        return [(c, self.sync_config.ad_network_type) for c in computers]

    @staticmethod
    def _apply_name_filters(
        computers: List[Tuple[ADComputer, str]],
        patterns: List[str],
    ) -> List[Tuple[ADComputer, str]]:
        """Filter computer list by name patterns using fnmatch."""
        if not patterns:
            return computers
        return [
            (c, nt) for c, nt in computers
            if any(fnmatch.fnmatch(c.name.upper(), p.upper()) for p in patterns)
        ]

    def sync_computer(
        self,
        computer: ADComputer,
        network_type: str,
        source: str,
    ) -> SyncResult:
        """
        Sync a single computer's NetworkType to SMAX.

        1. Find CI by name, fallback by IP
        2. If not found -> NOT_FOUND_IN_SMAX
        3. If found, check current NetworkType
        4. If already matches -> ALREADY_SYNCED
        5. If dry_run -> SKIPPED
        6. Else -> update and return SUCCESS or FAILED
        """
        # Get first IP if available
        ip = computer.ip_addresses[0] if computer.ip_addresses else None

        ci = self.smax_service.find_ci_for_computer(
            name=computer.name,
            ip=ip,
            ci_type=self.sync_config.smax_ci_type,
            network_type_field=self.sync_config.smax_network_type_field,
        )

        if not ci:
            return SyncResult(
                computer_name=computer.name,
                source=source,
                network_type=network_type,
                status=SyncStatus.NOT_FOUND_IN_SMAX,
                message=f"No CI found in SMAX matching '{computer.name}'"
                        + (f" or IP '{ip}'" if ip else ""),
            )

        # Check current value
        current_value = str(ci.network_type) if ci.network_type else None
        if current_value == network_type:
            return SyncResult(
                computer_name=computer.name,
                source=source,
                network_type=network_type,
                status=SyncStatus.ALREADY_SYNCED,
                message=f"NetworkType already set to '{network_type}'",
                ci_id=ci.id,
            )

        if self.sync_config.dry_run:
            return SyncResult(
                computer_name=computer.name,
                source=source,
                network_type=network_type,
                status=SyncStatus.SKIPPED,
                message=f"[DRY RUN] Would update NetworkType from "
                        f"'{current_value}' to '{network_type}'",
                ci_id=ci.id,
            )

        success = self.smax_service.client.update_ci_network_type(
            ci_id=ci.id,
            network_type=network_type,
            field_name=self.sync_config.smax_network_type_field,
        )

        if success:
            return SyncResult(
                computer_name=computer.name,
                source=source,
                network_type=network_type,
                status=SyncStatus.SUCCESS,
                message=f"Updated NetworkType from '{current_value}' to '{network_type}'",
                ci_id=ci.id,
            )
        else:
            return SyncResult(
                computer_name=computer.name,
                source=source,
                network_type=network_type,
                status=SyncStatus.FAILED,
                message="Failed to update NetworkType in SMAX",
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

        1. Load CSV computers (tagged with csv_network_type)
        2. Load AD live computers (tagged with ad_network_type)
        3. Merge & deduplicate (live AD takes precedence)
        4. Apply name pattern filters
        5. Process each computer
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
                logger.info(f"Incremental mode: AD computers modified after {last_run}")
            else:
                logger.info("No previous state found - full AD scan")

        # Load from CSV source
        csv_computers: List[Tuple[ADComputer, str]] = []
        if not ad_only:
            logger.info(f"Loading computers from CSV: {self.sync_config.csv_input_path}")
            csv_computers = self._load_csv_computers()
            report.sources_processed.append(f"csv:{self.sync_config.csv_input_path}")
            logger.info(f"Loaded {len(csv_computers)} computers from CSV")

        # Load from live AD source
        ad_computers: List[Tuple[ADComputer, str]] = []
        if not csv_only:
            logger.info("Querying live AD for computers...")
            ad_computers = self._load_ad_computers(modified_after=modified_after)
            report.sources_processed.append("ad_live")
            logger.info(f"Loaded {len(ad_computers)} computers from live AD")

        # Merge: build dict keyed by lowercase name, AD live overrides CSV
        merged: Dict[str, Tuple[ADComputer, str, str]] = {}

        for computer, net_type in csv_computers:
            key = computer.name.lower()
            merged[key] = (computer, net_type, "csv")

        for computer, net_type in ad_computers:
            key = computer.name.lower()
            merged[key] = (computer, net_type, "ad_live")  # AD overrides CSV

        # Apply name filters (ad-hoc overrides already set above)
        all_items = list(merged.values())
        if name_overrides:
            all_items = [
                (c, nt, src) for c, nt, src in all_items
                if any(fnmatch.fnmatch(c.name.upper(), p.upper()) for p in name_overrides)
            ]

        report.total_computers = len(all_items)
        logger.info(f"Processing {len(all_items)} computers from {len(report.sources_processed)} source(s)...")

        # Process each computer
        for i, (computer, net_type, source) in enumerate(all_items, 1):
            if i % self.sync_config.batch_size == 0:
                logger.info(f"Progress: {i}/{len(all_items)} computers processed")

            try:
                result = self.sync_computer(computer, net_type, source)
                report.add_result(result)

                if result.status == SyncStatus.SUCCESS:
                    logger.info(f"[SYNCED] [{source}] {computer.name}: {result.message}")
                elif result.status == SyncStatus.FAILED:
                    logger.warning(f"[FAILED] [{source}] {computer.name}: {result.message}")
                elif result.status == SyncStatus.NOT_FOUND_IN_SMAX:
                    logger.debug(f"[NOT FOUND] [{source}] {computer.name}: {result.message}")
                else:
                    logger.debug(f"[{result.status.value.upper()}] [{source}] {computer.name}: {result.message}")

            except Exception as e:
                logger.error(f"Error processing {computer.name}: {e}")
                report.add_result(SyncResult(
                    computer_name=computer.name,
                    source=source,
                    network_type=net_type,
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
            csv_input_path=sync_data.get("csv_input_path", "ad_computers.csv"),
            csv_network_type=sync_data.get("csv_network_type", "Network1"),
            ad_network_type=sync_data.get("ad_network_type", "Network2"),
            smax_ci_type=sync_data.get("smax_ci_type", "Device"),
            smax_matching_field=sync_data.get("smax_matching_field", "DisplayLabel"),
            smax_alt_matching_field=sync_data.get("smax_alt_matching_field", "PrimaryIP"),
            smax_network_type_field=sync_data.get("smax_network_type_field", "NetworkType"),
            name_patterns=sync_data.get("name_patterns", []),
            state_file_path=sync_data.get("state_file_path", ".sync_state.json"),
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
            "base_dn": "DC=example,DC=com",
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
            "csv_input_path": "ad_computers.csv",
            "csv_network_type": "Network1",
            "ad_network_type": "Network2",
            "smax_ci_type": "Device",
            "smax_matching_field": "DisplayLabel",
            "smax_alt_matching_field": "PrimaryIP",
            "smax_network_type_field": "NetworkType",
            "name_patterns": [],
            "state_file_path": ".sync_state.json",
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
    try:
        with ADClient(config.active_directory) as client:
            computers = client.search_computers(name_filter=["*"])
            print(f"  AD connection successful - Found {len(computers)} computer(s)")
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
    print("AD Network Type Sync Report")
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
    print(f"  Total computers: {summary.get('total_computers', 0)}")
    print(f"  Synced: {summary.get('synced', 0)}")
    print(f"  Already synced: {summary.get('already_synced', 0)}")
    print(f"  Skipped (dry run): {summary.get('skipped', 0)}")
    print(f"  Not found in SMAX: {summary.get('not_found_in_smax', 0)}")
    print(f"  No change: {summary.get('no_change', 0)}")
    print(f"  Failed: {summary.get('failed', 0)}")
    print("=" * 60)

    not_found = data.get("not_found_in_smax", [])
    if not_found:
        print("\nCOMPUTERS NOT FOUND IN SMAX:")
        print("-" * 60)
        for entry in not_found:
            print(f"  [{entry.get('source', '?')}] {entry.get('computer_name', '?')} "
                  f"(would assign: {entry.get('network_type', '?')})")
        print("-" * 60)

    print("")


def run_sync_command(config: AppConfig, args) -> None:
    """Run the sync command"""
    with NetworkSyncService(config) as service:
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
        description="AD Network Type Sync to SMAX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync from both CSV and live AD
  python ad_network_sync.py sync --config config.json

  # Dry run (no changes)
  python ad_network_sync.py sync --config config.json --dry-run

  # Full sync (ignore state, process all)
  python ad_network_sync.py sync --config config.json --full

  # CSV source only
  python ad_network_sync.py sync --config config.json --csv-only

  # Live AD source only
  python ad_network_sync.py sync --config config.json --ad-only

  # Ad-hoc name filtering
  python ad_network_sync.py sync --config config.json --names "SRV*" "WS-*"

  # Save report to JSON
  python ad_network_sync.py sync --config config.json --output report.json

  # Test connections
  python ad_network_sync.py test --config config.json

  # View a previous report
  python ad_network_sync.py report --input report.json

  # Generate config template
  python ad_network_sync.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync AD computer NetworkType to SMAX")
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
