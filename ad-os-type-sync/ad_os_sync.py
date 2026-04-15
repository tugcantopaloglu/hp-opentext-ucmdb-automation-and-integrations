#!/usr/bin/env python3
"""
AD Server OS Type Sync to SMAX
Reads server OS information from CSV (ad_os_export.py output from Network A) AND
live AD query (Network B), merges both sources (live AD takes precedence),
and updates the OS type field on matching SMAX CIs if empty.

Usage:
    python ad_os_sync.py sync --config config.json
    python ad_os_sync.py sync --config config.json --dry-run
    python ad_os_sync.py sync --config config.json --csv-only
    python ad_os_sync.py sync --config config.json --ad-only --full
    python ad_os_sync.py sync --config config.json --names "SRV*" "WS-*"
    python ad_os_sync.py test --config config.json
    python ad_os_sync.py generate-config --output config.json
    python ad_os_sync.py report --input sync_report.json
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
    csv_input_path: str = "ad_os_servers.csv"
    smax_ci_type: str = "Device"
    smax_ci_subtype: Optional[str] = "Server"
    smax_matching_field: str = "DisplayLabel"
    smax_target_field: str = "OsType"
    name_patterns: List[str] = field(default_factory=list)
    state_file_path: str = ".os_type_sync_state.json"
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
    """Represents a server with OS type information"""
    name: str
    operating_system: str = ""
    os_type: str = ""  # "Windows" or "Unix"
    distinguished_name: str = ""


@dataclass
class CIRecord:
    """Represents a Configuration Item in SMAX"""
    id: str
    display_label: str
    ci_type: str
    target_field_value: Optional[str] = None
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
    ALREADY_SET = "already_set"
    NO_OS_TYPE = "no_os_type"


@dataclass
class SyncResult:
    """Result of syncing a single server"""
    server_name: str
    source: str  # "csv" or "ad_live"
    os_type: str
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
    already_set: int = 0
    no_os_type: int = 0
    results: List[SyncResult] = field(default_factory=list)
    not_found_report: List[Dict[str, str]] = field(default_factory=list)
    no_os_report: List[Dict[str, str]] = field(default_factory=list)
    sources_processed: List[str] = field(default_factory=list)

    def add_result(self, result: SyncResult) -> None:
        """Add a sync result and update counters"""
        self.results.append(result)
        status_map = {
            SyncStatus.SUCCESS: "synced",
            SyncStatus.SKIPPED: "skipped",
            SyncStatus.FAILED: "failed",
            SyncStatus.NOT_FOUND_IN_SMAX: "not_found",
            SyncStatus.ALREADY_SET: "already_set",
            SyncStatus.NO_OS_TYPE: "no_os_type",
        }
        attr = status_map.get(result.status)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

        if result.status == SyncStatus.NOT_FOUND_IN_SMAX:
            self.not_found_report.append({
                "server_name": result.server_name,
                "source": result.source,
                "os_type": result.os_type,
            })

        if result.status == SyncStatus.NO_OS_TYPE:
            self.no_os_report.append({
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
                "already_set": self.already_set,
                "no_os_type": self.no_os_type,
            },
            "not_found_in_smax": self.not_found_report,
            "no_os_type_servers": self.no_os_report,
            "results": [
                {
                    "server_name": r.server_name,
                    "source": r.source,
                    "os_type": r.os_type,
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
        print("AD Server OS Type Sync Report")
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
        print(f"  Already set (no change): {self.already_set}")
        print(f"  Skipped (dry run): {self.skipped}")
        print(f"  Not found in SMAX: {self.not_found}")
        print(f"  No OS type determined: {self.no_os_type}")
        print(f"  Failed: {self.failed}")
        print("=" * 60)

        if self.not_found_report:
            print("\nSERVERS NOT FOUND IN SMAX:")
            print("-" * 60)
            for entry in self.not_found_report:
                print(f"  [{entry['source']}] {entry['server_name']} "
                      f"(OS: {entry['os_type'] or 'N/A'})")
            print("-" * 60)

        if self.no_os_report:
            print("\nSERVERS WITH NO OS TYPE DETERMINED:")
            print("-" * 60)
            for entry in self.no_os_report:
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
# CSV READER
# =============================================================================


def read_servers_from_csv(
    path: str,
    name_patterns: Optional[List[str]] = None,
) -> List[ServerInfo]:
    """
    Read servers from CSV file (ad_os_export.py output).
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

                if name_patterns:
                    matched = any(
                        fnmatch.fnmatch(name.upper(), p.upper())
                        for p in name_patterns
                    )
                    if not matched:
                        continue

                servers.append(ServerInfo(
                    name=name,
                    operating_system=row.get("OperatingSystem", "").strip(),
                    os_type=row.get("OsType", "").strip(),
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
        ci_type: str = "Device",
        target_field: str = "OsType",
        subtype: Optional[str] = None,
    ) -> Optional[CIRecord]:
        """Search for a CI by its display label (name)"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        filter_expr = f"(DisplayLabel = '{self._escape_query(name)}')"
        if subtype:
            filter_expr = f"(DisplayLabel = '{self._escape_query(name)}') and (SubType = '{subtype}')"
        params = {
            "layout": f"Id,DisplayLabel,SubType,{target_field}",
            "filter": filter_expr,
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
                    properties=props,
                )

        return None

    def search_cis(
        self,
        ci_type: str = "Device",
        filter_query: Optional[str] = None,
        layout: str = "Id,DisplayLabel,SubType",
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

        meta = data.get("meta", {})
        if meta.get("completion_status") == "FAILED":
            error_msg = meta.get("errorDetails", {}).get("message", "unknown")
            logger.error(f"SMAX query error: {error_msg}")
            return []

        entities = data.get("entities", [])

        cis = []
        for entity in entities:
            props = entity.get("properties", {})
            cis.append(
                CIRecord(
                    id=entity.get("entity_type", "") + "/" + str(props.get("Id")),
                    display_label=props.get("DisplayLabel", ""),
                    ci_type=ci_type,
                    properties=props,
                )
            )

        return cis

    def get_all_cis(
        self,
        ci_type: str = "Device",
        target_field: str = "OsType",
        subtype: Optional[str] = None,
        extra_fields: Optional[List[str]] = None,
    ) -> List[CIRecord]:
        """Get all CIs of a specific type (handles pagination)"""
        layout = f"Id,DisplayLabel,SubType,{target_field}"
        if extra_fields:
            layout += "," + ",".join(extra_fields)
        filter_query = None
        if subtype:
            filter_query = f"(SubType = '{subtype}')"
            logger.info(f"Using subtype filter: {subtype}")
        all_cis = []
        skip = 0
        size = 100

        while True:
            batch = self.search_cis(ci_type=ci_type, filter_query=filter_query, layout=layout, skip=skip, size=size)
            if not batch:
                break

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
        field_name: str = "OsType",
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
        ci_type: str = "Device",
        target_field: str = "OsType",
        subtype: Optional[str] = None,
    ) -> Optional[CIRecord]:
        """Find a CI that matches a server by DisplayLabel"""
        cache_key = name.lower()
        if cache_key in self._ci_cache:
            return self._ci_cache[cache_key]

        ci = self.client.get_ci_by_name(name, ci_type, target_field, subtype)

        if ci:
            self._ci_cache[cache_key] = ci

        return ci

    def load_all_cis(
        self,
        ci_type: str = "Device",
        target_field: str = "OsType",
        subtype: Optional[str] = None,
    ) -> None:
        """Pre-load all CIs into cache for faster lookups"""
        cis = self.client.get_all_cis(ci_type, target_field, subtype)

        for ci in cis:
            if ci.display_label:
                self._ci_cache[ci.display_label.lower()] = ci

        logger.info(f"Loaded {len(cis)} CIs into cache")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# OS TYPE SYNC SERVICE
# =============================================================================


class OsTypeSyncService:
    """Service to sync AD server OS types to SMAX CIs"""

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
            subtype=self.sync_config.smax_ci_subtype,
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
        """Load servers from live AD query, tag each with source 'ad_live'."""
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
        Sync a single server's OS type to the target SMAX field.

        1. Check if server has a determined OS type
        2. Find CI by name in SMAX
        3. If not found -> NOT_FOUND_IN_SMAX
        4. Check if field is already set
        5. If already set -> ALREADY_SET
        6. If dry_run -> SKIPPED
        7. Else -> update and return SUCCESS or FAILED
        """
        if not server.os_type:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type="",
                status=SyncStatus.NO_OS_TYPE,
                message=f"Could not determine OS type for '{server.name}' "
                        f"(OS: {server.operating_system or 'N/A'})",
            )

        ci = self.smax_service.find_ci_for_server(
            name=server.name,
            ci_type=self.sync_config.smax_ci_type,
            target_field=self.sync_config.smax_target_field,
            subtype=self.sync_config.smax_ci_subtype,
        )

        if not ci:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type=server.os_type,
                status=SyncStatus.NOT_FOUND_IN_SMAX,
                message=f"No CI found in SMAX matching '{server.name}'",
            )

        current_value = str(ci.target_field_value).strip() if ci.target_field_value else ""
        if current_value:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type=server.os_type,
                status=SyncStatus.ALREADY_SET,
                message=f"Field already set to '{current_value}'",
                ci_id=ci.id,
            )

        if self.sync_config.dry_run:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type=server.os_type,
                status=SyncStatus.SKIPPED,
                message=f"[DRY RUN] Would set to '{server.os_type}'",
                ci_id=ci.id,
            )

        success = self.smax_service.client.update_ci_field(
            ci_id=ci.id,
            value=server.os_type,
            field_name=self.sync_config.smax_target_field,
        )

        if success:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type=server.os_type,
                status=SyncStatus.SUCCESS,
                message=f"Set to '{server.os_type}'",
                ci_id=ci.id,
            )
        else:
            return SyncResult(
                server_name=server.name,
                source=source,
                os_type=server.os_type,
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
        2. Load AD live servers (Network B)
        3. Merge & deduplicate (live AD takes precedence)
        4. Apply name pattern filters
        5. Process each server
        6. Generate report
        7. Save state
        """
        report = SyncReport(start_time=datetime.now())

        if name_overrides:
            self.sync_config.name_patterns = name_overrides

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
            logger.info("Querying live AD for servers and OS info...")
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
                elif result.status == SyncStatus.NO_OS_TYPE:
                    logger.warning(f"[NO OS] [{source}] {server.name}: {result.message}")
                else:
                    logger.debug(f"[{result.status.value.upper()}] [{source}] {server.name}: {result.message}")

            except Exception as e:
                logger.error(f"Error processing {server.name}: {e}")
                report.add_result(SyncResult(
                    server_name=server.name,
                    source=source,
                    os_type=server.os_type,
                    status=SyncStatus.FAILED,
                    message=str(e),
                ))

        report.finalize()

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
            csv_input_path=sync_data.get("csv_input_path", "ad_os_servers.csv"),
            smax_ci_type=sync_data.get("smax_ci_type", "Device"),
            smax_ci_subtype=sync_data.get("smax_ci_subtype", "Server"),
            smax_matching_field=sync_data.get("smax_matching_field", "DisplayLabel"),
            smax_target_field=sync_data.get("smax_target_field", "OsType"),
            name_patterns=sync_data.get("name_patterns", []),
            state_file_path=sync_data.get("state_file_path", ".os_type_sync_state.json"),
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
            "csv_input_path": "ad_os_servers.csv",
            "smax_ci_type": "Device",
            "smax_ci_subtype": "Server",
            "smax_matching_field": "DisplayLabel",
            "smax_target_field": "OsType",
            "name_patterns": [],
            "state_file_path": ".os_type_sync_state.json",
            "dry_run": False,
            "batch_size": 50,
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connections(config: AppConfig) -> None:
    """Test AD and SMAX connections"""
    print(f"\n1. Testing AD connection to {config.active_directory.server}...")
    print(f"   Search base: {config.active_directory.base_dn}")
    try:
        with ADClient(config.active_directory) as client:
            servers = client.search_servers(name_filter=["*"], modified_after=None)
            windows = sum(1 for s in servers if s.os_type == "Windows")
            unix = sum(1 for s in servers if s.os_type == "Unix")
            unknown = sum(1 for s in servers if not s.os_type)
            print(f"   Connected - {len(servers)} server(s)")
            print(f"   Windows: {windows}, Unix: {unix}, Unclassified: {unknown}")
    except Exception as e:
        print(f"   Connection failed: {e}")
        sys.exit(1)

    print(f"\n2. Testing SMAX connection to {config.smax.base_url}...")
    try:
        smax = SMAXClient(config.smax)
        smax.connect()
        cis = smax.search_cis(
            ci_type=config.sync.smax_ci_type,
            layout=f"Id,DisplayLabel,SubType,{config.sync.smax_target_field}",
            size=5,
        )
        print(f"   Connected - Sample {len(cis)} CI(s):")
        for ci in cis:
            os_val = ci.properties.get(config.sync.smax_target_field, "")
            print(f"     {ci.display_label}: {config.sync.smax_target_field}={os_val or '(empty)'}")
        smax.disconnect()
    except Exception as e:
        print(f"   Connection failed: {e}")
        sys.exit(1)

    print("\nAll connections OK!")


def run_sync(config: AppConfig, args) -> None:
    """Run the OS type sync"""
    if args.dry_run:
        config.sync.dry_run = True
        logger.info("DRY RUN MODE: No actual changes will be made")

    name_overrides = args.names if args.names else None

    with OsTypeSyncService(config) as service:
        report = service.sync_all(
            full=args.full,
            csv_only=args.csv_only,
            ad_only=args.ad_only,
            name_overrides=name_overrides,
        )

    report.print_summary()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"Detailed report saved to: {args.output}")


def run_fill_empty(config: AppConfig, args) -> None:
    """Find CIs with empty OS type in SMAX and set them to a default value"""
    dry_run = args.dry_run
    default_value = args.value
    target_field = config.sync.smax_target_field

    if dry_run:
        logger.info("DRY RUN MODE: No actual changes will be made")

    logger.info(f"Searching SMAX for CIs with empty '{target_field}'...")

    smax = SMAXClient(config.smax)
    smax.connect()

    # Load all CIs with target field and Owner
    all_cis = smax.get_all_cis(
        ci_type=config.sync.smax_ci_type,
        target_field=target_field,
        subtype=config.sync.smax_ci_subtype,
        extra_fields=["OwnedByPerson"],
    )

    # Filter to empty target field AND Owner must be set
    empty_cis = []
    skipped_no_owner = 0
    for ci in all_cis:
        target_val = ci.target_field_value
        is_empty = not target_val or str(target_val).strip() == ""
        if not is_empty:
            continue
        owner = ci.properties.get("OwnedByPerson")
        if not owner or str(owner).strip() == "":
            skipped_no_owner += 1
            continue
        empty_cis.append(ci)

    logger.info(
        f"Found {len(empty_cis)} CIs with empty '{target_field}' and Owner set "
        f"(out of {len(all_cis)} total, {skipped_no_owner} skipped due to empty Owner)"
    )

    if not empty_cis:
        print(f"\nNo CIs found with empty '{target_field}'. Nothing to do.")
        smax.disconnect()
        return

    updated = 0
    failed = 0
    skipped = 0

    for i, ci in enumerate(empty_cis, 1):
        if i % 50 == 0:
            logger.info(f"Progress: {i}/{len(empty_cis)}")

        if dry_run:
            logger.info(f"[DRY RUN] Would set '{target_field}' to '{default_value}' for {ci.display_label} ({ci.id})")
            skipped += 1
        else:
            success = smax.update_ci_field(
                ci_id=ci.id,
                value=default_value,
                field_name=target_field,
            )
            if success:
                updated += 1
            else:
                failed += 1

    smax.disconnect()

    print("\n" + "=" * 60)
    print("Fill Empty OS Type Report")
    print("=" * 60)
    print(f"  Target field: {target_field}")
    print(f"  Default value: {default_value}")
    print(f"  CI type: {config.sync.smax_ci_type} / {config.sync.smax_ci_subtype or 'all'}")
    print(f"  Total CIs scanned: {len(all_cis)}")
    print(f"  CIs with empty field + Owner set: {len(empty_cis)}")
    print(f"  Skipped (empty Owner): {skipped_no_owner}")
    if dry_run:
        print(f"  Would update: {skipped}")
    else:
        print(f"  Updated: {updated}")
        print(f"  Failed: {failed}")
    print("=" * 60)
    print("")


def view_report(args) -> None:
    """View a saved sync report"""
    try:
        with open(args.input, "r") as f:
            data = json.load(f)

        print("\n" + "=" * 60)
        print("AD Server OS Type Sync Report")
        print("=" * 60)
        print(f"Start Time: {data.get('start_time')}")
        print(f"End Time: {data.get('end_time')}")
        if data.get("duration_seconds"):
            print(f"Duration: {data['duration_seconds']:.2f} seconds")
        if data.get("sources_processed"):
            print(f"Sources: {', '.join(data['sources_processed'])}")
        print("-" * 60)

        summary = data.get("summary", {})
        print("Summary:")
        print(f"  Total servers processed: {summary.get('total_servers', 0)}")
        print(f"  Successfully synced: {summary.get('synced', 0)}")
        print(f"  Already set: {summary.get('already_set', 0)}")
        print(f"  Skipped (dry run): {summary.get('skipped', 0)}")
        print(f"  Not found in SMAX: {summary.get('not_found_in_smax', 0)}")
        print(f"  No OS type: {summary.get('no_os_type', 0)}")
        print(f"  Failed: {summary.get('failed', 0)}")
        print("=" * 60)
    except Exception as e:
        print(f"Failed to read report: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AD Server OS Type Sync to SMAX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync OS types (CSV + live AD)
  python ad_os_sync.py sync --config config.json

  # Dry run (no changes)
  python ad_os_sync.py sync --config config.json --dry-run

  # Only from CSV (Network A export)
  python ad_os_sync.py sync --config config.json --csv-only

  # Only from live AD (Network B)
  python ad_os_sync.py sync --config config.json --ad-only --full

  # Specific servers
  python ad_os_sync.py sync --config config.json --names "SRV*" "WS-*"

  # Fill empty OS type fields in SMAX with 'Unix'
  python ad_os_sync.py fill-empty --config config.json --dry-run
  python ad_os_sync.py fill-empty --config config.json
  python ad_os_sync.py fill-empty --config config.json --value "Windows"

  # Test connections
  python ad_os_sync.py test --config config.json

  # View saved report
  python ad_os_sync.py report --input sync_report.json

  # Generate config template
  python ad_os_sync.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync OS types from AD to SMAX")
    sync_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    sync_parser.add_argument("--dry-run", action="store_true", help="Simulate without making changes")
    sync_parser.add_argument("--full", action="store_true", help="Full sync (ignore state)")
    sync_parser.add_argument("--csv-only", action="store_true", help="Only use CSV source")
    sync_parser.add_argument("--ad-only", action="store_true", help="Only use live AD source")
    sync_parser.add_argument("--names", nargs="+", help="Ad-hoc name patterns")
    sync_parser.add_argument("--output", "-o", help="Save detailed report to JSON file")
    sync_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    sync_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test AD and SMAX connections")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Report command
    report_parser = subparsers.add_parser("report", help="View a saved sync report")
    report_parser.add_argument("--input", "-i", required=True, help="Path to report JSON file")

    # Fill-empty command
    fill_parser = subparsers.add_parser("fill-empty", help="Set empty OS type fields in SMAX to a default value")
    fill_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    fill_parser.add_argument("--value", default="Unix", help="Value to set for empty fields (default: Unix)")
    fill_parser.add_argument("--dry-run", action="store_true", help="Simulate without making changes")
    fill_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    fill_parser.add_argument("--log-file", help="Log to file in addition to console")

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

    if args.command == "report":
        view_report(args)
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
        test_connections(config)
    elif args.command == "sync":
        run_sync(config, args)
    elif args.command == "fill-empty":
        run_fill_empty(config, args)


if __name__ == "__main__":
    main()
