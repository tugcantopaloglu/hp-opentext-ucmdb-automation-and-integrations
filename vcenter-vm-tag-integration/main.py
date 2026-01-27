#!/usr/bin/env python3
"""
VMware-SMAX Bridge
Synchronizes VMware VM tags (UPN-based owners) with SMAX CI owners

Usage:
    python vmware_smax_bridge.py sync --config config.json
    python vmware_smax_bridge.py sync --config config.json --dry-run
    python vmware_smax_bridge.py test --config config.json
    python vmware_smax_bridge.py list-tags --config config.json
    python vmware_smax_bridge.py generate-config --output config.json
"""

import argparse
import atexit
import json
import logging
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__version__ = "1.0.0"

# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class VMwareConfig:
    """VMware vCenter connection configuration"""
    host: str
    username: str
    password: str
    port: int = 443
    disable_ssl_verification: bool = False


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
    owner_tag_category: str = "Owner"
    smax_owner_field: str = "OwnedByPerson"
    smax_ci_type: str = "Device"
    smax_matching_field: str = "DisplayLabel"
    smax_alt_matching_field: Optional[str] = "PrimaryIP"
    dry_run: bool = False
    batch_size: int = 50


@dataclass
class AppConfig:
    """Main application configuration"""
    vmware: VMwareConfig
    smax: SMAXConfig
    sync: SyncConfig


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class VMInfo:
    """Represents a Virtual Machine with its relevant information"""
    name: str
    uuid: str
    power_state: str
    ip_address: Optional[str]
    tags: Dict[str, List[str]]
    guest_hostname: Optional[str] = None

    def get_owner_tag(self, owner_category: str) -> Optional[str]:
        """Get the owner tag value from the specified category"""
        tags = self.tags.get(owner_category, [])
        return tags[0] if tags else None


@dataclass
class CIRecord:
    """Represents a Configuration Item in SMAX"""
    id: str
    display_label: str
    ci_type: str
    owner: Optional[str] = None
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
    NOT_FOUND = "not_found"
    NO_OWNER_TAG = "no_owner_tag"
    OWNER_NOT_RESOLVED = "owner_not_resolved"
    ALREADY_SYNCED = "already_synced"


@dataclass
class SyncResult:
    """Result of syncing a single VM"""
    vm_name: str
    vm_uuid: str
    status: SyncStatus
    message: str
    owner_tag: Optional[str] = None
    resolved_owner_id: Optional[str] = None
    ci_id: Optional[str] = None
    previous_owner: Optional[str] = None


@dataclass
class SyncReport:
    """Summary report of the sync operation"""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_vms: int = 0
    synced: int = 0
    skipped: int = 0
    failed: int = 0
    not_found: int = 0
    no_owner_tag: int = 0
    owner_not_resolved: int = 0
    already_synced: int = 0
    results: List[SyncResult] = field(default_factory=list)

    def add_result(self, result: SyncResult) -> None:
        """Add a sync result and update counters"""
        self.results.append(result)
        status_map = {
            SyncStatus.SUCCESS: "synced",
            SyncStatus.SKIPPED: "skipped",
            SyncStatus.FAILED: "failed",
            SyncStatus.NOT_FOUND: "not_found",
            SyncStatus.NO_OWNER_TAG: "no_owner_tag",
            SyncStatus.OWNER_NOT_RESOLVED: "owner_not_resolved",
            SyncStatus.ALREADY_SYNCED: "already_synced",
        }
        attr = status_map.get(result.status)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

    def finalize(self) -> None:
        """Mark the report as complete"""
        self.end_time = datetime.now()

    def to_dict(self) -> Dict:
        """Convert report to dictionary"""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "summary": {
                "total_vms": self.total_vms,
                "synced": self.synced,
                "skipped": self.skipped,
                "failed": self.failed,
                "not_found": self.not_found,
                "no_owner_tag": self.no_owner_tag,
                "owner_not_resolved": self.owner_not_resolved,
                "already_synced": self.already_synced,
            },
            "results": [
                {
                    "vm_name": r.vm_name,
                    "vm_uuid": r.vm_uuid,
                    "status": r.status.value,
                    "message": r.message,
                    "owner_tag": r.owner_tag,
                    "resolved_owner_id": r.resolved_owner_id,
                    "ci_id": r.ci_id,
                    "previous_owner": r.previous_owner,
                }
                for r in self.results
            ],
        }

    def print_summary(self) -> None:
        """Print a human-readable summary"""
        print("\n" + "=" * 60)
        print("VMware-SMAX Synchronization Report")
        print("=" * 60)
        print(f"Start Time: {self.start_time}")
        print(f"End Time: {self.end_time}")
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            print(f"Duration: {duration:.2f} seconds")
        print("-" * 60)
        print("Summary:")
        print(f"  Total VMs processed: {self.total_vms}")
        print(f"  Successfully synced: {self.synced}")
        print(f"  Already synced (no change): {self.already_synced}")
        print(f"  Skipped: {self.skipped}")
        print(f"  CI not found in SMAX: {self.not_found}")
        print(f"  No owner tag: {self.no_owner_tag}")
        print(f"  Owner not resolved: {self.owner_not_resolved}")
        print(f"  Failed: {self.failed}")
        print("=" * 60 + "\n")


# =============================================================================
# VMWARE CLIENT
# =============================================================================

logger = logging.getLogger(__name__)


class VMwareClient:
    """Client for interacting with VMware vCenter"""

    def __init__(self, config: VMwareConfig):
        self.config = config
        self.service_instance = None
        self.content = None

    def connect(self) -> None:
        """Establish connection to vCenter"""
        try:
            context = None
            if self.config.disable_ssl_verification:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            self.service_instance = SmartConnect(
                host=self.config.host,
                user=self.config.username,
                pwd=self.config.password,
                port=self.config.port,
                sslContext=context,
            )

            atexit.register(Disconnect, self.service_instance)
            self.content = self.service_instance.RetrieveContent()
            logger.info(f"Successfully connected to vCenter: {self.config.host}")

        except Exception as e:
            logger.error(f"Failed to connect to vCenter: {e}")
            raise

    def disconnect(self) -> None:
        """Disconnect from vCenter"""
        if self.service_instance:
            Disconnect(self.service_instance)
            logger.info("Disconnected from vCenter")

    def get_all_vms(self) -> List[vim.VirtualMachine]:
        """Retrieve all virtual machines from vCenter"""
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.VirtualMachine], True
        )
        vms = list(container.view)
        container.Destroy()
        logger.info(f"Retrieved {len(vms)} virtual machines")
        return vms

    def get_vm_info(self, vm: vim.VirtualMachine) -> VMInfo:
        """Extract relevant information from a VM object"""
        ip_address = None
        if vm.guest and vm.guest.ipAddress:
            ip_address = vm.guest.ipAddress

        hostname = None
        if vm.guest and vm.guest.hostName:
            hostname = vm.guest.hostName

        power_state = str(vm.runtime.powerState)

        return VMInfo(
            name=vm.name,
            uuid=vm.config.uuid if vm.config else "",
            power_state=power_state,
            ip_address=ip_address,
            tags={},
            guest_hostname=hostname,
        )

    def get_all_vms_with_info(self) -> List[VMInfo]:
        """Get all VMs with their basic information"""
        vms = self.get_all_vms()
        vm_infos = []

        for vm in vms:
            try:
                info = self.get_vm_info(vm)
                vm_infos.append(info)
            except Exception as e:
                logger.warning(f"Failed to get info for VM: {e}")
                continue

        return vm_infos


class VMwareTagClient:
    """Client for VMware vSphere Automation API (for tags)"""

    def __init__(self, config: VMwareConfig):
        self.config = config
        self.session = None
        self.base_url = f"https://{config.host}/api"
        self._session_id = None

    def connect(self) -> None:
        """Authenticate and create session"""
        from requests.auth import HTTPBasicAuth

        if self.config.disable_ssl_verification:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.session.verify = not self.config.disable_ssl_verification

        auth_url = f"{self.base_url}/session"
        response = self.session.post(
            auth_url, auth=HTTPBasicAuth(self.config.username, self.config.password)
        )
        response.raise_for_status()

        self._session_id = response.json()
        self.session.headers.update({"vmware-api-session-id": self._session_id})

        logger.info("Successfully authenticated with vSphere Automation API")

    def disconnect(self) -> None:
        """Close the session"""
        if self.session and self._session_id:
            try:
                self.session.delete(f"{self.base_url}/session")
            except Exception as e:
                logger.warning(f"Failed to close session: {e}")

    def get_tag_categories(self) -> Dict[str, str]:
        """Get all tag categories: returns {category_id: category_name}"""
        response = self.session.get(f"{self.base_url}/cis/tagging/category")
        response.raise_for_status()

        categories = {}
        for category_id in response.json():
            cat_response = self.session.get(
                f"{self.base_url}/cis/tagging/category/{category_id}"
            )
            if cat_response.ok:
                cat_data = cat_response.json()
                categories[category_id] = cat_data.get("name", category_id)

        logger.info(f"Retrieved {len(categories)} tag categories")
        return categories

    def get_tags(self) -> Dict[str, Dict[str, Any]]:
        """Get all tags: returns {tag_id: {name, category_id}}"""
        response = self.session.get(f"{self.base_url}/cis/tagging/tag")
        response.raise_for_status()

        tags = {}
        for tag_id in response.json():
            tag_response = self.session.get(f"{self.base_url}/cis/tagging/tag/{tag_id}")
            if tag_response.ok:
                tag_data = tag_response.json()
                tags[tag_id] = {
                    "name": tag_data.get("name"),
                    "category_id": tag_data.get("category_id"),
                }

        logger.info(f"Retrieved {len(tags)} tags")
        return tags

    def get_all_vm_tags(self) -> Dict[str, List[str]]:
        """Get tags for all VMs. Returns: {vm_id: [tag_ids]}"""
        response = self.session.get(f"{self.base_url}/cis/tagging/tag")
        response.raise_for_status()

        vm_tags = {}
        tag_ids = response.json()

        for tag_id in tag_ids:
            attached_response = self.session.post(
                f"{self.base_url}/cis/tagging/tag-association/{tag_id}?action=list-attached-objects"
            )

            if attached_response.ok:
                for obj in attached_response.json():
                    if obj.get("type") == "VirtualMachine":
                        vm_id = obj.get("id")
                        if vm_id not in vm_tags:
                            vm_tags[vm_id] = []
                        vm_tags[vm_id].append(tag_id)

        logger.info(f"Retrieved tags for {len(vm_tags)} VMs")
        return vm_tags


class VMwareService:
    """High-level service combining VM and Tag clients"""

    def __init__(self, config: VMwareConfig):
        self.config = config
        self.vm_client = VMwareClient(config)
        self.tag_client = VMwareTagClient(config)
        self._categories = {}
        self._tags = {}

    def connect(self) -> None:
        """Connect both clients"""
        self.vm_client.connect()
        self.tag_client.connect()
        self._categories = self.tag_client.get_tag_categories()
        self._tags = self.tag_client.get_tags()

    def disconnect(self) -> None:
        """Disconnect both clients"""
        self.vm_client.disconnect()
        self.tag_client.disconnect()

    def get_vms_with_tags(self) -> List[VMInfo]:
        """Get all VMs with their tags resolved to names"""
        vms = self.vm_client.get_all_vms_with_info()
        vm_map = {vm.uuid: vm for vm in vms}
        all_vm_tags = self.tag_client.get_all_vm_tags()

        for vm_id, tag_ids in all_vm_tags.items():
            if vm_id in vm_map:
                vm_info = vm_map[vm_id]

                for tag_id in tag_ids:
                    if tag_id in self._tags:
                        tag_data = self._tags[tag_id]
                        tag_name = tag_data["name"]
                        category_id = tag_data["category_id"]
                        category_name = self._categories.get(category_id, "Unknown")

                        if category_name not in vm_info.tags:
                            vm_info.tags[category_name] = []
                        vm_info.tags[category_name].append(tag_name)

        logger.info(f"Retrieved {len(vms)} VMs with tags")
        return vms

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


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
        auth_url = f"{self.config.base_url}/auth/authentication-endpoint/authenticate/login"

        payload = {"Login": self.config.username, "Password": self.config.password}
        headers = {"Content-Type": "application/json"}

        response = self.session.post(auth_url, json=payload, headers=headers)
        response.raise_for_status()

        self._token = response.cookies.get("LWSSO_COOKIE_KEY")
        if not self._token:
            data = response.json()
            self._token = data.get("token")

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

    def get_ci_by_name(self, name: str, ci_type: str = "Device") -> Optional[CIRecord]:
        """Search for a CI by its display label (name)"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": "Id,DisplayLabel,OwnedByPerson,PrimaryIP,DnsName",
            "filter": f"DisplayLabel = '{self._escape_query(name)}'",
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
                    owner=props.get("OwnedByPerson"),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def get_ci_by_ip(self, ip_address: str, ci_type: str = "Device") -> Optional[CIRecord]:
        """Search for a CI by its IP address"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {
            "layout": "Id,DisplayLabel,OwnedByPerson,PrimaryIP,DnsName",
            "filter": f"PrimaryIP = '{self._escape_query(ip_address)}'",
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
                    owner=props.get("OwnedByPerson"),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )

        return None

    def search_cis(
        self,
        ci_type: str = "Device",
        filter_query: Optional[str] = None,
        layout: str = "Id,DisplayLabel,OwnedByPerson,PrimaryIP,DnsName",
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
        response.raise_for_status()

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
                    owner=props.get("OwnedByPerson"),
                    primary_ip=props.get("PrimaryIP"),
                    dns_name=props.get("DnsName"),
                    properties=props,
                )
            )

        return cis

    def get_all_cis(self, ci_type: str = "Device") -> List[CIRecord]:
        """Get all CIs of a specific type (handles pagination)"""
        all_cis = []
        skip = 0
        size = 100

        while True:
            batch = self.search_cis(ci_type=ci_type, skip=skip, size=size)
            if not batch:
                break

            all_cis.extend(batch)

            if len(batch) < size:
                break

            skip += size

        logger.info(f"Retrieved {len(all_cis)} CIs of type {ci_type}")
        return all_cis

    def get_person_by_upn(self, upn: str) -> Optional[str]:
        """Find a person by User Principal Name (UPN) and return their ID"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/Person"

        # Try exact match first
        params = {
            "layout": "Id,Name,Email,Upn",
            "filter": f"Upn = '{self._escape_query(upn)}'",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            entities = data.get("entities", [])

            if entities:
                props = entities[0].get("properties", {})
                return str(props.get("Id"))

        # If not found, try partial match (in case UPN has domain suffix)
        params = {
            "layout": "Id,Name,Email,Upn",
            "filter": f"Upn like '{self._escape_query(upn)}%'",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            entities = data.get("entities", [])

            if entities:
                props = entities[0].get("properties", {})
                return str(props.get("Id"))

        return None

    def get_person_by_name(self, name: str) -> Optional[str]:
        """Find a person by name and return their ID"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/Person"
        params = {
            "layout": "Id,Name,Email,Upn",
            "filter": f"Name = '{self._escape_query(name)}'",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            entities = data.get("entities", [])

            if entities:
                props = entities[0].get("properties", {})
                return str(props.get("Id"))

        return None

    def search_person(self, search_term: str) -> List[Dict[str, Any]]:
        """Search for persons by name, email, or UPN"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/Person"
        params = {
            "layout": "Id,Name,Email,Upn",
            "filter": f"Name like '%{self._escape_query(search_term)}%' or Email like '%{self._escape_query(search_term)}%' or Upn like '%{self._escape_query(search_term)}%'",
        }

        response = self.session.get(url, params=params)

        if response.ok:
            data = response.json()
            return [
                {
                    "id": e.get("properties", {}).get("Id"),
                    "name": e.get("properties", {}).get("Name"),
                    "email": e.get("properties", {}).get("Email"),
                    "upn": e.get("properties", {}).get("Upn"),
                }
                for e in data.get("entities", [])
            ]

        return []

    def update_ci_owner(
        self, ci_id: str, owner_id: str, owner_field: str = "OwnedByPerson"
    ) -> bool:
        """Update the owner of a CI"""
        self._ensure_authenticated()

        parts = ci_id.split("/")
        if len(parts) != 2:
            logger.error(f"Invalid CI ID format: {ci_id}")
            return False

        ci_type, record_id = parts

        url = f"{self.base_url}/ems/{ci_type}/{record_id}"

        payload = {"entity_type": ci_type, "properties": {owner_field: owner_id}}

        response = self.session.put(url, json=payload)

        if response.ok:
            logger.info(f"Successfully updated owner for CI {ci_id}")
            return True
        else:
            logger.error(
                f"Failed to update CI {ci_id}: {response.status_code} - {response.text}"
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


class SMAXService:
    """High-level service for SMAX operations with caching"""

    def __init__(self, config: SMAXConfig):
        self.client = SMAXClient(config)
        self._person_cache: Dict[str, Optional[str]] = {}
        self._ci_cache: Dict[str, CIRecord] = {}

    def connect(self) -> None:
        self.client.connect()

    def disconnect(self) -> None:
        self.client.disconnect()

    def resolve_owner_to_person_id(self, owner_identifier: str) -> Optional[str]:
        """Resolve an owner identifier (UPN like z12345) to a person ID with caching"""
        if owner_identifier in self._person_cache:
            return self._person_cache[owner_identifier]

        # Primary: Try by UPN (e.g., z12345)
        person_id = self.client.get_person_by_upn(owner_identifier)

        if not person_id:
            # Fallback: Try by Name
            person_id = self.client.get_person_by_name(owner_identifier)

        if not person_id:
            # Last resort: Search with partial match
            persons = self.client.search_person(owner_identifier)
            if persons:
                person_id = str(persons[0]["id"])

        self._person_cache[owner_identifier] = person_id
        return person_id

    def find_ci_for_vm(
        self, vm_name: str, vm_ip: Optional[str] = None, ci_type: str = "Device"
    ) -> Optional[CIRecord]:
        """Find a CI that matches a VM by name or IP"""
        cache_key = f"{vm_name}:{vm_ip}"
        if cache_key in self._ci_cache:
            return self._ci_cache[cache_key]

        ci = self.client.get_ci_by_name(vm_name, ci_type)

        if not ci and vm_ip:
            ci = self.client.get_ci_by_ip(vm_ip, ci_type)

        if ci:
            self._ci_cache[cache_key] = ci

        return ci

    def load_all_cis(self, ci_type: str = "Device") -> None:
        """Pre-load all CIs into cache for faster lookups"""
        cis = self.client.get_all_cis(ci_type)

        for ci in cis:
            self._ci_cache[ci.display_label] = ci
            if ci.primary_ip:
                self._ci_cache[ci.primary_ip] = ci

        logger.info(f"Loaded {len(cis)} CIs into cache")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# SYNC SERVICE
# =============================================================================


class SyncService:
    """Service to synchronize VMware VM tags with SMAX CI owners"""

    def __init__(self, config: AppConfig):
        self.config = config
        self.vmware_service = VMwareService(config.vmware)
        self.smax_service = SMAXService(config.smax)
        self.sync_config = config.sync

    def connect(self) -> None:
        """Connect to both VMware and SMAX"""
        logger.info("Connecting to VMware...")
        self.vmware_service.connect()

        logger.info("Connecting to SMAX...")
        self.smax_service.connect()

        logger.info("Loading CIs from SMAX...")
        self.smax_service.load_all_cis(self.sync_config.smax_ci_type)

    def disconnect(self) -> None:
        """Disconnect from both services"""
        self.vmware_service.disconnect()
        self.smax_service.disconnect()

    def sync_vm(self, vm: VMInfo) -> SyncResult:
        """Sync a single VM's owner tag to SMAX"""
        owner_tag = vm.get_owner_tag(self.sync_config.owner_tag_category)

        if not owner_tag:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.NO_OWNER_TAG,
                message=f"No '{self.sync_config.owner_tag_category}' tag found on VM",
            )

        ci = self.smax_service.find_ci_for_vm(
            vm_name=vm.name,
            vm_ip=vm.ip_address,
            ci_type=self.sync_config.smax_ci_type,
        )

        if not ci:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.NOT_FOUND,
                message=f"No CI found in SMAX matching VM name '{vm.name}' or IP '{vm.ip_address}'",
                owner_tag=owner_tag,
            )

        owner_id = self.smax_service.resolve_owner_to_person_id(owner_tag)

        if not owner_id:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.OWNER_NOT_RESOLVED,
                message=f"Could not resolve owner '{owner_tag}' to a Person in SMAX",
                owner_tag=owner_tag,
                ci_id=ci.id,
            )

        # Check if already synced - compare current owner with resolved owner
        if ci.owner == owner_id:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.ALREADY_SYNCED,
                message=f"CI owner already set to '{owner_tag}'",
                owner_tag=owner_tag,
                resolved_owner_id=owner_id,
                ci_id=ci.id,
                previous_owner=ci.owner,
            )

        if self.sync_config.dry_run:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.SKIPPED,
                message=f"[DRY RUN] Would update owner to '{owner_tag}' (ID: {owner_id})",
                owner_tag=owner_tag,
                resolved_owner_id=owner_id,
                ci_id=ci.id,
                previous_owner=ci.owner,
            )

        success = self.smax_service.client.update_ci_owner(
            ci_id=ci.id,
            owner_id=owner_id,
            owner_field=self.sync_config.smax_owner_field,
        )

        if success:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.SUCCESS,
                message=f"Successfully updated owner to '{owner_tag}'",
                owner_tag=owner_tag,
                resolved_owner_id=owner_id,
                ci_id=ci.id,
                previous_owner=ci.owner,
            )
        else:
            return SyncResult(
                vm_name=vm.name,
                vm_uuid=vm.uuid,
                status=SyncStatus.FAILED,
                message="Failed to update CI owner",
                owner_tag=owner_tag,
                resolved_owner_id=owner_id,
                ci_id=ci.id,
                previous_owner=ci.owner,
            )

    def sync_all(self) -> SyncReport:
        """Sync all VMs from VMware to SMAX"""
        report = SyncReport(start_time=datetime.now())

        logger.info("Retrieving VMs from VMware...")
        vms = self.vmware_service.get_vms_with_tags()
        report.total_vms = len(vms)

        logger.info(f"Processing {len(vms)} VMs...")

        for i, vm in enumerate(vms, 1):
            if i % 50 == 0:
                logger.info(f"Progress: {i}/{len(vms)} VMs processed")

            try:
                result = self.sync_vm(vm)
                report.add_result(result)

                if result.status == SyncStatus.SUCCESS:
                    logger.info(f"[SYNCED] {vm.name}: {result.message}")
                elif result.status in [SyncStatus.FAILED, SyncStatus.OWNER_NOT_RESOLVED]:
                    logger.warning(f"[{result.status.value.upper()}] {vm.name}: {result.message}")
                else:
                    logger.debug(f"[{result.status.value.upper()}] {vm.name}: {result.message}")

            except Exception as e:
                logger.error(f"Error processing VM {vm.name}: {e}")
                report.add_result(
                    SyncResult(
                        vm_name=vm.name,
                        vm_uuid=vm.uuid,
                        status=SyncStatus.FAILED,
                        message=str(e),
                    )
                )

        report.finalize()
        return report

    def sync_specific_vms(self, vm_names: List[str]) -> SyncReport:
        """Sync specific VMs by name"""
        report = SyncReport(start_time=datetime.now())

        all_vms = self.vmware_service.get_vms_with_tags()
        vms = [vm for vm in all_vms if vm.name in vm_names]
        report.total_vms = len(vms)

        found_names = {vm.name for vm in vms}
        not_found = set(vm_names) - found_names
        if not_found:
            logger.warning(f"VMs not found in VMware: {not_found}")

        for vm in vms:
            try:
                result = self.sync_vm(vm)
                report.add_result(result)
            except Exception as e:
                logger.error(f"Error processing VM {vm.name}: {e}")
                report.add_result(
                    SyncResult(
                        vm_name=vm.name,
                        vm_uuid=vm.uuid,
                        status=SyncStatus.FAILED,
                        message=str(e),
                    )
                )

        report.finalize()
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

    vmware_data = data.get("vmware", {})
    smax_data = data.get("smax", {})
    sync_data = data.get("sync", {})

    return AppConfig(
        vmware=VMwareConfig(
            host=vmware_data.get("host", ""),
            username=vmware_data.get("username", ""),
            password=vmware_data.get("password", ""),
            port=vmware_data.get("port", 443),
            disable_ssl_verification=vmware_data.get("disable_ssl_verification", False),
        ),
        smax=SMAXConfig(
            base_url=smax_data.get("base_url", ""),
            tenant_id=smax_data.get("tenant_id", ""),
            username=smax_data.get("username", ""),
            password=smax_data.get("password", ""),
            api_token=smax_data.get("api_token"),
        ),
        sync=SyncConfig(
            owner_tag_category=sync_data.get("owner_tag_category", "Owner"),
            smax_owner_field=sync_data.get("smax_owner_field", "OwnedByPerson"),
            smax_ci_type=sync_data.get("smax_ci_type", "Device"),
            smax_matching_field=sync_data.get("smax_matching_field", "DisplayLabel"),
            smax_alt_matching_field=sync_data.get("smax_alt_matching_field", "PrimaryIP"),
            dry_run=sync_data.get("dry_run", False),
            batch_size=sync_data.get("batch_size", 50),
        ),
    )


def generate_config_template(output_path: str) -> None:
    """Generate a configuration template file"""
    template = {
        "vmware": {
            "host": "vcenter.example.com",
            "username": "administrator@vsphere.local",
            "password": "your-password",
            "port": 443,
            "disable_ssl_verification": False,
        },
        "smax": {
            "base_url": "https://smax.example.com",
            "tenant_id": "your-tenant-id",
            "username": "admin",
            "password": "your-password",
            "api_token": None,
        },
        "sync": {
            "owner_tag_category": "Owner",
            "smax_owner_field": "OwnedByPerson",
            "smax_ci_type": "Device",
            "smax_matching_field": "DisplayLabel",
            "smax_alt_matching_field": "PrimaryIP",
            "dry_run": False,
            "batch_size": 50,
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


def test_connections(config: AppConfig) -> None:
    """Test connections to VMware and SMAX"""
    print("\nTesting VMware connection...")
    try:
        with VMwareService(config.vmware) as vmware:
            vms = vmware.vm_client.get_all_vms()
            print(f"✓ VMware connection successful - Found {len(vms)} VMs")
    except Exception as e:
        print(f"✗ VMware connection failed: {e}")

    print("\nTesting SMAX connection...")
    try:
        with SMAXService(config.smax) as smax:
            cis = smax.client.search_cis(ci_type=config.sync.smax_ci_type, size=1)
            print(f"✓ SMAX connection successful - CI type '{config.sync.smax_ci_type}' accessible")
    except Exception as e:
        print(f"✗ SMAX connection failed: {e}")


def list_vmware_tags(config: AppConfig) -> None:
    """List all VMware tags and categories"""
    with VMwareService(config.vmware) as vmware:
        print("\nTag Categories:")
        print("-" * 40)
        categories = vmware.tag_client.get_tag_categories()
        for cat_id, cat_name in categories.items():
            print(f"  - {cat_name}")

        print("\nTags:")
        print("-" * 40)
        tags = vmware.tag_client.get_tags()

        tags_by_category = {}
        for tag_id, tag_data in tags.items():
            cat_id = tag_data["category_id"]
            cat_name = categories.get(cat_id, "Unknown")
            if cat_name not in tags_by_category:
                tags_by_category[cat_name] = []
            tags_by_category[cat_name].append(tag_data["name"])

        for cat_name, tag_names in sorted(tags_by_category.items()):
            print(f"\n  {cat_name}:")
            for tag_name in sorted(tag_names):
                print(f"    - {tag_name}")


def run_sync_command(config: AppConfig, args) -> None:
    """Run the sync command"""
    with SyncService(config) as service:
        if args.vms:
            logger.info(f"Syncing specific VMs: {args.vms}")
            report = service.sync_specific_vms(args.vms)
        else:
            logger.info("Syncing all VMs")
            report = service.sync_all()

    report.print_summary()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"Report saved to {args.output}")

    if report.failed > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="VMware-SMAX Bridge: Sync VM tags to CI owners",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vmware_smax_bridge.py sync --config config.json
  python vmware_smax_bridge.py sync --config config.json --dry-run
  python vmware_smax_bridge.py sync --config config.json --vms vm1 vm2
  python vmware_smax_bridge.py test --config config.json
  python vmware_smax_bridge.py list-tags --config config.json
  python vmware_smax_bridge.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Synchronize VM tags to SMAX CI owners")
    sync_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    sync_parser.add_argument("--dry-run", "-n", action="store_true", help="Perform a dry run without making changes")
    sync_parser.add_argument("--vms", nargs="+", help="Specific VM names to sync (default: all VMs)")
    sync_parser.add_argument("--output", "-o", help="Output file for sync report (JSON format)")
    sync_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    sync_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test connections to VMware and SMAX")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # List tags command
    tags_parser = subparsers.add_parser("list-tags", help="List all VMware tags and categories")
    tags_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    tags_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

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

    if args.command == "sync" and args.dry_run:
        config.sync.dry_run = True
        logger.info("DRY RUN MODE: No actual changes will be made")

    if args.command == "test":
        test_connections(config)
    elif args.command == "list-tags":
        list_vmware_tags(config)
    elif args.command == "sync":
        run_sync_command(config, args)


if __name__ == "__main__":
    main()