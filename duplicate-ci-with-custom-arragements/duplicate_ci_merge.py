#!/usr/bin/env python3
"""
UCMDB Duplicate CI Merger
Detects and merges duplicate CIs between UCMDB and SMAX.
Migrates relations and properties from UCMDB-sourced CI to SMAX-sourced CI,
then deletes the UCMDB-sourced CI.

Usage:
    python duplicate_ci_merge.py detect --config config.json
    python duplicate_ci_merge.py merge --config config.json --dry-run
    python duplicate_ci_merge.py merge --config config.json
    python duplicate_ci_merge.py merge --config config.json --ci-names "SERVER01" "SERVER02"
    python duplicate_ci_merge.py test --config config.json
    python duplicate_ci_merge.py generate-config --output config.json
    python duplicate_ci_merge.py report --input merge_report.json
"""

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.0.0"

logger = logging.getLogger(__name__)

# System properties that should NOT be copied between CIs
SYSTEM_PROPERTIES = frozenset({
    "ucmdb_id", "global_id", "global_id_scope", "root_class",
    "createdby", "create_time", "updated_by", "update_time",
    "root_candidateforid_type", "root_candidateforid_value",
    "root_container", "root_iconpropertyname", "display_label",
    "calculated_id", "data_source", "data_note", "discovery_state",
    "track_changes", "is_save_persistency", "root_actualdeletionperiod",
    "root_enableageing", "last_discovered_by", "last_discovered_by_probe",
    "last_discovered_time", "last_modified_time",
})


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class UCMDBConfig:
    """UCMDB REST API connection configuration"""
    base_url: str
    username: str
    password: str
    client_context: int = 1
    disable_ssl_verification: bool = True


@dataclass
class SMAXConfig:
    """SMAX connection configuration"""
    base_url: str
    tenant_id: str
    username: str
    password: str
    api_token: Optional[str] = None


@dataclass
class MergeConfig:
    """Merge operation configuration"""
    ci_type: str = "node"
    smax_ci_type: str = "Device"
    smax_created_by_marker: str = "Updated-By-SMAX"
    name_property: str = "name"
    network_type_property: str = "_NetworkType"
    skip_relation_types: List[str] = field(default_factory=list)
    skip_composition_children: bool = True
    dry_run: bool = False
    batch_size: int = 50


@dataclass
class AppConfig:
    """Main application configuration"""
    ucmdb: UCMDBConfig
    smax: SMAXConfig
    merge: MergeConfig


# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class UCMDBCIRecord:
    """Represents a CI from UCMDB"""
    ucmdb_id: str
    ci_type: str
    name: str
    created_by: Optional[str] = None
    network_type: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    is_smax_sourced: bool = False


@dataclass
class UCMDBRelation:
    """Represents a relation between CIs in UCMDB"""
    relation_id: str
    relation_type: str
    end1_id: str
    end2_id: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DuplicatePair:
    """A pair of duplicate CIs: SMAX-sourced (keep) and UCMDB-sourced (merge+delete)"""
    smax_ci: UCMDBCIRecord  # keep this one
    ucmdb_ci: UCMDBCIRecord  # merge relations from this, then delete
    match_name: str
    match_network_type: Optional[str] = None


class MergeStatus(Enum):
    """Status of a merge operation"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    SKIPPED_SAFETY = "skipped_safety"


@dataclass
class RelationMigrationResult:
    """Result of migrating a single relation"""
    relation_id: str
    relation_type: str
    other_ci_id: str
    direction: str  # "outgoing" or "incoming"
    delete_success: bool = False
    create_success: bool = False
    message: str = ""


@dataclass
class PropertyCopyResult:
    """Result of copying a single property"""
    property_name: str
    source_value: Any = None
    was_missing: bool = False
    copy_success: bool = False


@dataclass
class MergeResult:
    """Result of merging a single duplicate pair"""
    smax_ci_id: str
    ucmdb_ci_id: str
    ci_name: str
    network_type: Optional[str] = None
    status: MergeStatus = MergeStatus.SKIPPED
    message: str = ""
    relations_migrated: List[RelationMigrationResult] = field(default_factory=list)
    properties_copied: List[PropertyCopyResult] = field(default_factory=list)
    ucmdb_ci_deleted: bool = False
    remaining_relations: int = -1  # -1 = not checked, 0 = verified clean


@dataclass
class MergeReport:
    """Aggregated merge report"""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_pairs: int = 0
    success: int = 0
    partial: int = 0
    failed: int = 0
    skipped: int = 0
    skipped_safety: int = 0
    results: List[MergeResult] = field(default_factory=list)

    def add_result(self, result: MergeResult) -> None:
        """Add a merge result and update counters"""
        self.results.append(result)
        status_map = {
            MergeStatus.SUCCESS: "success",
            MergeStatus.PARTIAL: "partial",
            MergeStatus.FAILED: "failed",
            MergeStatus.SKIPPED: "skipped",
            MergeStatus.SKIPPED_SAFETY: "skipped_safety",
        }
        attr = status_map.get(result.status)
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)

    def finalize(self) -> None:
        """Mark the report as complete"""
        self.end_time = datetime.now()

    def to_dict(self) -> Dict:
        """Convert report to dictionary for JSON serialization"""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (
                (self.end_time - self.start_time).total_seconds()
                if self.end_time else None
            ),
            "summary": {
                "total_pairs": self.total_pairs,
                "success": self.success,
                "partial": self.partial,
                "failed": self.failed,
                "skipped": self.skipped,
                "skipped_safety": self.skipped_safety,
            },
            "results": [
                {
                    "smax_ci_id": r.smax_ci_id,
                    "ucmdb_ci_id": r.ucmdb_ci_id,
                    "ci_name": r.ci_name,
                    "network_type": r.network_type,
                    "status": r.status.value,
                    "message": r.message,
                    "ucmdb_ci_deleted": r.ucmdb_ci_deleted,
                    "remaining_relations": r.remaining_relations,
                    "relations_migrated": [
                        {
                            "relation_id": rm.relation_id,
                            "relation_type": rm.relation_type,
                            "other_ci_id": rm.other_ci_id,
                            "direction": rm.direction,
                            "delete_success": rm.delete_success,
                            "create_success": rm.create_success,
                            "message": rm.message,
                        }
                        for rm in r.relations_migrated
                    ],
                    "properties_copied": [
                        {
                            "property_name": pc.property_name,
                            "source_value": str(pc.source_value) if pc.source_value is not None else None,
                            "was_missing": pc.was_missing,
                            "copy_success": pc.copy_success,
                        }
                        for pc in r.properties_copied
                    ],
                }
                for r in self.results
            ],
        }

    def print_summary(self) -> None:
        """Print a human-readable summary"""
        print("\n" + "=" * 60)
        print("UCMDB Duplicate CI Merge Report")
        print("=" * 60)
        print(f"Start Time: {self.start_time}")
        print(f"End Time:   {self.end_time}")
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            print(f"Duration:   {duration:.2f} seconds")
        print("-" * 60)
        print("Summary:")
        print(f"  Total pairs processed: {self.total_pairs}")
        print(f"  Successful merges:     {self.success}")
        print(f"  Partial merges:        {self.partial}")
        print(f"  Failed:                {self.failed}")
        print(f"  Skipped:               {self.skipped}")
        print(f"  Skipped (safety):      {self.skipped_safety}")
        print("=" * 60)

        # Show details per result
        for r in self.results:
            status_icon = {
                MergeStatus.SUCCESS: "+",
                MergeStatus.PARTIAL: "~",
                MergeStatus.FAILED: "x",
                MergeStatus.SKIPPED: "-",
                MergeStatus.SKIPPED_SAFETY: "!",
            }.get(r.status, "?")

            print(f"\n  [{status_icon}] {r.ci_name} (NetworkType: {r.network_type})")
            print(f"      SMAX CI:  {r.smax_ci_id}")
            print(f"      UCMDB CI: {r.ucmdb_ci_id}")
            print(f"      Status:   {r.status.value} - {r.message}")

            if r.relations_migrated:
                migrated_ok = sum(1 for rm in r.relations_migrated if rm.create_success)
                print(f"      Relations: {migrated_ok}/{len(r.relations_migrated)} migrated")

            if r.properties_copied:
                copied_ok = sum(1 for pc in r.properties_copied if pc.copy_success)
                print(f"      Properties: {copied_ok}/{len(r.properties_copied)} copied")

            if r.ucmdb_ci_deleted:
                print(f"      UCMDB CI deleted: Yes")

        print("")


# =============================================================================
# UCMDB CLIENT
# =============================================================================


class UCMDBClient:
    """Client for interacting with UCMDB REST API"""

    def __init__(self, config: UCMDBConfig):
        self.config = config
        self.session = None
        self.base_url = config.base_url.rstrip("/")
        self._token = None
        self._token_expiry = 0

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic"""
        session = requests.Session()
        session.verify = not self.config.disable_ssl_verification

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
        """Authenticate with UCMDB and obtain JWT token"""
        self.session = self._create_session()
        self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate using username and password"""
        auth_url = f"{self.base_url}/authenticate"

        payload = {
            "username": self.config.username,
            "password": self.config.password,
            "clientContext": self.config.client_context,
        }

        response = self.session.post(auth_url, json=payload)
        response.raise_for_status()

        data = response.json()
        self._token = data.get("token")

        if not self._token:
            raise Exception("Failed to obtain authentication token from UCMDB")

        self.session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        })

        self._token_expiry = time.time() + 3600
        logger.info("Successfully authenticated with UCMDB")

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid authentication token"""
        if time.time() >= self._token_expiry - 300:
            logger.info("UCMDB token expiring soon, re-authenticating...")
            self._authenticate()

    def get_ci(self, ci_id: str) -> Optional[Dict]:
        """Get a single CI by its ID"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel/ci/{ci_id}"
        response = self.session.get(url)

        if response.ok:
            return response.json()

        if response.status_code == 404:
            logger.warning(f"CI not found: {ci_id}")
            return None

        logger.error(f"Failed to get CI {ci_id}: {response.status_code} {response.text}")
        return None

    def get_related_cis(self, ci_id: str) -> Optional[Dict]:
        """Get all relations and related CIs for a given CI"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel/ci/{ci_id}/relations"
        response = self.session.get(url)

        if response.ok:
            return response.json()

        if response.status_code == 404:
            logger.warning(f"No relations found for CI: {ci_id}")
            return None

        logger.error(f"Failed to get relations for {ci_id}: {response.status_code} {response.text}")
        return None

    def delete_relation(self, relation_id: str) -> bool:
        """Delete a relation by its ID"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel/relation/{relation_id}"
        response = self.session.delete(url)

        if response.ok:
            logger.debug(f"Deleted relation: {relation_id}")
            return True

        logger.error(f"Failed to delete relation {relation_id}: {response.status_code} {response.text}")
        return False

    def create_relation(
        self,
        relation_type: str,
        end1_id: str,
        end1_type: str,
        end2_id: str,
        end2_type: str,
        properties: Optional[Dict] = None,
    ) -> bool:
        """Create a new relation between two CIs"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel"

        payload = {
            "relations": [
                {
                    "ucmdbId": None,
                    "type": relation_type,
                    "properties": properties or {},
                    "end1Id": end1_id,
                    "end2Id": end2_id,
                }
            ],
            "cis": [],
        }

        response = self.session.post(url, json=payload)

        if response.ok:
            logger.debug(f"Created relation {relation_type}: {end1_id} -> {end2_id}")
            return True

        logger.error(
            f"Failed to create relation {relation_type} "
            f"({end1_id} -> {end2_id}): {response.status_code} {response.text}"
        )
        return False

    def update_ci_properties(self, ci_id: str, ci_type: str, properties: Dict) -> bool:
        """Update properties on an existing CI"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel"

        payload = {
            "cis": [
                {
                    "ucmdbId": ci_id,
                    "type": ci_type,
                    "properties": properties,
                }
            ],
            "relations": [],
        }

        response = self.session.post(url, json=payload)

        if response.ok:
            logger.debug(f"Updated CI {ci_id} with {len(properties)} properties")
            return True

        logger.error(f"Failed to update CI {ci_id}: {response.status_code} {response.text}")
        return False

    def delete_ci(self, ci_id: str) -> bool:
        """Delete a CI by its ID"""
        self._ensure_authenticated()

        url = f"{self.base_url}/dataModel/ci/{ci_id}"
        response = self.session.delete(url)

        if response.ok:
            logger.info(f"Deleted CI: {ci_id}")
            return True

        logger.error(f"Failed to delete CI {ci_id}: {response.status_code} {response.text}")
        return False

    def query_cis_by_type(self, ci_type: str) -> List[Dict]:
        """Query all CIs of a given type using topology query"""
        self._ensure_authenticated()

        url = f"{self.base_url}/topologyQuery"

        # Use a simple TQL-style query to get all CIs of the given type
        payload = {
            "queryName": None,
            "queryExpression": {
                "nodes": [
                    {
                        "nodeId": "node1",
                        "type": ci_type,
                        "visible": True,
                        "queryIdentifier": "node1",
                    }
                ],
                "relationships": [],
            },
            "propertiesFilterList": [],
        }

        response = self.session.post(url, json=payload)

        if response.ok:
            data = response.json()
            cis = data.get("cis", [])
            logger.info(f"Retrieved {len(cis)} CIs of type '{ci_type}'")
            return cis

        logger.error(f"Failed to query CIs of type {ci_type}: {response.status_code} {response.text}")
        return []

    def disconnect(self) -> None:
        """Sign out from UCMDB"""
        if self.session and self._token:
            try:
                url = f"{self.base_url}/authenticate/sign-out"
                self.session.post(url)
                logger.info("Signed out from UCMDB")
            except Exception as e:
                logger.warning(f"Error signing out from UCMDB: {e}")
            finally:
                self._token = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# SMAX CLIENT (VERIFICATION ONLY)
# =============================================================================


class SMAXClient:
    """Stripped-down SMAX client for optional CI verification"""

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
            logger.info("Using API token authentication for SMAX")
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
            logger.info("SMAX token expiring soon, re-authenticating...")
            self._authenticate()

    def _escape_query(self, value: str) -> str:
        """Escape special characters in query values"""
        return value.replace("'", "''")

    def search_cis(
        self,
        ci_type: str = "Device",
        filter_query: Optional[str] = None,
        layout: str = "Id,DisplayLabel",
        skip: int = 0,
        size: int = 100,
    ) -> List[Dict]:
        """Search for CIs with optional filtering"""
        self._ensure_authenticated()

        url = f"{self.base_url}/ems/{ci_type}"
        params = {"layout": layout, "skip": skip, "size": size}

        if filter_query:
            params["filter"] = filter_query

        response = self.session.get(url, params=params)

        if not response.ok:
            logger.error(f"SMAX CI search failed: {response.status_code}")
            return []

        data = response.json()
        return data.get("entities", [])

    def disconnect(self) -> None:
        """Close SMAX session"""
        if self.session:
            try:
                self.session.close()
                logger.info("SMAX session closed")
            except Exception as e:
                logger.warning(f"Error closing SMAX session: {e}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# =============================================================================
# MERGE SERVICE
# =============================================================================


class MergeService:
    """Service that detects duplicate CIs and merges them"""

    def __init__(self, config: AppConfig, ucmdb_client: UCMDBClient):
        self.config = config
        self.ucmdb = ucmdb_client
        self.merge_config = config.merge

    def detect_duplicates(self) -> List[DuplicatePair]:
        """
        Detect duplicate CIs by matching (name, _NetworkType).
        A duplicate pair = 1 SMAX-sourced + 1 UCMDB-sourced CI with same key.
        """
        logger.info(f"Querying all CIs of type '{self.merge_config.ci_type}' from UCMDB...")
        raw_cis = self.ucmdb.query_cis_by_type(self.merge_config.ci_type)

        if not raw_cis:
            logger.warning("No CIs found in UCMDB")
            return []

        # Parse CIs
        ci_records = []
        for raw_ci in raw_cis:
            ci_record = self._parse_ci(raw_ci)
            if ci_record and ci_record.name:
                ci_records.append(ci_record)

        logger.info(f"Parsed {len(ci_records)} CIs with valid names")

        smax_count = sum(1 for c in ci_records if c.is_smax_sourced)
        ucmdb_count = len(ci_records) - smax_count
        logger.info(f"  SMAX-sourced: {smax_count}, UCMDB-sourced: {ucmdb_count}")

        # Group by (name.lower(), network_type)
        groups: Dict[tuple, List[UCMDBCIRecord]] = {}
        for ci in ci_records:
            key = (ci.name.lower().strip(), ci.network_type or "")
            if key not in groups:
                groups[key] = []
            groups[key].append(ci)

        # Find duplicate pairs
        pairs = []
        for key, group in groups.items():
            if len(group) < 2:
                continue

            smax_cis = [c for c in group if c.is_smax_sourced]
            ucmdb_cis = [c for c in group if not c.is_smax_sourced]

            if len(smax_cis) == 1 and len(ucmdb_cis) == 1:
                pair = DuplicatePair(
                    smax_ci=smax_cis[0],
                    ucmdb_ci=ucmdb_cis[0],
                    match_name=key[0],
                    match_network_type=key[1] or None,
                )
                pairs.append(pair)
                logger.info(
                    f"  Duplicate found: '{key[0]}' (NetworkType: {key[1] or 'N/A'}) "
                    f"SMAX={smax_cis[0].ucmdb_id} UCMDB={ucmdb_cis[0].ucmdb_id}"
                )
            elif len(group) > 2 or len(smax_cis) != 1 or len(ucmdb_cis) != 1:
                logger.warning(
                    f"  Ambiguous group for '{key[0]}' (NetworkType: {key[1] or 'N/A'}): "
                    f"{len(smax_cis)} SMAX-sourced, {len(ucmdb_cis)} UCMDB-sourced - SKIPPING"
                )

        logger.info(f"Detected {len(pairs)} duplicate pairs")
        return pairs

    def _parse_ci(self, raw_ci: Dict) -> Optional[UCMDBCIRecord]:
        """Parse raw CI data from UCMDB topology query into a UCMDBCIRecord"""
        ucmdb_id = raw_ci.get("ucmdbId")
        if not ucmdb_id:
            return None

        ci_type = raw_ci.get("type", self.merge_config.ci_type)
        properties = raw_ci.get("properties", {})

        name = properties.get(self.merge_config.name_property, "")
        created_by = properties.get("createdby", "")
        network_type = properties.get(self.merge_config.network_type_property)

        is_smax_sourced = (
            self.merge_config.smax_created_by_marker.lower()
            in (created_by or "").lower()
        )

        return UCMDBCIRecord(
            ucmdb_id=ucmdb_id,
            ci_type=ci_type,
            name=name or "",
            created_by=created_by,
            network_type=network_type,
            properties=properties,
            is_smax_sourced=is_smax_sourced,
        )

    def merge_pair(self, pair: DuplicatePair) -> MergeResult:
        """
        Merge a single duplicate pair:
        1. Safety check: both CIs still exist
        2. Get relations from UCMDB CI
        3. Migrate each relation to SMAX CI
        4. Copy missing properties
        5. Delete UCMDB CI (only if all relations migrated successfully)
        """
        result = MergeResult(
            smax_ci_id=pair.smax_ci.ucmdb_id,
            ucmdb_ci_id=pair.ucmdb_ci.ucmdb_id,
            ci_name=pair.match_name,
            network_type=pair.match_network_type,
        )

        dry_run = self.merge_config.dry_run

        logger.info(
            f"{'[DRY RUN] ' if dry_run else ''}"
            f"Merging: '{pair.match_name}' "
            f"(UCMDB={pair.ucmdb_ci.ucmdb_id} -> SMAX={pair.smax_ci.ucmdb_id})"
        )

        # Step 1: Safety check - verify both CIs still exist
        smax_ci_data = self.ucmdb.get_ci(pair.smax_ci.ucmdb_id)
        ucmdb_ci_data = self.ucmdb.get_ci(pair.ucmdb_ci.ucmdb_id)

        if not smax_ci_data:
            result.status = MergeStatus.FAILED
            result.message = f"SMAX CI {pair.smax_ci.ucmdb_id} no longer exists"
            logger.error(result.message)
            return result

        if not ucmdb_ci_data:
            result.status = MergeStatus.FAILED
            result.message = f"UCMDB CI {pair.ucmdb_ci.ucmdb_id} no longer exists"
            logger.error(result.message)
            return result

        # Refresh properties from live data
        smax_props = smax_ci_data.get("properties", {})
        ucmdb_props = ucmdb_ci_data.get("properties", {})
        smax_ci_type = smax_ci_data.get("type", pair.smax_ci.ci_type)
        ucmdb_ci_type = ucmdb_ci_data.get("type", pair.ucmdb_ci.ci_type)

        # Step 2: Get relations from UCMDB CI
        relations_data = self.ucmdb.get_related_cis(pair.ucmdb_ci.ucmdb_id)
        relations = self._extract_relations(relations_data, pair.ucmdb_ci.ucmdb_id)

        logger.info(f"  Found {len(relations)} relations on UCMDB CI")

        # Step 3: Migrate each relation
        all_relations_ok = True
        for rel in relations:
            rel_result = self._migrate_relation(
                rel, pair.ucmdb_ci.ucmdb_id, pair.smax_ci.ucmdb_id, dry_run
            )
            result.relations_migrated.append(rel_result)

            if not rel_result.create_success and not dry_run:
                all_relations_ok = False

        # Step 4: Copy missing properties
        props_to_copy = {}
        for prop_name, prop_value in ucmdb_props.items():
            if prop_name.lower() in {p.lower() for p in SYSTEM_PROPERTIES}:
                continue

            smax_value = smax_props.get(prop_name)

            # Only copy if SMAX CI is missing this property (None or empty)
            if prop_value is not None and prop_value != "":
                is_missing = smax_value is None or smax_value == ""
                prop_result = PropertyCopyResult(
                    property_name=prop_name,
                    source_value=prop_value,
                    was_missing=is_missing,
                )

                if is_missing:
                    props_to_copy[prop_name] = prop_value
                    prop_result.copy_success = True  # will be set properly below

                result.properties_copied.append(prop_result)

        if props_to_copy:
            if dry_run:
                logger.info(f"  [DRY RUN] Would copy {len(props_to_copy)} properties")
                for pc in result.properties_copied:
                    if pc.was_missing:
                        pc.copy_success = True
            else:
                success = self.ucmdb.update_ci_properties(
                    pair.smax_ci.ucmdb_id, smax_ci_type, props_to_copy
                )
                for pc in result.properties_copied:
                    if pc.was_missing:
                        pc.copy_success = success
                if success:
                    logger.info(f"  Copied {len(props_to_copy)} properties to SMAX CI")
                else:
                    logger.error(f"  Failed to copy properties to SMAX CI")
                    all_relations_ok = False
        else:
            logger.info(f"  No properties to copy")

        # Step 5: Verify UCMDB CI has no remaining relations, then delete
        if dry_run:
            if all_relations_ok:
                result.status = MergeStatus.SUCCESS
                result.message = (
                    f"[DRY RUN] Would migrate {len(relations)} relations, "
                    f"copy {len(props_to_copy)} properties, and delete UCMDB CI"
                )
            else:
                result.status = MergeStatus.PARTIAL
                result.message = "[DRY RUN] Some operations would fail"
            logger.info(f"  {result.message}")
        elif all_relations_ok:
            # Re-query relations on UCMDB CI to verify none remain
            remaining_data = self.ucmdb.get_related_cis(pair.ucmdb_ci.ucmdb_id)
            remaining = self._extract_relations(remaining_data, pair.ucmdb_ci.ucmdb_id)

            # Filter out skipped relation types (composition etc.) — those are expected to remain
            non_skipped_remaining = [
                r for r in remaining
                if not self._should_skip_relation(r)
            ]
            result.remaining_relations = len(non_skipped_remaining)

            if non_skipped_remaining:
                result.status = MergeStatus.PARTIAL
                result.message = (
                    f"UCMDB CI still has {len(non_skipped_remaining)} remaining "
                    f"relation(s) after migration - NOT deleted for safety"
                )
                logger.warning(f"  PARTIAL: {result.message}")
                for rem in non_skipped_remaining:
                    logger.warning(
                        f"    Remaining: {rem.relation_type} "
                        f"({rem.end1_id} -> {rem.end2_id})"
                    )
            else:
                deleted = self.ucmdb.delete_ci(pair.ucmdb_ci.ucmdb_id)
                result.ucmdb_ci_deleted = deleted
                if deleted:
                    result.status = MergeStatus.SUCCESS
                    result.message = (
                        f"Merged {len(relations)} relations, "
                        f"copied {len(props_to_copy)} properties, "
                        f"verified 0 remaining relations, UCMDB CI deleted"
                    )
                    logger.info(f"  SUCCESS: {result.message}")
                else:
                    result.status = MergeStatus.PARTIAL
                    result.message = "Relations migrated but failed to delete UCMDB CI"
                    logger.warning(f"  PARTIAL: {result.message}")
        else:
            result.status = MergeStatus.PARTIAL
            result.message = (
                "Some relation migrations failed - UCMDB CI NOT deleted for safety"
            )
            logger.warning(f"  PARTIAL: {result.message}")

        return result

    def _extract_relations(
        self, relations_data: Optional[Dict], ci_id: str
    ) -> List[UCMDBRelation]:
        """Extract relation objects from the UCMDB related CIs response"""
        if not relations_data:
            return []

        relations = []
        raw_relations = relations_data.get("relations", [])

        for raw_rel in raw_relations:
            rel_id = raw_rel.get("ucmdbId")
            rel_type = raw_rel.get("type", "")
            end1_id = raw_rel.get("end1Id", "")
            end2_id = raw_rel.get("end2Id", "")
            props = raw_rel.get("properties", {})

            if rel_id:
                relations.append(UCMDBRelation(
                    relation_id=rel_id,
                    relation_type=rel_type,
                    end1_id=end1_id,
                    end2_id=end2_id,
                    properties=props,
                ))

        return relations

    def _should_skip_relation(self, relation: UCMDBRelation) -> bool:
        """Check if a relation type is in the skip list (composition, skip_relation_types)"""
        if relation.relation_type in self.merge_config.skip_relation_types:
            return True

        if self.merge_config.skip_composition_children:
            rel_type_lower = relation.relation_type.lower()
            if "composition" in rel_type_lower or "containment" in rel_type_lower:
                return True

        return False

    def _migrate_relation(
        self,
        relation: UCMDBRelation,
        source_ci_id: str,
        target_ci_id: str,
        dry_run: bool,
    ) -> RelationMigrationResult:
        """Migrate a single relation from source CI to target CI"""
        # Determine direction and other CI
        if relation.end1_id == source_ci_id:
            direction = "outgoing"
            other_ci_id = relation.end2_id
            new_end1 = target_ci_id
            new_end2 = other_ci_id
        else:
            direction = "incoming"
            other_ci_id = relation.end1_id
            new_end1 = other_ci_id
            new_end2 = target_ci_id

        result = RelationMigrationResult(
            relation_id=relation.relation_id,
            relation_type=relation.relation_type,
            other_ci_id=other_ci_id,
            direction=direction,
        )

        # Check skip rules (composition, explicit skip list)
        if self._should_skip_relation(relation):
            result.message = f"Skipped: relation type '{relation.relation_type}'"
            result.delete_success = True
            result.create_success = True
            logger.debug(f"    {result.message}")
            return result

        # Skip self-relation: if the other end is the target CI itself,
        # migrating would create a relation from SMAX CI to itself
        if other_ci_id == target_ci_id:
            result.message = (
                f"Skipped: relation '{relation.relation_type}' is between "
                f"the two duplicate CIs — would create self-relation"
            )
            result.delete_success = True
            result.create_success = True
            logger.info(f"    {result.message}")
            return result

        if dry_run:
            result.delete_success = True
            result.create_success = True
            result.message = (
                f"[DRY RUN] Would migrate {relation.relation_type} "
                f"({direction}) to/from {other_ci_id}"
            )
            logger.debug(f"    {result.message}")
            return result

        # Create new relation first (safe: old relation still intact if this fails)
        create_ok = self.ucmdb.create_relation(
            relation_type=relation.relation_type,
            end1_id=new_end1,
            end1_type="",  # UCMDB resolves types from IDs
            end2_id=new_end2,
            end2_type="",
            properties=relation.properties,
        )
        result.create_success = create_ok

        if not create_ok:
            result.message = (
                f"Failed to create new relation {relation.relation_type} "
                f"({direction}) — old relation preserved, no data loss"
            )
            logger.error(f"    {result.message}")
            return result

        # Create succeeded — now safe to delete old relation
        del_ok = self.ucmdb.delete_relation(relation.relation_id)
        result.delete_success = del_ok

        if del_ok:
            result.message = (
                f"Migrated {relation.relation_type} ({direction}) "
                f"to/from {other_ci_id}"
            )
            logger.debug(f"    {result.message}")
        else:
            result.message = (
                f"New relation created but failed to delete old one "
                f"for {relation.relation_type} ({direction}) — "
                f"duplicate relation exists, manual cleanup needed"
            )
            logger.warning(f"    {result.message}")

        return result

    def merge_all(self, pairs: List[DuplicatePair]) -> MergeReport:
        """Merge all duplicate pairs and produce a report"""
        report = MergeReport(start_time=datetime.now())
        report.total_pairs = len(pairs)

        for i, pair in enumerate(pairs, 1):
            logger.info(f"Processing pair {i}/{len(pairs)}: {pair.match_name}")

            try:
                merge_result = self.merge_pair(pair)
                report.add_result(merge_result)
            except Exception as e:
                logger.error(f"Error merging '{pair.match_name}': {e}")
                report.add_result(MergeResult(
                    smax_ci_id=pair.smax_ci.ucmdb_id,
                    ucmdb_ci_id=pair.ucmdb_ci.ucmdb_id,
                    ci_name=pair.match_name,
                    network_type=pair.match_network_type,
                    status=MergeStatus.FAILED,
                    message=f"Exception: {e}",
                ))

        report.finalize()
        return report


# =============================================================================
# CONFIGURATION LOADING
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

    ucmdb_data = data.get("ucmdb", {})
    smax_data = data.get("smax", {})
    merge_data = data.get("merge", {})

    return AppConfig(
        ucmdb=UCMDBConfig(
            base_url=ucmdb_data.get("base_url", ""),
            username=ucmdb_data.get("username", ""),
            password=ucmdb_data.get("password", ""),
            client_context=ucmdb_data.get("client_context", 1),
            disable_ssl_verification=ucmdb_data.get("disable_ssl_verification", True),
        ),
        smax=SMAXConfig(
            base_url=smax_data.get("base_url", ""),
            tenant_id=smax_data.get("tenant_id", ""),
            username=smax_data.get("username", ""),
            password=smax_data.get("password", ""),
            api_token=smax_data.get("api_token"),
        ),
        merge=MergeConfig(
            ci_type=merge_data.get("ci_type", "node"),
            smax_ci_type=merge_data.get("smax_ci_type", "Device"),
            smax_created_by_marker=merge_data.get("smax_created_by_marker", "Updated-By-SMAX"),
            name_property=merge_data.get("name_property", "name"),
            network_type_property=merge_data.get("network_type_property", "_NetworkType"),
            skip_relation_types=merge_data.get("skip_relation_types", []),
            skip_composition_children=merge_data.get("skip_composition_children", True),
            dry_run=merge_data.get("dry_run", False),
            batch_size=merge_data.get("batch_size", 50),
        ),
    )


def generate_config_template(output_path: str) -> None:
    """Generate a configuration template file"""
    template = {
        "ucmdb": {
            "base_url": "https://ucmdb-server:8443/rest-api",
            "username": "admin",
            "password": "your-password",
            "client_context": 1,
            "disable_ssl_verification": True,
        },
        "smax": {
            "base_url": "https://smax.example.com",
            "tenant_id": "your-tenant-id",
            "username": "admin",
            "password": "your-password",
            "api_token": None,
        },
        "merge": {
            "ci_type": "node",
            "smax_ci_type": "Device",
            "smax_created_by_marker": "Updated-By-SMAX",
            "name_property": "name",
            "network_type_property": "_NetworkType",
            "skip_relation_types": [],
            "skip_composition_children": True,
            "dry_run": False,
            "batch_size": 50,
        },
    }

    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)

    print(f"Configuration template generated: {output_path}")


# =============================================================================
# CLI COMMANDS
# =============================================================================


def test_connections(config: AppConfig) -> None:
    """Test UCMDB and SMAX connections"""
    print("\nTesting UCMDB connection...")
    print(f"  URL: {config.ucmdb.base_url}")
    try:
        with UCMDBClient(config.ucmdb) as ucmdb:
            cis = ucmdb.query_cis_by_type(config.merge.ci_type)
            print(f"  + Connected - Found {len(cis)} CIs of type '{config.merge.ci_type}'")
    except Exception as e:
        print(f"  x UCMDB connection failed: {e}")

    print("\nTesting SMAX connection...")
    print(f"  URL: {config.smax.base_url}")
    try:
        with SMAXClient(config.smax) as smax:
            entities = smax.search_cis(ci_type=config.merge.smax_ci_type, size=1)
            print(f"  + Connected - CI type '{config.merge.smax_ci_type}' accessible")
    except Exception as e:
        print(f"  x SMAX connection failed: {e}")


def run_detect_command(config: AppConfig, args) -> None:
    """Run the detect command to find duplicate CIs"""
    with UCMDBClient(config.ucmdb) as ucmdb:
        service = MergeService(config, ucmdb)
        pairs = service.detect_duplicates()

    if not pairs:
        print("\nNo duplicate pairs found.")
        return

    print(f"\nFound {len(pairs)} duplicate pairs:")
    print("-" * 80)
    print(f"{'#':<4} {'CI Name':<30} {'NetworkType':<15} {'SMAX CI ID':<20} {'UCMDB CI ID':<20}")
    print("-" * 80)

    for i, pair in enumerate(pairs, 1):
        print(
            f"{i:<4} {pair.match_name:<30} {(pair.match_network_type or 'N/A'):<15} "
            f"{pair.smax_ci.ucmdb_id:<20} {pair.ucmdb_ci.ucmdb_id:<20}"
        )

    print("-" * 80)

    if args.output:
        output_data = {
            "detected_at": datetime.now().isoformat(),
            "total_pairs": len(pairs),
            "pairs": [
                {
                    "ci_name": p.match_name,
                    "network_type": p.match_network_type,
                    "smax_ci_id": p.smax_ci.ucmdb_id,
                    "ucmdb_ci_id": p.ucmdb_ci.ucmdb_id,
                    "smax_ci_created_by": p.smax_ci.created_by,
                    "ucmdb_ci_created_by": p.ucmdb_ci.created_by,
                }
                for p in pairs
            ],
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nDetection results saved to: {args.output}")


def run_merge_command(config: AppConfig, args) -> None:
    """Run the merge command"""
    if args.dry_run:
        config.merge.dry_run = True
        logger.info("DRY RUN MODE: No actual changes will be made")

    with UCMDBClient(config.ucmdb) as ucmdb:
        service = MergeService(config, ucmdb)

        # Detect duplicates
        pairs = service.detect_duplicates()

        if not pairs:
            print("\nNo duplicate pairs found. Nothing to merge.")
            return

        # Filter by CI names if specified
        if args.ci_names:
            ci_names_lower = [n.lower() for n in args.ci_names]
            pairs = [p for p in pairs if p.match_name.lower() in ci_names_lower]
            logger.info(f"Filtered to {len(pairs)} pairs matching specified CI names")

            if not pairs:
                print("\nNo matching duplicate pairs found for the specified CI names.")
                return

        print(f"\n{'[DRY RUN] ' if config.merge.dry_run else ''}Processing {len(pairs)} duplicate pairs...")

        # Merge
        report = service.merge_all(pairs)

    report.print_summary()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"Merge report saved to: {args.output}")

    if report.failed > 0:
        sys.exit(1)


def run_report_command(args) -> None:
    """Display a previously saved merge report"""
    try:
        with open(args.input, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Report file not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in report file: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("UCMDB Duplicate CI Merge Report (from file)")
    print("=" * 60)
    print(f"Start Time: {data.get('start_time')}")
    print(f"End Time:   {data.get('end_time')}")

    duration = data.get("duration_seconds")
    if duration is not None:
        print(f"Duration:   {duration:.2f} seconds")

    summary = data.get("summary", {})
    print("-" * 60)
    print("Summary:")
    print(f"  Total pairs processed: {summary.get('total_pairs', 0)}")
    print(f"  Successful merges:     {summary.get('success', 0)}")
    print(f"  Partial merges:        {summary.get('partial', 0)}")
    print(f"  Failed:                {summary.get('failed', 0)}")
    print(f"  Skipped:               {summary.get('skipped', 0)}")
    print(f"  Skipped (safety):      {summary.get('skipped_safety', 0)}")
    print("=" * 60)

    results = data.get("results", [])
    for r in results:
        status = r.get("status", "unknown")
        status_icon = {
            "success": "+", "partial": "~", "failed": "x",
            "skipped": "-", "skipped_safety": "!",
        }.get(status, "?")

        print(f"\n  [{status_icon}] {r.get('ci_name')} (NetworkType: {r.get('network_type')})")
        print(f"      SMAX CI:  {r.get('smax_ci_id')}")
        print(f"      UCMDB CI: {r.get('ucmdb_ci_id')}")
        print(f"      Status:   {status} - {r.get('message')}")

        rels = r.get("relations_migrated", [])
        if rels:
            migrated_ok = sum(1 for rm in rels if rm.get("create_success"))
            print(f"      Relations: {migrated_ok}/{len(rels)} migrated")

        props = r.get("properties_copied", [])
        if props:
            copied_ok = sum(1 for pc in props if pc.get("copy_success"))
            print(f"      Properties: {copied_ok}/{len(props)} copied")

        if r.get("ucmdb_ci_deleted"):
            print(f"      UCMDB CI deleted: Yes")

    print("")


# =============================================================================
# MAIN
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="UCMDB Duplicate CI Merger: Detect and merge duplicate CIs between UCMDB and SMAX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test connections
  python duplicate_ci_merge.py test --config config.json

  # Detect duplicate CIs
  python duplicate_ci_merge.py detect --config config.json
  python duplicate_ci_merge.py detect --config config.json --output duplicates.json

  # Merge with dry run first
  python duplicate_ci_merge.py merge --config config.json --dry-run
  python duplicate_ci_merge.py merge --config config.json --dry-run --ci-names "SERVER01"

  # Actual merge
  python duplicate_ci_merge.py merge --config config.json
  python duplicate_ci_merge.py merge --config config.json --ci-names "SERVER01" "SERVER02"

  # View a saved report
  python duplicate_ci_merge.py report --input merge_report.json

  # Generate config template
  python duplicate_ci_merge.py generate-config --output config.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Detect duplicate CIs")
    detect_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    detect_parser.add_argument("--output", "-o", help="Output file for detection results (JSON)")
    detect_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    detect_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Merge command
    merge_parser = subparsers.add_parser("merge", help="Merge duplicate CIs")
    merge_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    merge_parser.add_argument("--dry-run", "-n", action="store_true", help="Perform a dry run without making changes")
    merge_parser.add_argument("--output", "-o", help="Output file for merge report (JSON)")
    merge_parser.add_argument("--ci-names", nargs="+", help="Specific CI names to merge (default: all duplicates)")
    merge_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    merge_parser.add_argument("--log-file", help="Log to file in addition to console")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test UCMDB and SMAX connections")
    test_parser.add_argument("--config", "-c", required=True, help="Path to configuration JSON file")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    # Generate config command
    template_parser = subparsers.add_parser("generate-config", help="Generate a configuration template")
    template_parser.add_argument("--output", "-o", default="config.json", help="Output file path")

    # Report command
    report_parser = subparsers.add_parser("report", help="Display a saved merge report")
    report_parser.add_argument("--input", "-i", required=True, help="Path to merge report JSON file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-config":
        generate_config_template(args.output)
        return

    if args.command == "report":
        run_report_command(args)
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
    elif args.command == "detect":
        run_detect_command(config, args)
    elif args.command == "merge":
        run_merge_command(config, args)


if __name__ == "__main__":
    main()
