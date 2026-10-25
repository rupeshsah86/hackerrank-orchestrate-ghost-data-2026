"""Multimodal evidence parser and point-in-time state indexer.

Extracts ground-truth resource observations from SQLite SQL snapshots,
JSON snapshot bundles, log traces, handover notes, PDFs, and PNG screenshots.
"""

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

try:
    import pypdf
except ImportError:
    pypdf = None


@dataclass
class EvidenceRecord:
    evidence_id: str
    file_path: str
    captured_at: str
    system_id: str
    resource_id: str
    data_category: str
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    user_identifiers: Set[str] = field(default_factory=set)
    details: Dict = field(default_factory=dict)


class EvidenceParser:
    def __init__(self, manifest_path: str, evidence_root: str):
        self.manifest_path = manifest_path
        self.evidence_root = evidence_root
        self.evidence_files: List[Dict[str, str]] = []
        self.records_by_evidence_id: Dict[str, List[EvidenceRecord]] = {}
        self.records_by_resource_id: Dict[str, List[EvidenceRecord]] = {}
        self._load_manifest()

    def _load_manifest(self):
        with open(self.manifest_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.evidence_files.append(row)

    def parse_all(self):
        for ev in self.evidence_files:
            ev_id = ev["file_id"]
            rel_path = ev["file_path"]
            # dataset/evidence_files.csv paths look like 'evidence/databases/...'
            # Resolve relative to dataset/ directory
            full_path = os.path.join(os.path.dirname(self.manifest_path), rel_path)
            if not os.path.exists(full_path):
                # Try relative to repo root
                full_path = os.path.join(self.evidence_root, rel_path)

            captured_at = ev["captured_at"]
            ext = os.path.splitext(full_path)[1].lower()

            recs = []
            if ext == ".sql":
                recs = self._parse_sql(ev_id, full_path, captured_at)
            elif ext == ".json":
                recs = self._parse_json(ev_id, full_path, captured_at)
            elif ext == ".txt":
                recs = self._parse_txt(ev_id, full_path, captured_at)
            elif ext == ".log":
                recs = self._parse_log(ev_id, full_path, captured_at)
            elif ext == ".pdf":
                recs = self._parse_pdf(ev_id, full_path, captured_at)

            self.records_by_evidence_id[ev_id] = recs
            for r in recs:
                self.records_by_resource_id.setdefault(r.resource_id, []).append(r)

    def _parse_sql(self, ev_id: str, file_path: str, captured_at: str) -> List[EvidenceRecord]:
        recs = []
        if not os.path.exists(file_path):
            return recs

        try:
            conn = sqlite3.connect(":memory:")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                sql_script = f.read()
            conn.executescript(sql_script)

            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            # Track primary vs replica presence to detect replication drift
            primary_resources = set()
            replica_resources = set()

            for table in tables:
                cursor.execute(f"PRAGMA table_info({table});")
                cols = [c[1] for c in cursor.fetchall()]

                cursor.execute(f"SELECT * FROM {table};")
                rows = cursor.fetchall()

                is_replica = "replica" in table.lower()
                is_primary = "primary" in table.lower()

                for row in rows:
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id")
                    if not res_id:
                        continue

                    if is_primary:
                        primary_resources.add(res_id)
                    if is_replica:
                        replica_resources.add(res_id)

                    system_id = row_dict.get("origin_system", "account_service")
                    collection = row_dict.get("collection_name", "")

                    record_json_str = row_dict.get("record_json")
                    record_data = {}
                    if record_json_str:
                        try:
                            record_data = json.loads(record_json_str)
                        except:
                            record_data = {}

                    user_ids = set()
                    for k in ["user_id", "customer_reference", "subject_reference", "email", "phone", "email_hash", "full_name", "display_name", "customer_email", "customer_phone", "requester_email", "requester_phone", "owner_email", "owner_phone", "correlation_key", "match_key", "lookup_key"]:
                        val = record_data.get(k) or row_dict.get(k)
                        if not val and isinstance(record_data.get("document"), dict):
                            val = record_data["document"].get(k)
                        if val and isinstance(val, str):
                            clean_val = val.strip()
                            if clean_val.lower() not in ["null", "none", "undefined"]:
                                user_ids.add(clean_val.lower() if ("@" in clean_val or (len(clean_val) == 64 and not clean_val.startswith("user_"))) else clean_val)

                    # Determine state & system from resource/data
                    state = "PRESENT"
                    data_cat = "USER_PROFILE"
                    if "analytics_" in res_id:
                        system_id = "analytics_platform"
                        data_cat = "ANALYTICS_PROFILE"
                        # check if attributable
                        if not any(record_data.get(k) or row_dict.get(k) for k in ["user_id", "email", "phone", "email_hash", "customer_email"]):
                            state = "ANONYMIZED"
                    elif "search_" in res_id:
                        system_id = "search_service"
                        data_cat = "SEARCH_INDEX_ENTRY"
                    elif "audit_record_" in res_id:
                        system_id = "security_service"
                        data_cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif "backup_" in res_id:
                        system_id = "backup_service"
                        data_cat = "BACKUP_ARCHIVE"
                        restore_allowed_val = record_data.get("restore_allowed") if "restore_allowed" in record_data else row_dict.get("restore_allowed")
                        state = "BLOCKED" if str(restore_allowed_val).lower() in ["0", "false", "none"] else "ACTIVE"
                    elif "data_flow_" in res_id:
                        system_id = "integration_service"
                        data_cat = "DATA_FLOW"
                        enabled_val = record_data.get("enabled") if "enabled" in record_data else row_dict.get("enabled")
                        state = "DISABLED" if str(enabled_val).lower() in ["0", "false", "stopped", "disabled"] else "ACTIVE"
                    elif "support_" in res_id:
                        system_id = "support_platform"
                        data_cat = "SUPPORT_MESSAGE"
                        msg = record_data.get("message_text", "")
                        if "[REDACTED]" in msg:
                            state = "REDACTED"
                    elif "tombstone_" in res_id:
                        system_id = "identity_service"
                        data_cat = "ACCOUNT_TOMBSTONE"
                        if any(record_data.get(k) for k in ["name", "email", "phone", "email_hash"]):
                            state = "PRESENT"  # exposed PII
                        else:
                            state = "REDACTED"
                    elif "account_" in res_id:
                        system_id = "account_service"
                        data_cat = "USER_PROFILE"

                    recs.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            system_id=system_id,
                            resource_id=res_id,
                            data_category=data_cat,
                            state=state,
                            user_identifiers=user_ids,
                            details=record_data or row_dict,
                        )
                    )

            conn.close()
        except Exception:
            pass

        return recs

    def _parse_json(self, ev_id: str, file_path: str, captured_at: str) -> List[EvidenceRecord]:
        recs = []
        if not os.path.exists(file_path):
            return recs

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Type 1: service_resource_export_*.json
            if "service_exports" in data:
                sexports = data["service_exports"]
                for svc_name, svc_content in sexports.items():
                    # Account service
                    for item in svc_content.get("profile_lookups", []):
                        res_id = item.get("resource_id")
                        status_code = item.get("status_code", 404)
                        state = "ABSENT" if status_code == 404 else "PRESENT"
                        uids = set()
                        prof = item.get("profile") or {}
                        for k in ["customer_reference", "email", "phone", "email_hash", "full_name"]:
                            if prof.get(k):
                                uids.add(prof[k].strip().lower() if "@" in prof[k] else prof[k].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "account_service", res_id, "USER_PROFILE", state, uids, item))

                    # Analytics platform
                    for item in svc_content.get("profiles", []):
                        res_id = item.get("resource_id")
                        uids = set()
                        has_ident = False
                        for k in ["customer_reference", "email", "phone", "email_hash", "user_id"]:
                            if item.get(k):
                                has_ident = True
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        state = "PRESENT" if has_ident else "ANONYMIZED"
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "analytics_platform", res_id, "ANALYTICS_PROFILE", state, uids, item))

                    # Backup service
                    for item in svc_content.get("restore_entries", []):
                        res_id = item.get("resource_id")
                        allowed = item.get("restore_allowed", False)
                        state = "ACTIVE" if allowed else "BLOCKED"
                        uids = set()
                        for k in ["customer_reference", "customer_email"]:
                            if item.get(k):
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "backup_service", res_id, "BACKUP_ARCHIVE", state, uids, item))

                    # Export service
                    for item in svc_content.get("exports", []):
                        res_id = item.get("resource_id")
                        avail = item.get("download_available", False) or bool(item.get("object_key"))
                        state = "PRESENT" if avail else "ABSENT"
                        uids = set()
                        for k in ["customer_reference", "owner_email"]:
                            if item.get(k):
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "export_service", res_id, "USER_EXPORT", state, uids, item))

                    # Identity service tombstones
                    for item in svc_content.get("tombstones", []):
                        res_id = item.get("resource_id")
                        uids = set()
                        has_pii = False
                        for k in ["name", "email", "phone", "email_hash"]:
                            if item.get(k):
                                has_pii = True
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        if item.get("subject_reference"):
                            uids.add(item["subject_reference"].strip())
                        state = "PRESENT" if has_pii else "REDACTED"
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "identity_service", res_id, "ACCOUNT_TOMBSTONE", state, uids, item))

                    # Integration service
                    for item in svc_content.get("connectors", []):
                        res_id = item.get("resource_id")
                        enabled = item.get("enabled", False)
                        state = "ACTIVE" if enabled else "DISABLED"
                        uids = set()
                        for k in ["customer_reference", "customer_email"]:
                            if item.get(k):
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "integration_service", res_id, "DATA_FLOW", state, uids, item))

                    # Search service
                    for item in svc_content.get("index_queries", []):
                        res_id = item.get("resource_id")
                        hits_obj = item.get("hits")
                        hits = item.get("total_hits", 0)
                        if isinstance(hits_obj, dict):
                            hits = hits_obj.get("total", hits)
                            docs = hits_obj.get("documents", [])
                        elif isinstance(hits_obj, int):
                            hits = hits_obj
                            docs = []
                        else:
                            docs = []

                        state = "PRESENT" if hits > 0 else "ABSENT"
                        uids = set()
                        for k in ["customer_reference", "email", "query"]:
                            if item.get(k):
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        for doc in docs:
                            if isinstance(doc, dict):
                                for k in ["email", "display_name", "customer_reference"]:
                                    if doc.get(k):
                                        uids.add(doc[k].strip().lower() if "@" in doc[k] else doc[k].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "search_service", res_id, "SEARCH_INDEX_ENTRY", state, uids, item))

                    # Security service
                    audit_list = svc_content.get("audit_records") or svc_content.get("audit_events") or []
                    for item in audit_list:
                        res_id = item.get("resource_id")
                        state = "PRESENT"
                        uids = set()
                        if item.get("subject_reference"):
                            uids.add(item["subject_reference"].strip())
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "security_service", res_id, "SECURITY_AUDIT_LOG", state, uids, item))

                    # Support platform
                    for item in svc_content.get("tickets", []):
                        res_id = item.get("resource_id")
                        uids = set()
                        has_pii = False
                        for k in ["requester_name", "requester_email", "requester_phone"]:
                            if item.get(k):
                                has_pii = True
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        if item.get("customer_reference"):
                            uids.add(item["customer_reference"].strip())
                        state = "PRESENT" if has_pii else "REDACTED"
                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, "support_platform", res_id, "SUPPORT_MESSAGE", state, uids, item))

            # Type 2: customer_data_snapshot_bundle_*.json
            elif "snapshots" in data:
                for snap in data.get("snapshots", []):
                    store = snap.get("data_store")
                    coll = snap.get("collection", "")
                    for item in snap.get("records", []):
                        res_id = item.get("resource_id")
                        if not res_id:
                            continue
                        uids = set()
                        for k in ["user_id", "customer_reference", "subject_reference", "email", "phone", "email_hash", "full_name", "name"]:
                            if item.get(k):
                                uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())
                        doc = item.get("document", {})
                        if isinstance(doc, dict):
                            for k in ["email", "display_name", "customer_reference"]:
                                if doc.get(k):
                                    uids.add(doc[k].strip().lower() if "@" in doc[k] else doc[k].strip())

                        state = "PRESENT"
                        data_cat = "USER_PROFILE"
                        if store == "analytics_platform":
                            data_cat = "ANALYTICS_PROFILE"
                            if not any(item.get(k) for k in ["user_id", "email", "phone", "email_hash"]):
                                state = "ANONYMIZED"
                        elif store == "identity_service":
                            data_cat = "ACCOUNT_TOMBSTONE"
                            if any(item.get(k) for k in ["name", "email", "phone", "email_hash"]):
                                state = "PRESENT"
                            else:
                                state = "REDACTED"
                        elif store == "security_service":
                            data_cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif store == "search_service":
                            data_cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"

                        recs.append(EvidenceRecord(ev_id, file_path, captured_at, store, res_id, data_cat, state, uids, item))

            # Type 3: Specialized JSON records
            elif "records" in data:
                for item in data.get("records", []):
                    res_id = item.get("resource_id")
                    if not res_id:
                        continue
                    uids = set()
                    for k in ["owner_email", "subject_selector", "user_id", "customer_reference", "subject_reference", "email"]:
                        if item.get(k):
                            uids.add(item[k].strip().lower() if "@" in item[k] else item[k].strip())

                    state = "PRESENT"
                    sys_id = "export_service"
                    cat = "USER_EXPORT"
                    if "export_" in res_id:
                        avail = item.get("download_available", True)
                        state = "PRESENT" if avail else "ABSENT"
                        sys_id = "export_service"
                        cat = "USER_EXPORT"
                    elif "data_flow_" in res_id:
                        en = item.get("enabled", True)
                        state = "ACTIVE" if en else "DISABLED"
                        sys_id = "integration_service"
                        cat = "DATA_FLOW"
                    elif "audit_record_" in res_id:
                        state = "PRESENT"
                        sys_id = "security_service"
                        cat = "SECURITY_AUDIT_LOG"

                    recs.append(EvidenceRecord(ev_id, file_path, captured_at, sys_id, res_id, cat, state, uids, item))

        except Exception:
            pass

        return recs

    def _parse_txt(self, ev_id: str, file_path: str, captured_at: str) -> List[EvidenceRecord]:
        recs = []
        if not os.path.exists(file_path):
            return recs

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, res_id, cat, raw_status, identifier = parts[:6]
                    uids = set()
                    if identifier and identifier != "no direct identifier":
                        uids.add(identifier.lower() if "@" in identifier else identifier)

                    state = "PRESENT"
                    if raw_status == "NOT_FOUND":
                        state = "ABSENT"
                    elif raw_status == "FOUND":
                        state = "PRESENT"
                    elif raw_status == "IDENTIFIABLE":
                        state = "PRESENT"
                    elif raw_status == "ANONYMIZED":
                        state = "ANONYMIZED"
                    elif raw_status == "REDACTED":
                        state = "REDACTED"
                    elif raw_status == "ACTIVE":
                        state = "ACTIVE"
                    elif raw_status == "DISABLED":
                        state = "DISABLED"
                    elif raw_status == "BLOCKED":
                        state = "BLOCKED"

                    recs.append(EvidenceRecord(ev_id, file_path, captured_at, sys_id, res_id, cat, state, uids, {"raw": line}))

        return recs

    def _parse_log(self, ev_id: str, file_path: str, captured_at: str) -> List[EvidenceRecord]:
        recs = []
        if not os.path.exists(file_path):
            return recs

        traces: Dict[str, Dict] = {}
        untraced_entries: List = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                entry_data = {}
                json_start = line_str.find("{")
                if json_start != -1 and line_str.endswith("}"):
                    try:
                        entry_data = json.loads(line_str[json_start:])
                    except Exception:
                        entry_data = {}

                kv_pairs = dict(re.findall(r'(\b[a-zA-Z0-9_-]+)=["\']?([^"\'\s,|]+)["\']?', line))
                merged = {**kv_pairs, **entry_data}

                trace_key = merged.get("trace_id") or merged.get("requestId") or merged.get("request_id")

                uids = set()
                for k in ["lookup_key", "match_key", "subject_key", "correlation_key", "matched_value",
                          "subject_ref", "subject_reference", "customer_reference", "customer_email",
                          "email", "requester_email", "owner_email", "scan_key", "owner_key"]:
                    val = merged.get(k)
                    if val and isinstance(val, str):
                        clean_val = val.strip()
                        if clean_val.lower() not in ["null", "none", "true", "false", "hit", "miss", "undefined"]:
                            uids.add(clean_val.lower() if ("@" in clean_val or (len(clean_val) == 64 and not clean_val.startswith("user_"))) else clean_val)

                for em in re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", line):
                    uids.add(em.lower())

                for uid_match in re.findall(r"\buser_\w+\b", line):
                    uids.add(uid_match)

                res_id = merged.get("resource_id") or merged.get("target_resource")
                if not res_id:
                    res_match = re.search(r'resource_id[:=]["\']?([a-zA-Z0-9_]+)["\']?', line)
                    if res_match:
                        res_id = res_match.group(1)

                sys_id = merged.get("service") or merged.get("function") or merged.get("logger")
                if not sys_id:
                    sys_match = re.search(r'(?:service|function|logger)[:=]["\']?([a-zA-Z0-9_]+)["\']?', line)
                    if sys_match:
                        sys_id = sys_match.group(1)

                if trace_key:
                    if trace_key not in traces:
                        traces[trace_key] = {
                            "resource_id": res_id,
                            "sys_id": sys_id,
                            "uids": set(uids),
                            "lines": [line_str],
                            "merged": merged,
                        }
                    else:
                        t = traces[trace_key]
                        if res_id:
                            t["resource_id"] = res_id
                        if sys_id:
                            t["sys_id"] = sys_id
                        t["uids"].update(uids)
                        t["lines"].append(line_str)
                        t["merged"].update(merged)
                else:
                    if res_id:
                        untraced_entries.append((res_id, sys_id, uids, [line_str], merged))

        all_groups = []
        for t in traces.values():
            if t.get("resource_id"):
                all_groups.append((t["resource_id"], t["sys_id"], t["uids"], t["lines"], t["merged"]))
        all_groups.extend(untraced_entries)

        for res_id, sys_id, uids, lines, merged in all_groups:
            full_text = " ".join(lines)
            sys_id = sys_id or "account_service"
            if sys_id:
                if sys_id.startswith("support") or "attachment" in sys_id:
                    sys_id = "support_platform"
                elif sys_id.startswith("analytics"):
                    sys_id = "analytics_platform"
                elif sys_id.startswith("search"):
                    sys_id = "search_service"
                elif sys_id.startswith("security") or "audit" in sys_id:
                    sys_id = "security_service"
                elif sys_id.startswith("integration"):
                    sys_id = "integration_service"
                elif sys_id.startswith("backup"):
                    sys_id = "backup_service"
                elif sys_id.startswith("account") or sys_id.startswith("profile"):
                    sys_id = "account_service"

            state = "PRESENT"
            if (
                "rows=0" in full_text
                or "http_status=404" in full_text
                or '"rows":"0"' in full_text
                or '"http_status":"404"' in full_text
                or str(merged.get("rows")) == "0"
                or str(merged.get("http_status")) == "404"
            ):
                state = "ABSENT"
            elif "enabled=false" in full_text or "status=stopped" in full_text or str(merged.get("enabled")).lower() == "false":
                state = "DISABLED"
            elif "enabled=true" in full_text or str(merged.get("enabled")).lower() == "true":
                state = "ACTIVE"
            elif "restore_allowed=false" in full_text or str(merged.get("restore_allowed")).lower() == "false":
                state = "BLOCKED"
            elif "restore_allowed=true" in full_text or str(merged.get("restore_allowed")).lower() == "true":
                state = "ACTIVE"
            elif (
                "rows=1" in full_text
                or "http_status=200" in full_text
                or '"rows":"1"' in full_text
                or '"http_status":"200"' in full_text
                or "total_hits=1" in full_text
                or "result=hit" in full_text
                or str(merged.get("rows")) == "1"
                or str(merged.get("http_status")) == "200"
            ):
                state = "PRESENT"

            if "analytics_" in res_id:
                sys_id = "analytics_platform"
                if uids and ("rows=1" in full_text or "total_hits=1" in full_text):
                    state = "PRESENT"
                elif ("customer_reference=null" in full_text and "email=null" in full_text and "phone=null" in full_text):
                    state = "ANONYMIZED"
                elif not uids and merged.get("customer_reference") is None and merged.get("email") is None and merged.get("phone") is None and "analytics_identity_scan" not in full_text:
                    state = "ANONYMIZED"
            elif "support_" in res_id:
                sys_id = "support_platform"
                if "marker_found=false" in full_text or (uids and "rows=1" in full_text):
                    state = "PRESENT"
                elif ("requester_name=null" in full_text and "requester_email=null" in full_text and "requester_phone=null" in full_text) or \
                   (not uids and merged.get("requester_name") is None and merged.get("requester_email") is None and merged.get("requester_phone") is None and "message_read" not in full_text):
                    state = "REDACTED"
                if "[REDACTED]" in full_text:
                    state = "REDACTED"
            elif "audit_record_" in res_id:
                sys_id = "security_service"
                state = "PRESENT"
            elif "data_flow_" in res_id:
                sys_id = "integration_service"
            elif "backup_" in res_id:
                sys_id = "backup_service"
            elif "search_" in res_id:
                sys_id = "search_service"
            elif "account_" in res_id:
                sys_id = "account_service"
            elif "tombstone_" in res_id:
                sys_id = "identity_service"
                if any(merged.get(k) for k in ["name", "email", "phone", "email_hash"]):
                    state = "PRESENT"
                else:
                    state = "REDACTED"

            cat = "USER_PROFILE"
            if "analytics_" in res_id:
                if "email_opt_in" in full_text or "marketing" in full_text or merged.get("email_opt_in") is not None:
                    cat = "MARKETING_PROFILE"
                else:
                    cat = "ANALYTICS_PROFILE"
            elif "search_" in res_id:
                cat = "SEARCH_INDEX_ENTRY"
            elif "audit_record_" in res_id:
                cat = "SECURITY_AUDIT_LOG"
            elif "data_flow_" in res_id:
                cat = "DATA_FLOW"
            elif "backup_" in res_id:
                cat = "BACKUP_ARCHIVE"
            elif "support_" in res_id:
                if "attachment" in full_text or "preview" in full_text:
                    cat = "SUPPORT_ATTACHMENT"
                else:
                    cat = "SUPPORT_MESSAGE"
            elif "tombstone_" in res_id:
                cat = "ACCOUNT_TOMBSTONE"

            recs.append(EvidenceRecord(
                evidence_id=ev_id,
                file_path=file_path,
                captured_at=captured_at,
                system_id=sys_id,
                resource_id=res_id,
                data_category=cat,
                state=state,
                user_identifiers=uids,
                details=merged,
            ))

        return recs

    def _parse_pdf(self, ev_id: str, file_path: str, captured_at: str) -> List[EvidenceRecord]:
        recs = []
        if not pypdf or not os.path.exists(file_path):
            return recs

        try:
            reader = pypdf.PdfReader(file_path)
            text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])

            # Extract resource IDs
            res_matches = re.findall(r"\b(account_\w+|search_\w+|support_\w+|analytics_\w+|data_flow_\w+|backup_\w+|audit_record_\w+|export_\w+|tombstone_\w+|object_\w+)\b", text)
            uids = set()
            for m in re.findall(r"\b(user_\w+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", text):
                uids.add(m.lower() if "@" in m else m)

            for res_id in set(res_matches):
                sys_id = "account_service"
                cat = "USER_PROFILE"
                state = "PRESENT"
                if "support_" in res_id or "delivery_correction" in file_path:
                    sys_id = "support_platform"
                    cat = "SUPPORT_ATTACHMENT"
                elif "audit_record_" in res_id or "security_retention" in file_path:
                    sys_id = "security_service"
                    cat = "SECURITY_AUDIT_LOG"
                elif "export_" in res_id:
                    sys_id = "export_service"
                    cat = "USER_EXPORT"

                recs.append(EvidenceRecord(ev_id, file_path, captured_at, sys_id, res_id, cat, state, uids, {"pdf_text_snippet": text[:200]}))
        except Exception:
            pass

        return recs
