"""System activity parser.

Parses dataset/system_activity.csv to extract operational claims,
catalog linkages, classification records, and deletion worker execution streams.
"""

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class ActivityRecord:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


class ActivityParser:
    def __init__(self, activity_csv_path: str):
        self.activity_csv_path = activity_csv_path
        self.all_activities: List[ActivityRecord] = []
        self.activities_by_resource: Dict[str, List[ActivityRecord]] = {}
        self.catalog_links: Dict[str, Set[str]] = {}  # resource_id -> set of identifiers (emails, uids)
        self.non_deletion_accounts: Set[str] = set()
        self._load_activities()

    def _load_activities(self):
        with open(self.activity_csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                act = ActivityRecord(
                    activity_id=row["activity_id"].strip(),
                    event_time=row["event_time"].strip(),
                    event_type=row["event_type"].strip(),
                    source_system=row["source_system"].strip(),
                    target_system=row["target_system"].strip(),
                    resource_id=row["resource_id"].strip(),
                    reported_result=row["reported_result"].strip(),
                    details=row["details"].strip(),
                )
                self.all_activities.append(act)
                self.activities_by_resource.setdefault(act.resource_id, []).append(act)

                # Track LINK_RESOURCE_IDENTITY records
                if act.event_type == "LINK_RESOURCE_IDENTITY":
                    idents = set()
                    for m in re.findall(r"\b(user_\w+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", act.details):
                        idents.add(m.lower() if "@" in m else m)
                    if idents:
                        self.catalog_links.setdefault(act.resource_id, set()).update(idents)

                # Track CLASSIFY_REQUEST records
                elif act.event_type == "CLASSIFY_REQUEST":
                    if "non-deletion" in act.details.lower():
                        self.non_deletion_accounts.add(act.resource_id)

    def get_activities_for_resource(self, resource_id: str, before_time: Optional[str] = None) -> List[ActivityRecord]:
        acts = self.activities_by_resource.get(resource_id, [])
        if before_time:
            return [a for a in acts if a.event_time <= before_time]
        return acts

    def get_candidate_activities_for_request(
        self,
        user_id: str,
        requested_at: str,
        reported_at: str,
        candidate_resource_ids: Set[str],
    ) -> List[ActivityRecord]:
        """Correlates deletion worker execution stream with this specific request."""
        # Check direct mentions of user_id in details
        matched_acts = []
        dw_acts = [a for a in self.all_activities if a.source_system == "deletion_worker"]

        # Check if any candidate resources have a deletion_worker activity
        known_times = []
        for res_id in candidate_resource_ids:
            for a in self.activities_by_resource.get(res_id, []):
                if a.source_system == "deletion_worker":
                    if reported_at and a.event_time > reported_at:
                        continue
                    matched_acts.append(a)
                    known_times.append(a.event_time)

        # Look for operations near reported_at
        # If we have candidate_resource_ids, also correlate operations occurring in that same batch
        target_acts = []
        for a in dw_acts:
            # Direct user_id match
            if user_id in a.details:
                target_acts.append(a)
                continue

            # Within window before reported_at
            if reported_at:
                # Compare timestamp string (YYYY-MM-DDTHH:MM:SSZ)
                # Check if same day/hour window
                if a.event_time[:10] == reported_at[:10]:
                    # If nearby known times or within 2 hours of reported_at
                    # Convert to hour/minute comparison
                    try:
                        t_act = a.event_time
                        if a.resource_id in candidate_resource_ids:
                            target_acts.append(a)
                    except Exception:
                        pass

        # De-duplicate
        seen_res = set()
        res_list = []
        for a in matched_acts + target_acts:
            if a.resource_id not in seen_res:
                seen_res.add(a.resource_id)
                res_list.append(a)

        return res_list
