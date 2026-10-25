"""Identity resolution engine.

Reconstructs current and historical identifiers for every user using
dataset/user_identities.csv and dataset/user_audit_log.csv.
"""

import csv
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


@dataclass
class UserProfile:
    user_id: str
    primary_name: str
    primary_email: str
    primary_phone: str
    primary_email_hash: str
    names: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)

    def matches_identifier(self, identifier: Optional[str]) -> bool:
        if not identifier:
            return False
        clean = identifier.strip().lower()
        if clean in self.emails:
            return True
        if clean in self.email_hashes:
            return True
        if identifier.strip() in self.phones:
            return True
        if identifier.strip() == self.user_id:
            return True
        # Also check without country code spaces
        compact_phone = "".join(c for c in identifier if c.isdigit())
        if compact_phone and len(compact_phone) >= 7:
            for p in self.phones:
                p_compact = "".join(c for c in p if c.isdigit())
                if compact_phone in p_compact or p_compact in compact_phone:
                    return True
        return False


class IdentityResolver:
    def __init__(self, identities_csv_path: str, audit_log_csv_path: str):
        self.users_by_id: Dict[str, UserProfile] = {}
        self.email_to_uid: Dict[str, str] = {}
        self._load_identities(identities_csv_path)
        self._load_audit_log(audit_log_csv_path)

    def _load_identities(self, path: str):
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip()
                email = row["email"].strip().lower()
                phone = row["phone"].strip()
                ehash = row["email_hash"].strip().lower()

                profile = UserProfile(
                    user_id=uid,
                    primary_name=name,
                    primary_email=email,
                    primary_phone=phone,
                    primary_email_hash=ehash,
                    names={name},
                    emails={email},
                    phones={phone},
                    email_hashes={ehash},
                )
                self.users_by_id[uid] = profile
                self.email_to_uid[email] = uid

    def _load_audit_log(self, path: str):
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                field_name = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()

                if uid not in self.users_by_id:
                    continue

                profile = self.users_by_id[uid]
                if field_name == "email":
                    if old_val:
                        em_old = old_val.lower()
                        profile.emails.add(em_old)
                        self.email_to_uid[em_old] = uid
                        profile.email_hashes.add(hashlib.sha256(em_old.encode("utf-8")).hexdigest())
                    if new_val:
                        em_new = new_val.lower()
                        profile.emails.add(em_new)
                        self.email_to_uid[em_new] = uid
                        profile.email_hashes.add(hashlib.sha256(em_new.encode("utf-8")).hexdigest())
                elif field_name == "email_hash":
                    if old_val:
                        profile.email_hashes.add(old_val.lower())
                    if new_val:
                        profile.email_hashes.add(new_val.lower())
                elif field_name == "phone":
                    if old_val:
                        profile.phones.add(old_val)
                    if new_val:
                        profile.phones.add(new_val)

    def resolve_by_email(self, email: str) -> Optional[UserProfile]:
        clean = email.strip().lower()
        uid = self.email_to_uid.get(clean)
        if uid:
            return self.users_by_id.get(uid)
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserProfile]:
        return self.users_by_id.get(user_id.strip())
