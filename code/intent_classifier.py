"""Deletion intent classification engine.

Determines whether a user request authorizes account deletion or is NOT_APPLICABLE
(e.g., access, export, rectification/correction, marketing opt-out, or instructions
to keep the account open).
"""

import re


class IntentClassifier:
    NON_DELETION_PATTERNS = [
        r"\bleave\s+the\s+account\s+active\b",
        r"\bkeep\s+the\s+account\b",
        r"\bdo\s+not\s+close\s+the\s+account\b",
        r"\bdon'?t\s+close\s+the\s+account\b",
        r"\bnot\s+asking\s+for\s+deletion\b",
        r"\bwithout\s+removing\s+any\b",
        r"\bremove\s+me\s+from\s+marketing\s+lists\b",
        r"\bthis\s+is\s+an\s+information\s+request,\s+not\s+a\s+request\s+to\s+erase\b",
        r"\bleave\s+my\s+profile\s+and\s+purchase\s+history\s+in\s+place\b",
        r"\bi\s+want\s+to\s+continue\s+using\s+the\s+service\b",
        r"\bplease\s+don'?t\s+delete\s+or\s+change\s+anything\b",
        r"\bdownload\s+my\s+account\s+information\b",
        r"\bhelp\s+resetting\s+the\s+login\b",
        r"\bcopy\s+of\s+last\s+year'?s\s+invoices\b",
        r"\bcopy\s+of\s+the\s+information\s+held\b",
    ]

    DELETION_KEYWORDS = [
        "delet",
        "remov",
        "eras",
        "close",
        "clean",
        "purg",
        "wipe",
        "supprim",
        "suppress",
        "elimin",
        "exclu",
        "gone",
        "destroy",
        "cancel my account",
        "termination",
        "terminate",
        "anonymiz",
        "forget",
        "gdpr",
        "privacy request",
        "right to be forgotten",
        "삭제",
        "削除",
    ]

    @classmethod
    def classify(cls, request_text: str) -> bool:
        return cls.is_deletion_authorized(request_text)

    @classmethod
    def is_deletion_authorized(cls, request_text: str) -> bool:
        """Returns True if the request authorizes account/data deletion, False if NOT_APPLICABLE."""
        if not request_text:
            return False

        lower = request_text.lower()

        # Check explicit non-deletion expressions first
        for pat in cls.NON_DELETION_PATTERNS:
            if re.search(pat, lower):
                return False

        # Check for presence of deletion authorization keywords across languages
        for kw in cls.DELETION_KEYWORDS:
            if kw in lower:
                return True

        return False
