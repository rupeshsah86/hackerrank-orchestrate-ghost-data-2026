"""Canonical configuration, operation types, phase mappings, and sorting orders.

Authoritative source: problem_statement.md and AGENTS.md.
"""

from typing import Dict, List, Tuple

# Allowed Phases
PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"

PHASE_ORDER = {
    PHASE_FINDING: 1,
    PHASE_REMEDIATION: 2,
    PHASE_VERIFICATION: 3,
}

# Allowed Operations and their expected states
ALLOWED_OPERATIONS = {
    PHASE_FINDING: {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    PHASE_REMEDIATION: {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    PHASE_VERIFICATION: {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}

# Canonical Operation Sorting Index within each phase
OPERATION_ORDER = {
    PHASE_FINDING: {
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
    },
    PHASE_REMEDIATION: {
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
    },
    PHASE_VERIFICATION: {
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    },
}

# Deletion Status Values
STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Mapping from System ID to canonical service names
SYSTEM_ACCOUNT = "account_service"
SYSTEM_SEARCH = "search_service"
SYSTEM_SUPPORT = "support_platform"
SYSTEM_ANALYTICS = "analytics_platform"
SYSTEM_INTEGRATION = "integration_service"
SYSTEM_BACKUP = "backup_service"
SYSTEM_SECURITY = "security_service"
SYSTEM_IDENTITY = "identity_service"
SYSTEM_EXPORT = "export_service"
SYSTEM_MARKETING = "marketing_platform"

# CSV Field Headers
CSV_HEADER = ["case_id", "deletion_status", "steps_json"]
