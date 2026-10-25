"""Policy evaluation engine.

Applies dataset/deletion_rules.csv to map resources and their observed states
to required policy actions, findings, remediation, and verification checks.
"""

from typing import Dict, Optional, Tuple


class PolicyEngine:
    @staticmethod
    def evaluate_resource_treatment(
        system_id: str,
        resource_id: str,
        data_category: str,
        observed_state: str,
        workflow_operation: Optional[str] = None,
    ) -> Dict:
        """Determines compliance, finding operation, remediation operation, and verification operation.

        Returns a dict:
        {
            "is_compliant": bool,
            "finding_op": str or None,
            "finding_state": str or None,
            "remediation_op": str or None,
            "remediation_state": str or None,
            "verification_op": str,
            "verification_state": str,
        }
        """
        # 1. ACCOUNT_SERVICE (USER_PROFILE)
        if system_id == "account_service" or "account_" in resource_id:
            if observed_state == "ABSENT":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_REMAINING_RECORD",
                    "finding_state": "PRESENT",
                    "remediation_op": "DELETE_RECORD",
                    "remediation_state": "ABSENT",
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }

        # 2. SEARCH_SERVICE (SEARCH_INDEX_ENTRY)
        elif system_id == "search_service" or "search_" in resource_id:
            if observed_state == "ABSENT":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_REMAINING_RECORD",
                    "finding_state": "PRESENT",
                    "remediation_op": "DELETE_RECORD",
                    "remediation_state": "ABSENT",
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }

        # 3. EXPORT_SERVICE (USER_EXPORT)
        elif system_id == "export_service" or "export_" in resource_id:
            if observed_state == "ABSENT":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_REMAINING_RECORD",
                    "finding_state": "PRESENT",
                    "remediation_op": "DELETE_RECORD",
                    "remediation_state": "ABSENT",
                    "verification_op": "VERIFY_RECORD_ABSENT",
                    "verification_state": "ABSENT",
                }

        # 4. SUPPORT_PLATFORM
        elif system_id == "support_platform" or "support_" in resource_id:
            # Check if it's an attachment vs a conversation message
            if data_category == "SUPPORT_ATTACHMENT" or workflow_operation == "DELETE_RECORD":
                if observed_state == "ABSENT":
                    return {
                        "is_compliant": True,
                        "finding_op": None,
                        "finding_state": None,
                        "remediation_op": None,
                        "remediation_state": None,
                        "verification_op": "VERIFY_RECORD_ABSENT",
                        "verification_state": "ABSENT",
                    }
                else:
                    return {
                        "is_compliant": False,
                        "finding_op": "REPORT_REMAINING_RECORD",
                        "finding_state": "PRESENT",
                        "remediation_op": "DELETE_RECORD",
                        "remediation_state": "ABSENT",
                        "verification_op": "VERIFY_RECORD_ABSENT",
                        "verification_state": "ABSENT",
                    }
            else:  # SUPPORT_MESSAGE (Redact)
                if observed_state == "REDACTED":
                    return {
                        "is_compliant": True,
                        "finding_op": None,
                        "finding_state": None,
                        "remediation_op": None,
                        "remediation_state": None,
                        "verification_op": "VERIFY_RECORD_REDACTED",
                        "verification_state": "REDACTED",
                    }
                elif observed_state == "ABSENT":
                    return {
                        "is_compliant": True,
                        "finding_op": None,
                        "finding_state": None,
                        "remediation_op": None,
                        "remediation_state": None,
                        "verification_op": "VERIFY_RECORD_ABSENT",
                        "verification_state": "ABSENT",
                    }
                else:  # Exposed PII
                    return {
                        "is_compliant": False,
                        "finding_op": "REPORT_EXPOSED_PII",
                        "finding_state": "PRESENT",
                        "remediation_op": "REDACT_RECORD",
                        "remediation_state": "REDACTED",
                        "verification_op": "VERIFY_RECORD_REDACTED",
                        "verification_state": "REDACTED",
                    }

        # 5. ANALYTICS_PLATFORM (ANALYTICS_PROFILE or MARKETING_PROFILE)
        elif system_id == "analytics_platform" or "analytics_" in resource_id:
            # Special case: if workflow attempted DELETE_RECORD or data_category is MARKETING_PROFILE
            if workflow_operation == "DELETE_RECORD" or data_category == "MARKETING_PROFILE":
                if observed_state == "ABSENT":
                    return {
                        "is_compliant": True,
                        "finding_op": None,
                        "finding_state": None,
                        "remediation_op": None,
                        "remediation_state": None,
                        "verification_op": "VERIFY_RECORD_ABSENT",
                        "verification_state": "ABSENT",
                    }
                else:
                    return {
                        "is_compliant": False,
                        "finding_op": "REPORT_REMAINING_RECORD",
                        "finding_state": "PRESENT",
                        "remediation_op": "DELETE_RECORD",
                        "remediation_state": "ABSENT",
                        "verification_op": "VERIFY_RECORD_ABSENT",
                        "verification_state": "ABSENT",
                    }
            else:  # Anonymize
                if observed_state == "ANONYMIZED":
                    return {
                        "is_compliant": True,
                        "finding_op": None,
                        "finding_state": None,
                        "remediation_op": None,
                        "remediation_state": None,
                        "verification_op": "VERIFY_RECORD_ANONYMIZED",
                        "verification_state": "ANONYMIZED",
                    }
                else:
                    return {
                        "is_compliant": False,
                        "finding_op": "REPORT_EXPOSED_PII",
                        "finding_state": "PRESENT",
                        "remediation_op": "ANONYMIZE_RECORD",
                        "remediation_state": "ANONYMIZED",
                        "verification_op": "VERIFY_RECORD_ANONYMIZED",
                        "verification_state": "ANONYMIZED",
                    }

        # 6. INTEGRATION_SERVICE (DATA_FLOW)
        elif system_id == "integration_service" or "data_flow_" in resource_id:
            if observed_state == "DISABLED":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_DATA_FLOW_DISABLED",
                    "verification_state": "DISABLED",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_ACTIVE_DATA_FLOW",
                    "finding_state": "ACTIVE",
                    "remediation_op": "DISABLE_DATA_FLOW",
                    "remediation_state": "DISABLED",
                    "verification_op": "VERIFY_DATA_FLOW_DISABLED",
                    "verification_state": "DISABLED",
                }

        # 7. BACKUP_SERVICE (BACKUP_ARCHIVE)
        elif system_id == "backup_service" or "backup_" in resource_id:
            if observed_state == "BLOCKED":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_RESTORE_BLOCKED",
                    "verification_state": "BLOCKED",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_RESTORE_RISK",
                    "finding_state": "ACTIVE",
                    "remediation_op": "BLOCK_RESTORE",
                    "remediation_state": "BLOCKED",
                    "verification_op": "VERIFY_RESTORE_BLOCKED",
                    "verification_state": "BLOCKED",
                }

        # 8. IDENTITY_SERVICE (ACCOUNT_TOMBSTONE)
        elif system_id == "identity_service" or "tombstone_" in resource_id:
            if observed_state == "REDACTED":
                return {
                    "is_compliant": True,
                    "finding_op": None,
                    "finding_state": None,
                    "remediation_op": None,
                    "remediation_state": None,
                    "verification_op": "VERIFY_RECORD_REDACTED",
                    "verification_state": "REDACTED",
                }
            else:
                return {
                    "is_compliant": False,
                    "finding_op": "REPORT_EXPOSED_PII",
                    "finding_state": "PRESENT",
                    "remediation_op": "REDACT_RECORD",
                    "remediation_state": "REDACTED",
                    "verification_op": "VERIFY_RECORD_REDACTED",
                    "verification_state": "REDACTED",
                }

        # 9. SECURITY_SERVICE (SECURITY_AUDIT_LOG)
        elif system_id == "security_service" or "audit_record_" in resource_id:
            return {
                "is_compliant": True,
                "finding_op": None,
                "finding_state": None,
                "remediation_op": None,
                "remediation_state": None,
                "verification_op": "VERIFY_RECORD_PRESENT",
                "verification_state": "PRESENT",
            }

        # Default fallback
        return {
            "is_compliant": observed_state == "ABSENT",
            "finding_op": "REPORT_REMAINING_RECORD" if observed_state != "ABSENT" else None,
            "finding_state": "PRESENT" if observed_state != "ABSENT" else None,
            "remediation_op": "DELETE_RECORD" if observed_state != "ABSENT" else None,
            "remediation_state": "ABSENT" if observed_state != "ABSENT" else None,
            "verification_op": "VERIFY_RECORD_ABSENT",
            "verification_state": "ABSENT",
        }
