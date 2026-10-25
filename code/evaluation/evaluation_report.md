# Deletion Audit Agent Evaluation Report

## 1. Executive Summary

This report presents the empirical evaluation of the AI-powered deletion-audit agent for the HackerRank Orchestrate (October 2026) challenge: **Ghost Data Still Exists**.

- **Total Public Sample Cases Evaluated**: 32
- **Case-Level Deletion Status Accuracy**: **32/32 (100.0%)**
- **Step-Level Precision**: **100.0%** (165/165 generated steps matched)
- **Step-Level Recall**: **85.5%** (165/193 expected steps matched)
- **Sequence Ordering Accuracy**: **100.0%** (strict compliance with FINDING -> REMEDIATION -> VERIFICATION phase structure)

## 2. Field-Level Accuracy

| Field | Accuracy |
|---|---|
| `phase` | 100.0% |
| `system_id` | 77.0% |
| `resource_id` | 77.0% |
| `operation` | 81.2% |
| `state` | 81.2% |
| `evidence_id` | 99.4% |

## 3. Custom Evaluation Cases

Three challenging edge cases were created to evaluate domain boundaries, multi-system dependencies, and point-in-time reasoning:

### Case EDGE_01: Non-Deletion Account Clarification vs Marketing Unsubscribe [PASS]

- **Description**: User requests a copy of previous billing statements and asks to stop newsletters, explicitly requesting that the account remains open. Tests that intent classifier categorizes this as NOT_APPLICABLE and generates empty steps_json.
- **Expected Status**: `NOT_APPLICABLE`
- **Actual Status**: `NOT_APPLICABLE`
- **Generated Steps Count**: 0
- **Validation Result**: **PASS**

### Case EDGE_02: Historical Email Hash in Analytics Correlation Key [PASS]

- **Description**: User previously changed email address. Analytics log entry contains correlation_key matching SHA-256 hash of historical email. Tests historical identity resolution and detection of un-anonymized analytical records.
- **Expected Status**: `INCOMPLETE`
- **Actual Status**: `INCOMPLETE`
- **Generated Steps Count**: 5
- **Validation Result**: **PASS**

### Case EDGE_03: Active Restore Risk on Archive Snapshot Post-Deletion [PASS]

- **Description**: Primary user profile and support tickets were successfully cleared, but backup archive retains restore_allowed=true. Tests detection of restore risk (REPORT_RESTORE_RISK) and safe ordered remediation (BLOCK_RESTORE before verification).
- **Expected Status**: `INCOMPLETE`
- **Actual Status**: `INCOMPLETE`
- **Generated Steps Count**: 3
- **Validation Result**: **PASS**

## 4. Failure Analysis and Systemic Improvements

During incremental testing against the public sample suite, several key challenges were identified and addressed in the core audit engine:

1. **Replication Drift and False Anonymization**:
   - *Issue*: Analytical log lines contained anonymized `email=null` but preserved historical email hashes in `correlation_key`.
   - *Fix*: The log parser was enhanced to correlate `correlation_key` against all historical email hashes recovered via `IdentityResolver`.

2. **Point-in-Time Temporal Reasoning**:
   - *Issue*: Snapshots taken after `audit_at` cannot be used to prove the state at audit time.
   - *Fix*: Strict temporal filtering was implemented across all evidence loaders, ensuring only artifacts captured at or before `audit_at` support findings and compliant verifications.

3. **Multi-Line Log Tracing**:
   - *Issue*: Systems emitting separate log entries for query start and query completion caused detached resource IDs.
   - *Fix*: Grouped log events by `trace_id` and `requestId` to reconstruct atomic multi-line transactions.

4. **Restoration Risks and Active Data Flows**:
   - *Issue*: Backups with `restore_allowed=true` and sync connectors with `enabled=true` can recreate deleted data.
   - *Fix*: Added deep inspection of backup manifest flags and sync connector status, generating prerequisite `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` remediation steps.
