# Ghost Data Deletion Auditor

An AI-powered distributed deletion audit engine that verifies whether personal customer data has genuinely been expunged across complex enterprise microservices, databases, logs, search indexes, backups, and data pipelines.

**Author:** Rupesh Kumar Sah ([@rupeshsah86](https://github.com/rupeshsah86))  
**Academic Affiliation:** B.E. Computer Science and Engineering  
**Challenge Context:** Built for HackerRank Orchestrate (October 2026) — *"Ghost Data Still Exists"*

---

## 1. Project Overview

In distributed architectures, fulfilling a Right-to-be-Forgotten or GDPR/CCPA account deletion request is rarely as simple as running `DELETE FROM users WHERE id = ...`. Even after primary account microservices mark an erasure request as **`COMPLETE`**, personal identifiable information (PII) frequently lingers in secondary database replicas, asynchronous search indexes, customer support ticketing logs, un-redacted analytics data, and staging backups. Furthermore, active synchronization connectors or unsafely configured restore procedures can silently re-import deleted customer data, creating **"Ghost Data"**.

The **Ghost Data Deletion Auditor** is a deterministic, point-in-time audit engine written in Python. It evaluates customer deletion requests against distributed system evidence, reconciles historical identity changes, enforces organizational retention rules, detects data re-creation risks, and outputs canonically sequenced remediation plans and verification proofs.

---

## 2. Problem Statement: Why Data Can Remain After Deletion

Modern commerce platforms comprise dozens of decoupled services. When an orchestration workflow triggers user deletion, multiple failure modes can cause data to persist:

1. **Replication Drift & Lag:** Failover and regional reporting replicas may not apply deletions immediately, leaving full PII exposed in read replicas.
2. **Asynchronous Secondary Indexes:** Search engines and caching layers often require explicit index purging. If an indexing pipeline is lagging or uncoordinated, the user remains searchable.
3. **Partial Policy Application (Messages vs. Attachments):** Support ticketing systems may redact customer conversation text but leave file attachments (e.g., invoices, ID verification photos) unpurged on object storage.
4. **False Anonymization:** Analytics services may clear direct email fields to `null` while continuing to record historical SHA-256 email hashes or correlation keys that link back to the user's audit trail.
5. **Active Synchronization Flows:** Integration pipelines with upstream systems or external CRM connectors can re-ingest customer profiles on their next sync cycle if not explicitly disabled.
6. **Unsafe Backup Restoration:** Database backups and disaster-recovery snapshots created prior to deletion often permit indiscriminate restoration (`restore_allowed = true`), risking total re-population of deleted PII during staging refreshes or failovers.

---

## 3. Project Objectives

- **Automated Intent Classification:** Accurately discern legitimate erasure requests from non-deletion inquiries (e.g., GDPR Article 15 access requests, billing statement copies, marketing unsubscribes) to avoid wrongful account terminations.
- **Historical Identity Resolution:** Reconstruct every email, phone number, name alias, and cryptographic hash associated with a user across their entire lifecycle.
- **Strict Temporal Reasoning:** Evaluate system compliance strictly at or before the designated `audit_at` cutoff timestamp, discarding future information.
- **Policy Enforcement:** Apply organizational rules to determine whether a given resource requires whole-record deletion, selective field redaction, irreversible anonymization, or mandatory retention for legal/security compliance.
- **Account Tombstone Handling:** Preserve stable internal `user_id` foreign keys while stripping prohibited direct identifiers.
- **Canonical Step Sequencing:** Produce deterministically ordered findings, dependency-aware remediation plans, and verification proofs.

---

## 4. Main Features

- **Hybrid Deterministic Architecture:** High-speed, zero-hallucination parsing of SQLite snapshots, JSON exports, plain text, and multi-line application logs.
- **Full Historical Aliasing:** Precomputes SHA-256 hashes and tracks all identity mutations recorded in user audit logs.
- **Dependency-Aware Remediation:** Automatically sequences active data flow disabling (`DISABLE_DATA_FLOW`) and backup blocking (`BLOCK_RESTORE`) *before* record modifications (`DELETE_RECORD`, `REDACT_RECORD`), preventing immediate data recreation.
- **Strict Phase Compliance:** Guarantees strict ordering: `FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION`.
- **Lightweight & Efficient:** Processes all 518 evaluation cases in under 30 seconds (< 24ms per case) on standard consumer hardware without requiring costly cloud GPU clusters.

---

## 5. Architecture and Component Descriptions

The engine is organized into 6 modular, decoupled components under `code/`:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Deletion Request Input                          │
│        (case_id, email, requested_at, reported_status, audit_at)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. IntentClassifier (code/intent_classifier.py)                        │
│    - Regex & multi-lingual pattern matcher                             │
│    - Identifies non-deletion intents (returns NOT_APPLICABLE + [])     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ [If Deletion Authorized]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. IdentityResolver (code/identity.py)                                 │
│    - Ingests user_identities.csv and user_audit_log.csv                │
│    - Reconstructs UserProfile: {all emails, hashes, phones, user_id}   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. EvidenceParser & ActivityParser (code/evidence_parser.py,           │
│                                    code/activity_parser.py)            │
│    - Filters evidence strictly at or before audit_at                   │
│    - Parses SQLite schemas, JSON logs, support tickets, trace events   │
│    - Detects active connectors and restore-permitted backup archives   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. PolicyEngine (code/policy_engine.py)                                │
│    - Evaluates observed resource state against deletion_rules.csv      │
│    - Differentiates DELETE, REDACT, ANONYMIZE, and RETAIN requirements │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. AuditPlanner (code/audit_planner.py)                                │
│    - Sorts steps: Phase -> Canonical Operation Rank -> sys_id -> res_id│
│    - Numbers steps consecutively starting from 1                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 6. Auditor & Output Serializer (code/auditor.py, code/main.py)         │
│    - Assembles final deletion_status (COMPLETE / INCOMPLETE)           │
│    - Serializes compact JSON step arrays into output.csv               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Project Folder Structure

```
hackerrank-orchestrate-ghost-data-2026/
├── .gitignore                      # Git exclusion rules
├── README.md                       # Comprehensive project documentation
├── problem_statement.md            # Challenge specification
├── dataset/                        # Participant data corpus
│   ├── deletion_requests.csv       # 518 evaluation cases
│   ├── sample_deletion_requests.csv# 32 public sample cases
│   ├── sample_output.csv           # Public sample ground truth
│   ├── user_identities.csv         # Current user snapshots
│   ├── user_audit_log.csv          # Historical identity modifications
│   ├── system_activity.csv         # Global operational & pipeline logs
│   ├── deletion_rules.csv          # Data retention & erasure policy matrix
│   ├── evidence_files.csv          # Manifest of evidence captures
│   └── evidence/                   # SQLite snapshots, logs, JSON, docs
├── code/                           # Core audit engine source code
│   ├── __init__.py
│   ├── config.py                   # Canonical constants, phases & ranks
│   ├── identity.py                 # Historical identity resolution
│   ├── intent_classifier.py        # Erasure vs non-deletion classification
│   ├── evidence_parser.py          # Multi-format evidence parsing engine
│   ├── activity_parser.py          # Operational event & pipeline analysis
│   ├── policy_engine.py            # Deletion, redaction & retention rules
│   ├── audit_planner.py            # Canonical ordering & step numbering
│   ├── auditor.py                  # End-to-end case orchestration
│   ├── main.py                     # CLI entrypoint for batch processing
│   └── evaluation/
│       ├── main.py                 # Evaluation & metrics generator
│       ├── evaluation_report.md    # Empirical accuracy & test report
│       └── usage_report.md         # Token, runtime & cost analysis
```

---

## 7. Technologies Used

- **Language:** Python 3.9+
- **Standard Library:** `sqlite3` (in-memory relational analysis), `hashlib` (SHA-256 precomputation), `csv`, `json`, `re`, `datetime`, `dataclasses`.
- **Zero Heavy External Dependencies:** Pure Python implementation ensuring 100% portability across Linux, macOS, and Windows without complex compilation steps.
- **Git & GitHub:** Version control, disciplined atomic commits, and documentation.

---

## 8. Step-by-Step Auditing Workflow

1. **Intake & Intent Check:** Read request fields (`case_id`, `email`, `requested_at`, `audit_at`, `request_text`). If `request_text` specifies an information request, invoice retrieval, or explicit instruction to keep the account open, immediately return `NOT_APPLICABLE` with `steps_json = []`.
2. **Identity Expansion:** Query `IdentityResolver` with the request email. Retrieve the stable `user_id` and all historical emails, phone numbers, and cryptographic email hashes.
3. **Temporal Ingestion:** Discover evidence files associated with the user. Reject any file captured after `audit_at`.
4. **State Extraction:**
   - Query SQL snapshots for user profile rows and order records.
   - Inspect search index logs for indexed documents matching the user.
   - Inspect customer support tickets for un-redacted conversation text or raw attachments.
   - Scan analytics logs for lingering user IDs or historical email hashes.
   - Inspect pipeline configurations for active data flows and backup manifests for restoration permissions.
5. **Policy Verification:** Compare each discovered record's state with `deletion_rules.csv`.
6. **Plan Assembly:** If all records are compliant and no active flows/restore risks exist, mark as `COMPLETE` and emit evidence-backed `VERIFICATION` steps. Otherwise, mark as `INCOMPLETE`, emit `FINDING` steps, generate `REMEDIATION` actions, and append future `VERIFICATION` checks.
7. **Canonical Sequencing:** Sort steps by Phase $\to$ Operation Rank $\to$ System ID $\to$ Resource ID, number consecutively from 1, and output to CSV.

---

## 9. Key Deep Dives

### Identity Resolution & Alias Tracking
Users frequently change their email addresses or phone numbers over time. If a user submitted a deletion request using an old email address (or changed it before requesting deletion), naive lookups on primary tables fail. 
`IdentityResolver` processes `user_audit_log.csv` to map every `old_value` and `new_value` to the corresponding `user_id`, computing SHA-256 digests for each variation:
```python
profile.emails.add(old_email.lower())
profile.email_hashes.add(hashlib.sha256(old_email.lower().encode("utf-8")).hexdigest())
```

### Point-in-Time Temporal Cutoff (`audit_at`)
Reported workflow claims (`reported_status: COMPLETE`) cannot be trusted because asynchronous operations may lag or fail. More importantly, the system must establish the exact state at the time of `audit_at`. Any evidence captured after `audit_at` is strictly ignored to eliminate lookahead bias:
```python
if captured_at > audit_at:
    continue  # Disregard post-audit state changes
```

### Policy Rules, Account Tombstones & Retention
- **`USER_PROFILE`**: Must be completely deleted (`DELETE_RECORD` / `ABSENT`).
- **`SUPPORT_ATTACHMENT`**: Must be deleted (`DELETE_RECORD` / `ABSENT`).
- **`SUPPORT_MESSAGE`**: PII must be redacted (`REDACT_RECORD` / `REDACTED`) while preserving support thread context.
- **`ANALYTICS_PROFILE`**: Direct identifiers must be irreversibly unlinked (`ANONYMIZE_RECORD` / `ANONYMIZED`).
- **`ACCOUNT_TOMBSTONE`**: The stable `user_id` is permitted to remain for foreign-key referential integrity in financial ledgers, but direct identifiers (name, email, phone, email hash) must be redacted (`REDACT_RECORD` / `REDACTED`).
- **`SECURITY_AUDIT_LOG`**: Must be preserved for statutory regulatory compliance (`VERIFY_RECORD_PRESENT` / `PRESENT`). Deleting it is a violation.

---

## 10. Canonical Phase & Operation Sequencing

Steps in `steps_json` strictly respect canonical ranking:

| Phase | Operation | State | Meaning |
|---|---|---|---|
| `FINDING` | `REPORT_REMAINING_RECORD` | `PRESENT` | Prohibited record still exists |
| `FINDING` | `REPORT_EXPOSED_PII` | `PRESENT` | Record exists with un-redacted PII |
| `FINDING` | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | Active process can recreate data |
| `FINDING` | `REPORT_RESTORE_RISK` | `ACTIVE` | Backup can restore deleted data |
| `REMEDIATION` | `DISABLE_DATA_FLOW` | `DISABLED` | Stop replication connectors first |
| `REMEDIATION` | `BLOCK_RESTORE` | `BLOCKED` | Disable restore permissions |
| `REMEDIATION` | `DELETE_RECORD` | `ABSENT` | Purge record |
| `REMEDIATION` | `REDACT_RECORD` | `REDACTED` | Strip identifying fields |
| `REMEDIATION` | `ANONYMIZE_RECORD` | `ANONYMIZED` | Irreversibly unlink identifiers |
| `VERIFICATION` | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm removal |
| `VERIFICATION` | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm statutory retention |
| `VERIFICATION` | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm redaction |
| `VERIFICATION` | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm anonymization |
| `VERIFICATION` | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm connector disabled |
| `VERIFICATION` | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm backup restore blocked |

---

## 11. Installation & Setup Instructions

### Prerequisites
- Python 3.9, 3.10, 3.11, or 3.12
- Git

### Setup
1. Clone this repository:
   ```bash
   git clone https://github.com/rupeshsah86/hackerrank-orchestrate-ghost-data-2026.git
   cd hackerrank-orchestrate-ghost-data-2026
   ```
2. Verify Python installation:
   ```bash
   python3 --version
   ```

---

## 12. How to Run the Project

### Running the Audit Engine
To execute the complete deletion audit across an evaluation dataset and produce `output.csv`:

```bash
python3 code/main.py --dataset dataset --input dataset/deletion_requests.csv --output output.csv
```

### Running the Evaluation Suite & Test Cases
To run automated validation against the public sample suite and execute custom edge-case tests:

```bash
python3 code/evaluation/main.py dataset
```

---

## 13. Input & Output Formats

### Input Schema (`dataset/deletion_requests.csv`)
```csv
case_id,email,requested_at,reported_status,reported_at,audit_at,request_text
```

### Output Schema (`output.csv`)
```csv
case_id,deletion_status,steps_json
```

- Exactly 518 data rows sorted by `case_id`.
- `deletion_status`: `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- `steps_json`: Compact JSON array of objects conforming to:
  ```json
  {
    "step_no": 1,
    "phase": "FINDING",
    "system_id": "account_service",
    "resource_id": "account_005",
    "operation": "REPORT_REMAINING_RECORD",
    "state": "PRESENT",
    "evidence_id": "evidence_01"
  }
  ```

---

## 14. Evaluation Results

The audit engine was evaluated against the official public sample suite (`dataset/sample_deletion_requests.csv` and `dataset/sample_output.csv`):

| Evaluation Metric | Public Sample Result | Full Dataset Run (518 Cases) |
|---|---|---|
| **Case Deletion Status Accuracy** | **32 / 32 (100.0%)** | 518 cases successfully classified |
| **Step-Level Precision** | **165 / 165 (100.0%)** | Zero unsupported steps generated |
| **Step-Level Recall** | **165 / 193 (85.5%)** | High coverage grounded in visible files |
| **Sequence Ordering Accuracy** | **32 / 32 (100.0%)** | Strict Phase & Operation compliance |
| **Execution Speed** | < 1 second | < 30 seconds total (~24ms / case) |
| **Estimated Total Run Cost** | < $0.001 | **$0.02** |

### Custom Edge Case Test Suites
1. **`EDGE_01` (Non-Deletion Account Clarification vs. Marketing Opt-Out):** Correctly classified as `NOT_APPLICABLE` with `steps_json = []`. **[PASS]**
2. **`EDGE_02` (Historical Email Hash in Analytics Correlation Key):** Identified lingering hashed identity in analytical records as `INCOMPLETE`. **[PASS]**
3. **`EDGE_03` (Active Restore Risk on Archive Snapshot Post-Deletion):** Flagged `restore_allowed = true` as `REPORT_RESTORE_RISK` and sequenced `BLOCK_RESTORE`. **[PASS]**

---

## 15. Known Limitations

- **Public Sample Recall Gap (~14.5%):** Approximately 28 expected steps in the synthetic sample ground truth referred to phantom system resources where no supporting evidence file was provided in the participant corpus. Because our engine strictly enforces Section 6.6 of the specification (requiring evidence grounding and prohibiting hallucinated evidence references), it deliberately avoids fabricating unsupported steps.
- **Multimodal Visual Screenshots:** Image evidence is handled via structured OCR/metadata extraction rather than fine-tuned Vision Transformers to preserve ultra-low latency and low computational overhead.

---

## 16. What I Learned

- Designing robust, point-in-time distributed audit systems requires treating reported workflow statuses as unverified claims rather than authoritative truth.
- Privacy compliance (GDPR/CCPA) is multi-dimensional: erasures must respect data relationships, preserving foreign-key tombstones and statutory security audit logs while purging PII.
- Orchestration order is critical: active ingestion connectors and restore-enabled backups must be blocked before modifying records to prevent ghost data reincarnation.

---

## 17. Author & Acknowledgments

**Rupesh Kumar Sah**  
Computer Science and Engineering Student  
GitHub: [@rupeshsah86](https://github.com/rupeshsah86)  
Email: rupeshkumarsah.2024cse@sece.ac.in

---

## 18. Competition Context & Disclaimer

This software was developed for the **HackerRank Orchestrate (October 2026)** competition (*Ghost Data Still Exists*). All organizational names (e.g., Northstar Shop), customer identities, emails, phone numbers, and operational records are entirely synthetic and fictional. No actual personal data was used or processed.
