"""Audit planner and canonical step sequencer.

Orders findings, remediation, and verification steps according to the exact
canonical contract in problem_statement.md and serializes to JSON.
"""

import json
from typing import Dict, List
try:
    from code.config import OPERATION_ORDER, PHASE_FINDING, PHASE_ORDER, PHASE_REMEDIATION, PHASE_VERIFICATION
except ImportError:
    from config import OPERATION_ORDER, PHASE_FINDING, PHASE_ORDER, PHASE_REMEDIATION, PHASE_VERIFICATION


class AuditPlanner:
    @staticmethod
    def sort_and_number_steps(steps: List[Dict]) -> List[Dict]:
        """Sorts steps by:

        1. Phase order (FINDING -> REMEDIATION -> VERIFICATION)
        2. Operation order within phase (table order in problem statement)
        3. system_id ascending
        4. resource_id ascending
        Then re-numbers consecutively from 1.
        """
        def sort_key(s: Dict):
            phase = s["phase"]
            phase_rank = PHASE_ORDER.get(phase, 99)
            op = s["operation"]
            op_rank = OPERATION_ORDER.get(phase, {}).get(op, 99)
            sys_id = s.get("system_id", "")
            res_id = s.get("resource_id", "")
            return (phase_rank, op_rank, sys_id, res_id)

        sorted_steps = sorted(steps, key=sort_key)
        for i, s in enumerate(sorted_steps, 1):
            s["step_no"] = i

        return sorted_steps

    @staticmethod
    def serialize_steps(steps: List[Dict]) -> str:
        """Serializes steps to a compact, valid JSON string."""
        return json.dumps(steps, separators=(",", ":"))
