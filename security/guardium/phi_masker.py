"""
IBM Security Guardium Dynamic PHI Masking Engine
------------------------------------------------
Provides role-based automated data masking for Protected Health Information (PHI)
including Social Security Numbers (SSN), clinical diagnosis, psychiatric histories,
prescriptions, and financial identifiers.

Author: Joyline Kamoing (Cybersecurity Track)
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union


# Role permissions for PHI data categories
ROLE_PHI_PERMISSIONS = {
    "physician": {
        "medical_history": True,
        "clinical_notes": True,
        "diagnosis_code": True,
        "prescription": True,
        "ssn": False,          # Minimum necessary: physicians rarely need unmasked full SSN
        "financial": False,
    },
    "nurse": {
        "medical_history": True,
        "clinical_notes": True,
        "diagnosis_code": True,
        "prescription": True,
        "ssn": False,
        "financial": False,
    },
    "billing_clerk": {
        "medical_history": False,  # Masked under HIPAA Minimum Necessary Rule
        "clinical_notes": False,
        "diagnosis_code": False,   # Billing sees sanitized billing codes, not raw clinical text
        "prescription": False,
        "ssn": True,               # Allowed SSN (partial/full for insurance verification)
        "financial": True,
    },
    "pharmacist": {
        "medical_history": False,
        "clinical_notes": False,
        "diagnosis_code": False,
        "prescription": True,
        "ssn": False,
        "financial": False,
    },
    "lab_tech": {
        "medical_history": False,
        "clinical_notes": False,
        "diagnosis_code": False,
        "prescription": False,
        "ssn": False,
        "financial": False,
    },
    "admin": {
        "medical_history": False,  # System admins have no clinical right to see raw medical charts
        "clinical_notes": False,
        "diagnosis_code": False,
        "prescription": False,
        "ssn": True,
        "financial": True,
    },
    "compliance_officer": {
        "medical_history": False,
        "clinical_notes": False,
        "diagnosis_code": False,
        "prescription": False,
        "ssn": True,
        "financial": True,
    }
}


class PHIMasker:
    """Dynamic Data Masking (DDM) engine matching IBM Guardium policy behavior."""

    SSN_REGEX = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")

    @classmethod
    def mask_ssn(cls, ssn_value: Optional[str], role: str) -> Tuple[str, bool]:
        """
        Masks SSN according to role.
        Billing / Compliance get partial mask (***-**-1234).
        Unauthorized roles get full mask (XXX-XX-XXXX).
        """
        if not ssn_value:
            return "XXX-XX-XXXX", True

        clean = re.sub(r"\D", "", str(ssn_value))
        role_perm = ROLE_PHI_PERMISSIONS.get(role.lower(), {}).get("ssn", False)

        if role_perm:
            # Authorized for partial display
            last_4 = clean[-4:] if len(clean) >= 4 else "0000"
            return f"***-**-{last_4}", False
        else:
            # Unauthorized - completely masked
            return "XXX-XX-XXXX", True

    @classmethod
    def mask_medical_history(cls, text: Optional[str], role: str) -> Tuple[str, bool]:
        """
        Masks patient medical history, diagnosis codes, and clinical notes for non-clinical roles.
        """
        if not text:
            return "[NO RECORD]", False

        role_perm = ROLE_PHI_PERMISSIONS.get(role.lower(), {}).get("medical_history", False)
        if role_perm:
            return str(text), False
        else:
            return "[RESTRICTED MEDICAL HISTORY - CLINICAL ROLE REQUIRED]", True

    @classmethod
    def mask_prescription(cls, rx_text: Optional[str], role: str) -> Tuple[str, bool]:
        """
        Masks prescription / DEA controlled substances.
        """
        if not rx_text:
            return "[NO PRESCRIPTION]", False

        role_perm = ROLE_PHI_PERMISSIONS.get(role.lower(), {}).get("prescription", False)
        if role_perm:
            return str(rx_text), False
        else:
            return "[RESTRICTED PRESCRIPTION DATA - AUTHORIZED PHARMACIST/CLINICIAN ONLY]", True

    @classmethod
    def mask_record(cls, record: Dict[str, Any], role: str) -> Tuple[Dict[str, Any], List[str]]:
        """
        Inspects a row/dictionary of patient data and applies dynamic masking in-place.
        Returns (masked_record, list_of_masked_fields).
        """
        masked = dict(record)
        masked_fields: List[str] = []
        role_norm = role.strip().lower() if role else "guest"

        # SSN masking
        for ssn_key in ["ssn", "social_security_number", "tax_id"]:
            if ssn_key in masked and masked[ssn_key]:
                val, was_masked = cls.mask_ssn(masked[ssn_key], role_norm)
                masked[ssn_key] = val
                if was_masked:
                    masked_fields.append(ssn_key)

        # Medical history / clinical notes masking
        for med_key in ["medical_history", "diagnosis", "diagnosis_code", "clinical_notes", "psychiatric_history"]:
            if med_key in masked and masked[med_key]:
                val, was_masked = cls.mask_medical_history(masked[med_key], role_norm)
                masked[med_key] = val
                if was_masked:
                    masked_fields.append(med_key)

        # Prescription masking
        for rx_key in ["prescription", "medications", "rx_details"]:
            if rx_key in masked and masked[rx_key]:
                val, was_masked = cls.mask_prescription(masked[rx_key], role_norm)
                masked[rx_key] = val
                if was_masked:
                    masked_fields.append(rx_key)

        return masked, masked_fields

    @classmethod
    def mask_result_set(cls, rows: List[Dict[str, Any]], role: str) -> Tuple[List[Dict[str, Any]], int]:
        """
        Applies dynamic masking to an entire database result set.
        """
        masked_rows = []
        total_masked_cells = 0
        for row in rows:
            masked_row, fields = cls.mask_record(row, role)
            total_masked_cells += len(fields)
            masked_rows.append(masked_row)
        return masked_rows, total_masked_cells
