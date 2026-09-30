"""
Official CVSS v3.1 Base Score Calculator.
Conforms to FIRST.org Common Vulnerability Scoring System v3.1 Specification.
"""

import math
from typing import Dict, Tuple


def roundup(val: float) -> float:
    """CVSS v3.1 Roundup function: rounds up to the next decimal point."""
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


class CvssV31Calculator:
    """
    CVSS v3.1 calculator supporting vector parsing, validation, and score calculation.
    """

    AV_VALUES = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
    AC_VALUES = {'L': 0.77, 'H': 0.44}
    PR_U_VALUES = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    PR_C_VALUES = {'N': 0.85, 'L': 0.68, 'H': 0.50}
    UI_VALUES = {'N': 0.85, 'R': 0.62}
    CIA_VALUES = {'N': 0.0, 'L': 0.22, 'H': 0.56}

    @classmethod
    def parse_vector(cls, vector_str: str) -> Dict[str, str]:
        """Parses a CVSS 3.1 vector string into metric dictionary."""
        metrics = {}
        cleaned = vector_str.strip()
        if cleaned.startswith("CVSS:3.1/"):
            cleaned = cleaned[9:]
        elif cleaned.startswith("CVSS:3.0/"):
            cleaned = cleaned[9:]

        parts = cleaned.split('/')
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                metrics[k.upper()] = v.upper()
        return metrics

    @classmethod
    def calculate_from_metrics(cls, metrics: Dict[str, str]) -> Tuple[float, str, str]:
        """Calculates CVSS 3.1 Base Score, Severity, and Canonical Vector."""
        av = metrics.get('AV', 'N')
        ac = metrics.get('AC', 'L')
        pr = metrics.get('PR', 'N')
        ui = metrics.get('UI', 'N')
        s = metrics.get('S', 'U')
        c = metrics.get('C', 'N')
        i = metrics.get('I', 'N')
        a = metrics.get('A', 'N')

        av_val = cls.AV_VALUES.get(av, 0.85)
        ac_val = cls.AC_VALUES.get(ac, 0.77)
        pr_val = cls.PR_C_VALUES.get(pr, 0.85) if s == 'C' else cls.PR_U_VALUES.get(pr, 0.85)
        ui_val = cls.UI_VALUES.get(ui, 0.85)

        c_val = cls.CIA_VALUES.get(c, 0.0)
        i_val = cls.CIA_VALUES.get(i, 0.0)
        a_val = cls.CIA_VALUES.get(a, 0.0)

        # Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # Impact
        if s == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

        # Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if s == 'U':
                base_score = roundup(min(impact + exploitability, 10.0))
            else:
                base_score = roundup(min(1.08 * (impact + exploitability), 10.0))

        # Severity
        if base_score == 0.0:
            severity = "NONE"
        elif base_score <= 3.9:
            severity = "LOW"
        elif base_score <= 6.9:
            severity = "MEDIUM"
        elif base_score <= 8.9:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        canonical_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return base_score, severity, canonical_vector

    @classmethod
    def calculate(cls, vector_str: str) -> Tuple[float, str, str]:
        """Convenience function taking a vector string."""
        metrics = cls.parse_vector(vector_str)
        return cls.calculate_from_metrics(metrics)
