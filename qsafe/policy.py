"""Trust policy: when is each algorithm considered broken?

Real deployments would take this from a national authority (e.g. a list
published by NIST or CERT-In). The policy also says how many independent
timestamp authorities must agree. Here it is a simple table so we can simulate
future algorithm breaks such as "ECDSA falls to a quantum computer in 2045".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class TrustPolicy:
    broken_at: dict[str, date] = field(default_factory=dict)
    # How many DIFFERENT timestamp authorities must validly sign each evidence link.
    # 1 trusts a single authority completely; 2 of 3 survives one compromised authority.
    tsa_threshold: int = 1

    def mark_broken(self, algorithm: str, when: date) -> None:
        self.broken_at[algorithm] = when

    def trusted_at(self, algorithm: str, when: date) -> bool:
        """True if `algorithm` was still secure on date `when`."""
        broken = self.broken_at.get(algorithm)
        return broken is None or when < broken
