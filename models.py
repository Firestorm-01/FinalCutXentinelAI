from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
import uuid
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Domain(str, Enum):
    CODE = "CODE"
    IAC  = "IAC"
    IAM  = "IAM"


class Finding(BaseModel):
    id:          str      = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    domain:      Domain
    severity:    Severity
    title:       str
    description: str
    file:        Optional[str]  = None
    line:        Optional[int]  = None
    rule_id:     Optional[str]  = None
    cwe:         Optional[str]  = None
    fix_hint:    Optional[str]  = None
    fixed_code:  Optional[str]  = None
    raw:         Optional[dict] = None

    model_config = {"use_enum_values": True}


class AttackChain(BaseModel):
    """Links findings across domains into a complete breach path."""
    id:          str     = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title:       str
    risk_score:  int     = Field(ge=0, le=100)
    description: str
    steps:       List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    remediation: str


class ScanResult(BaseModel):
    scan_id:       str           = Field(default_factory=lambda: str(uuid.uuid4()))
    repo:          str
    scanned_at:    str           = Field(default_factory=lambda: datetime.utcnow().isoformat())
    findings:      List[Finding]     = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    stats:         dict              = Field(default_factory=dict)
    repo_path:     Optional[str]     = Field(default=None, exclude=True)  # runtime only, not serialised

    def compute_stats(self):
        from collections import Counter
        sev_counts = Counter(f.severity for f in self.findings)
        dom_counts = Counter(f.domain   for f in self.findings)
        self.stats = {
            "total":    len(self.findings),
            "critical": sev_counts.get(Severity.CRITICAL, 0),
            "high":     sev_counts.get(Severity.HIGH,     0),
            "medium":   sev_counts.get(Severity.MEDIUM,   0),
            "low":      sev_counts.get(Severity.LOW,      0),
            "by_domain": {d.value: dom_counts.get(d, 0) for d in Domain},
            "attack_chains": len(self.attack_chains),
        }
        return self