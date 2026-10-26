"""SOC 2 controls that cannot be verified from AWS APIs.

Most of a SOC 2 audit is people and process. These rows go into the workbook so the
team can assign an owner and attach evidence alongside the automated results.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ManualControl:
    id: str
    criterion: str
    control: str
    evidence: str
    frequency: str


MANUAL_CONTROLS: list[ManualControl] = [
    ManualControl("MC-01", "CC1.1", "Employees acknowledge a code of conduct",
                  "Signed acknowledgements for every employee in the period", "At hire, annually"),
    ManualControl("MC-02", "CC1.3", "Security roles and responsibilities are assigned",
                  "Org chart; named security owner; job descriptions", "Annually"),
    ManualControl("MC-03", "CC1.4", "Background checks are performed for new hires",
                  "Background check completion records for a sample of hires", "At hire"),
    ManualControl("MC-04", "CC2.2", "Security awareness training is completed",
                  "Training completion report for all staff", "At hire, annually"),
    ManualControl("MC-05", "CC2.3", "Security commitments are communicated to customers",
                  "Public security page, terms of service, DPA", "Ongoing"),
    ManualControl("MC-06", "CC3.1", "A formal risk assessment is performed",
                  "Risk register with likelihood, impact, owner and treatment", "Annually"),
    ManualControl("MC-07", "CC4.1", "Control effectiveness is reviewed by management",
                  "Meeting notes or sign-off on this workbook's results", "Quarterly"),
    ManualControl("MC-08", "CC5.3", "Information security policies are approved and published",
                  "Approved policy set (access, change, IR, data retention, vendor) with version history", "Annually"),
    ManualControl("MC-09", "CC6.2", "Access is provisioned through an approved request",
                  "Access request tickets with approver for a sample of grants", "Per request"),
    ManualControl("MC-10", "CC6.2", "User access reviews are performed",
                  "Reviewed list of AWS, IdP and production-system users with sign-off", "Quarterly"),
    ManualControl("MC-11", "CC6.3", "Access is removed promptly at termination",
                  "Offboarding tickets showing removal within 24-72 hours", "Per termination"),
    ManualControl("MC-12", "CC6.4", "Physical security of data centers",
                  "Inherited from AWS: download the AWS SOC 2 report from AWS Artifact", "Annually"),
    ManualControl("MC-13", "CC6.5", "Company devices are wiped before disposal or reuse",
                  "Asset register and disposal certificates", "Per device"),
    ManualControl("MC-14", "CC6.8", "Endpoints run anti-malware and disk encryption",
                  "MDM / EDR compliance report for all laptops", "Monthly"),
    ManualControl("MC-15", "CC7.1", "Vulnerability scanning and patching",
                  "Scan reports and tickets showing remediation within SLA", "Monthly"),
    ManualControl("MC-16", "CC7.3", "An incident response plan exists",
                  "Approved IR plan with roles, severity levels and contacts", "Annually"),
    ManualControl("MC-17", "CC7.4", "Incident response is tested",
                  "Tabletop exercise notes and follow-up actions", "Annually"),
    ManualControl("MC-18", "CC8.1", "Code changes are peer-reviewed before production",
                  "Branch protection settings and a sample of merged PRs with approvals", "Per change"),
    ManualControl("MC-19", "CC9.1", "A business continuity plan exists",
                  "Approved BCP with RTO/RPO targets", "Annually"),
    ManualControl("MC-20", "CC9.2", "Vendors are assessed for security risk",
                  "Vendor inventory with SOC reports or questionnaires for critical vendors", "Annually"),
    ManualControl("MC-21", "A1.3", "Backup restores are tested",
                  "Restore test record showing data recovered within RTO", "Annually"),
    ManualControl("MC-22", "C1.2", "Confidential data is deleted per retention policy",
                  "Retention schedule and deletion logs / tickets", "Per schedule"),
]

# Short descriptions of the Trust Services Criteria referenced in this kit (AICPA TSC 2017, rev. 2022).
CRITERIA: dict[str, str] = {
    "CC1.1": "Commitment to integrity and ethical values",
    "CC1.3": "Structures, reporting lines and responsibilities",
    "CC1.4": "Commitment to attract and retain competent people",
    "CC2.2": "Internal communication of security responsibilities",
    "CC2.3": "Communication with external parties",
    "CC3.1": "Risk assessment objectives",
    "CC4.1": "Ongoing evaluation of controls",
    "CC5.3": "Policies and procedures",
    "CC6.1": "Logical access security software, infrastructure and architecture",
    "CC6.2": "User registration and authorization",
    "CC6.3": "Role-based access and removal",
    "CC6.4": "Physical access restrictions",
    "CC6.5": "Disposal of assets",
    "CC6.6": "Protection against threats from outside system boundaries",
    "CC6.7": "Restriction of data transmission and movement",
    "CC6.8": "Prevention / detection of unauthorized or malicious software",
    "CC7.1": "Detection of configuration changes and vulnerabilities",
    "CC7.2": "Monitoring of system components for anomalies",
    "CC7.3": "Evaluation of security events",
    "CC7.4": "Incident response",
    "CC8.1": "Change management",
    "CC9.1": "Business disruption risk mitigation",
    "CC9.2": "Vendor and business partner risk",
    "A1.2": "Backup and recovery infrastructure",
    "A1.3": "Recovery plan testing",
    "C1.1": "Identification and protection of confidential information",
    "C1.2": "Disposal of confidential information",
}
