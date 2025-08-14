from enum import Enum

# API Endpoints
ALERTS_ENDPOINT = "/alert/api/v1/alerts"
ALERTS_STATUS_ENDPOINT = "/alert/api/v1/alerts/status"
TAKEDOWN_SUBMIT_ENDPOINT = "/takedown/api/v1/submit"
TAKEDOWN_REQUEST_ENDPOINT = "/takedown/api/v1/request"


ClosureReason = Enum(
    "ClosureReason",
    [
        ("RESOLVED", "resolved"),
        ("IRRELEVANT", "irrelevant"),
        ("FALSE_POSITIVE", "false_positive"),
        ("IRRELEVANT_ALERT_SUBTYPE", "irrelevant_alert_subtype"),
        ("NO_LONGER_A_THREAT", "no_longer_a_threat"),
        ("ASSET_SHOULD_NOT_BE_MONITORED", "asset_should_not_be_monitored"),
        ("ASSET_BELONGS_TO_MY_ORGANIZATION", "asset_belongs_to_my_organization"),
        ("ASM_NO_LONGER_DETECTED", "asm_no_longer_detected"),
        ("ASM_MANUALLY_CLOSED", "asm_manually_closed"),
        ("OTHER", "other"),
    ],
)

Status = Enum("Status", [("OPEN", "open"), ("ACKNOWLEDGED", "acknowledged"), ("CLOSED", "closed")])

TakedownReason = Enum(
    "TakedownReason",
    [
        ("PHISHING", "phishing"),
        ("BRAND_ABUSE", "brand_abuse"),
        ("IMPERSONATING_APPLICATION", "impersonating_application"),
        ("UNOFFICIAL_APPLICATION_DISTRIBUTION", "unofficial_application_distribution"),
        ("MALICIOUS_CONTENT", "malicious_content"),
        ("SOCIAL_MEDIA_IMPERSONATION", "social_media_impersonation"),
        ("SOCIAL_MEDIA_EMPLOYEE_IMPERSONATION", "social_media_employee_impersonation"),
        ("FAKE_JOB_POST", "fake_job_post"),
        (
            "SENSITIVE_FILE_ON_ANTIVIRUS_REPOSITORY",
            "sensitive_file_on_antivirus_repository",
        ),
        ("INSTANT_MESSAGING_IMPERSONATION", "instant_messaging_impersonation"),
        ("OTHER", "other"),
    ],
)
