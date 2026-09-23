"""
CloudTrail log-based detection & auto-remediation.

Trigger: S3 "object created" notification on the CloudTrail log bucket.
Each time CloudTrail delivers a log file, this function downloads it,
runs every record through the detection rules below, sends an alert
for each match, and auto-remediates where a safe fix exists.

Why log-based instead of EventBridge: the account is region-locked to
us-east-2 by an organization SCP, but IAM and console sign-in events are
only delivered to EventBridge in us-east-1. A multi-region trail still
writes those events to its S3 bucket, so detection reads them from there.
"""
import gzip
import json
import os
import urllib.parse

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ALLOWED_KEY_USERS = {
    u.strip() for u in os.environ.get("ALLOWED_KEY_USERS", "").split(",") if u.strip()
}

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

S3_EXPOSURE_EVENTS = {
    "PutBucketPolicy",
    "PutBucketAcl",
    "PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock",
}
TRAIL_TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}


# ---------------------------------------------------------------- helpers

def summarize(record):
    """Fields every alert includes."""
    identity = record.get("userIdentity", {})
    return {
        "event_name": record.get("eventName"),
        "event_time": record.get("eventTime"),
        "actor": identity.get("arn") or identity.get("type"),
        "source_ip": record.get("sourceIPAddress"),
        "region": record.get("awsRegion"),
        "event_id": record.get("eventID"),
    }


def is_self(record, function_name):
    """True if this function made the call (avoids alerting on our own fixes)."""
    arn = record.get("userIdentity", {}).get("arn", "")
    return arn.endswith(f"/{function_name}")


# ------------------------------------------------------ remediation actions

def remediate_s3(record):
    bucket = (record.get("requestParameters") or {}).get("bucketName")
    if not bucket:
        return "none - no bucket name in event"
    try:
        current = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        current = {}
    if all(current.get(k) for k in FULL_BLOCK):
        return "none - bucket already fully blocked"
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=FULL_BLOCK)
    return f"re-enabled all Block Public Access settings on {bucket}"


def remediate_access_key(record):
    key = (record.get("responseElements") or {}).get("accessKey", {})
    key_id = key.get("accessKeyId")
    user = key.get("userName") or (record.get("requestParameters") or {}).get("userName")
    if not user or not key_id:
        return "none - could not identify an IAM user key (manual review)"
    if user in ALLOWED_KEY_USERS:
        return f"none - {user} is allowlisted"
    iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return f"deactivated key {key_id} for {user}"


def remediate_trail(record):
    if record.get("eventName") != "StopLogging":
        return "none - alert only (manual review)"
    trail = (record.get("requestParameters") or {}).get("name")
    if not trail:
        return "none - no trail name in event"
    cloudtrail.start_logging(Name=trail)
    return f"restarted logging on {trail}"


# --------------------------------------------------------- detection rules
# Each rule: name, severity, MITRE technique, match(record), optional remediate.

def is_console_login(r):
    return r.get("eventName") == "ConsoleLogin"


RULES = [
    {
        "name": "Root console login",
        "severity": "HIGH",
        "mitre": "T1078.004 Valid Accounts: Cloud Accounts",
        "match": lambda r: is_console_login(r)
        and r.get("userIdentity", {}).get("type") == "Root",
    },
    {
        "name": "IAM user console login without MFA",
        "severity": "MEDIUM",
        "mitre": "T1078.004 Valid Accounts: Cloud Accounts",
        "match": lambda r: is_console_login(r)
        and r.get("userIdentity", {}).get("type") == "IAMUser"
        and (r.get("additionalEventData") or {}).get("MFAUsed") == "No"
        and (r.get("responseElements") or {}).get("ConsoleLogin") == "Success",
    },
    {
        "name": "S3 public access weakened",
        "severity": "HIGH",
        "mitre": "T1530 Data from Cloud Storage",
        "match": lambda r: r.get("eventSource") == "s3.amazonaws.com"
        and r.get("eventName") in S3_EXPOSURE_EVENTS,
        "remediate": remediate_s3,
    },
    {
        "name": "New IAM access key created",
        "severity": "MEDIUM",
        "mitre": "T1098.001 Account Manipulation: Additional Cloud Credentials",
        "match": lambda r: r.get("eventSource") == "iam.amazonaws.com"
        and r.get("eventName") == "CreateAccessKey",
        "remediate": remediate_access_key,
    },
    {
        "name": "CloudTrail logging tampered with",
        "severity": "CRITICAL",
        "mitre": "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
        "match": lambda r: r.get("eventSource") == "cloudtrail.amazonaws.com"
        and r.get("eventName") in TRAIL_TAMPER_EVENTS,
        "remediate": remediate_trail,
    },
]


# ------------------------------------------------------------------ engine

def evaluate(record, function_name):
    """Return a list of findings for one CloudTrail record."""
    if record.get("errorCode"):  # failed calls changed nothing
        return []
    if is_self(record, function_name):
        return []
    findings = []
    for rule in RULES:
        if not rule["match"](record):
            continue
        finding = {
            "detection": rule["name"],
            "severity": rule["severity"],
            "mitre": rule["mitre"],
            **summarize(record),
        }
        remediate = rule.get("remediate")
        if remediate:
            try:
                finding["action_taken"] = remediate(record)
            except ClientError as e:
                err = e.response["Error"]
                finding["action_taken"] = f"REMEDIATION FAILED: {err.get('Code')} - {err.get('Message')}"
        else:
            finding["action_taken"] = "none - alert only"
        findings.append(finding)
    return findings


def alert(finding):
    subject = f"[{finding['severity']}] {finding['detection']}"
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100],
                Message=json.dumps(finding, indent=2))
    print(json.dumps(finding))


def read_log_file(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = gzip.decompress(obj["Body"].read())
    return json.loads(data).get("Records", [])


def lambda_handler(event, context):
    total_records = 0
    total_findings = 0
    for notification in event.get("Records", []):
        bucket = notification["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(notification["s3"]["object"]["key"])
        if "CloudTrail-Digest" in key or not key.endswith(".json.gz"):
            continue  # digest files are integrity hashes, not events
        for record in read_log_file(bucket, key):
            total_records += 1
            for finding in evaluate(record, context.function_name):
                total_findings += 1
                alert(finding)
    print(f"Processed {total_records} records, {total_findings} findings")
    return {"records": total_records, "findings": total_findings}
