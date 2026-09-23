# Setup Guide (region: us-east-2, Ohio)

Everything lives in **us-east-2**. Log timestamps are UTC.

## 1. CloudTrail
Trail `org-trail`: multi-region, management events Read + Write, log file
validation enabled, no SSE-KMS (if KMS is used, add `kms:Decrypt` to the policy).

## 2. SNS
Standard topic `security-alerts` + confirmed email subscription.

## 3. IAM
1. Replace `ACCOUNT_ID` and `TRAIL_BUCKET` in `iam/cloudtrail-detector-policy.json`.
2. Create customer-managed policy `cloudtrail-detector-policy`.
3. Create role `cloudtrail-detector-role` (trusted entity: Lambda) with only that policy.

## 4. Lambda
1. Create `cloudtrail-detector` (Python 3.12+), execution role `cloudtrail-detector-role`.
2. **Verify** Configuration → Permissions shows `cloudtrail-detector-role`.
3. Paste `lambda/lambda_function.py`, Deploy. Timeout 1 min.
4. Env vars: `SNS_TOPIC_ARN`, optional `ALLOWED_KEY_USERS`.
5. S3 trail bucket → Properties → Event notification: prefix
   `AWSLogs/ACCOUNT_ID/CloudTrail/`, suffix `.json.gz`, all object create → Lambda.
6. Check CloudWatch logs for `Processed N records, 0 findings`.

## 5. Error alarm
CloudWatch alarm on `AWS/Lambda` `Errors` for the function: Sum, 5 min,
>= 1, 1 of 1 datapoints, missing data = not breaching, notify
`security-alerts` on ALARM (optionally OK).
Test: Lambda Test tab, event `{"Records": [{"s3": {}}]}`.

## 6. Tests
| Simulate | Expected |
|---|---|
| Turn off Block Public Access on a test bucket | BPA back on, HIGH email |
| Create access key for a test IAM user | Key Inactive, MEDIUM email |
| Stop logging on `org-trail` | Logging back on, CRITICAL email |
| Console login without MFA (if account allows console passwords) | MEDIUM email |

## 7. Teardown
Test resources, S3 event notification, alarm, Lambda, role, policy, SNS
topic, trail, log bucket.
