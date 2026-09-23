"""Offline tests: run with `python -m unittest discover tests` (needs boto3)."""
import gzip
import io
import json
import os
import sys
import types
import unittest
from unittest import mock

os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-2:111111111111:security-alerts")
os.environ.setdefault("ALLOWED_KEY_USERS", "ci-bot")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-2")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

import lambda_function as lf  # noqa: E402

CTX = types.SimpleNamespace(function_name="cloudtrail-detector")
USER = {"type": "IAMUser", "arn": "arn:aws:iam::111111111111:user/tester"}


def rec(**kw):
    base = {"eventTime": "2026-09-23T12:00:00Z", "sourceIPAddress": "1.2.3.4",
            "awsRegion": "us-east-2", "userIdentity": USER}
    base.update(kw)
    return base


class DetectionTests(unittest.TestCase):
    def setUp(self):
        for name in ("s3", "iam", "cloudtrail", "sns"):
            setattr(lf, name, mock.MagicMock())

    def names(self, record):
        return [f["detection"] for f in lf.evaluate(record, CTX.function_name)]

    def test_root_login(self):
        r = rec(eventName="ConsoleLogin", userIdentity={"type": "Root", "arn": "arn:aws:iam::1:root"})
        self.assertEqual(self.names(r), ["Root console login"])

    def test_login_no_mfa(self):
        r = rec(eventName="ConsoleLogin", additionalEventData={"MFAUsed": "No"},
                responseElements={"ConsoleLogin": "Success"})
        self.assertEqual(self.names(r), ["IAM user console login without MFA"])

    def test_login_with_mfa_ignored(self):
        r = rec(eventName="ConsoleLogin", additionalEventData={"MFAUsed": "Yes"},
                responseElements={"ConsoleLogin": "Success"})
        self.assertEqual(self.names(r), [])

    def test_s3_remediated(self):
        lf.s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        r = rec(eventSource="s3.amazonaws.com", eventName="DeleteBucketPublicAccessBlock",
                requestParameters={"bucketName": "test-bucket"})
        f = lf.evaluate(r, CTX.function_name)[0]
        self.assertIn("re-enabled", f["action_taken"])
        lf.s3.put_public_access_block.assert_called_once()

    def test_access_key_deactivated(self):
        r = rec(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                responseElements={"accessKey": {"accessKeyId": "AKIATEST", "userName": "test-user"}})
        f = lf.evaluate(r, CTX.function_name)[0]
        self.assertIn("deactivated", f["action_taken"])
        lf.iam.update_access_key.assert_called_once_with(
            UserName="test-user", AccessKeyId="AKIATEST", Status="Inactive")

    def test_allowlisted_key(self):
        r = rec(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                responseElements={"accessKey": {"accessKeyId": "AKIATEST", "userName": "ci-bot"}})
        f = lf.evaluate(r, CTX.function_name)[0]
        self.assertIn("allowlisted", f["action_taken"])
        lf.iam.update_access_key.assert_not_called()

    def test_stop_logging_restarted(self):
        r = rec(eventSource="cloudtrail.amazonaws.com", eventName="StopLogging",
                requestParameters={"name": "org-trail"})
        f = lf.evaluate(r, CTX.function_name)[0]
        self.assertEqual(f["severity"], "CRITICAL")
        lf.cloudtrail.start_logging.assert_called_once_with(Name="org-trail")

    def test_failed_call_ignored(self):
        r = rec(eventSource="iam.amazonaws.com", eventName="CreateAccessKey",
                errorCode="AccessDenied")
        self.assertEqual(self.names(r), [])

    def test_own_actions_ignored(self):
        r = rec(eventSource="s3.amazonaws.com", eventName="PutBucketPublicAccessBlock",
                requestParameters={"bucketName": "b"},
                userIdentity={"type": "AssumedRole",
                              "arn": "arn:aws:sts::1:assumed-role/detector-role/cloudtrail-detector"})
        self.assertEqual(self.names(r), [])

    def test_handler_reads_gzip_and_skips_digest(self):
        records = [rec(eventName="ConsoleLogin",
                       userIdentity={"type": "Root", "arn": "arn:aws:iam::1:root"}),
                   rec(eventName="DescribeInstances", eventSource="ec2.amazonaws.com")]
        body = gzip.compress(json.dumps({"Records": records}).encode())
        lf.s3.get_object.return_value = {"Body": io.BytesIO(body)}
        event = {"Records": [
            {"s3": {"bucket": {"name": "trail"}, "object": {"key": "AWSLogs/1/CloudTrail/us-east-2/x.json.gz"}}},
            {"s3": {"bucket": {"name": "trail"}, "object": {"key": "AWSLogs/1/CloudTrail-Digest/us-east-2/d.json.gz"}}},
        ]}
        result = lf.lambda_handler(event, CTX)
        self.assertEqual(result, {"records": 2, "findings": 1})
        lf.sns.publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
