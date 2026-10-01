"""Offline fixtures: never contact a proxy or generate subscription files.

If requests is absent locally, only its exception hierarchy is supplied for the
fake-session tests. Production still requires requirements.txt unchanged.
"""
import contextlib
import io
import json
import sys
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

try:
    import requests
except ModuleNotFoundError:
    requests = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class SSLError(ConnectionError):
        pass

    class Timeout(RequestException):
        pass

    requests.exceptions = types.SimpleNamespace(
        RequestException=RequestException, ConnectionError=ConnectionError,
        SSLError=SSLError, Timeout=Timeout,
    )
    requests.Session = Mock(side_effect=AssertionError("Use an offline fake session"))
    sys.modules["requests"] = requests

import vpngate

NODE = {"host": "fixture.invalid", "port": 443, "country": "Japan", "country_code": "JP"}
PRIVATE_TEXT = "fixture-sensitive-marker https://user:password@fixture.invalid/check?token=fixture-sensitive-marker"


class Response:
    def __init__(self, status=200, payload=None, error=None):
        self.status_code, self.payload, self.error = status, payload, error

    def json(self):
        if self.error:
            raise self.error
        return self.payload


class Session:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.url = response, error, None

    def get(self, url, **kwargs):
        self.url = url
        if self.error:
            raise self.error
        return self.response


class WorkerDiagnosticsTests(unittest.TestCase):
    def check(self, session):
        return vpngate.check_one(dict(NODE), session)

    def test_legacy_request_encodes_host_and_port_correctly(self):
        session = Session(Response(payload={"success": True, "responseTime": 12}))
        with patch.object(vpngate, "WORKER_CHECK_URL", "https://checker.invalid/check?sstp=vpn:vpn@"):
            result = self.check(session)
        uri = urlsplit(session.url)
        self.assertEqual(uri.path, "/check")
        self.assertEqual(parse_qs(uri.query), {"sstp": ["vpn:vpn@fixture.invalid:443"]})
        self.assertTrue(result["success"])
        self.assertFalse(result.get("worker_error", False))

    def test_http_statuses_do_not_read_response_body(self):
        for status in (400, 401, 403, 404, 429, 500, 503):
            with self.subTest(status=status):
                response = Response(status, error=AssertionError("Body must not be read"))
                result = self.check(Session(response))
                self.assertEqual(result["worker_error_type"], "HTTPError")
                self.assertEqual(result["worker_http_status"], status)
                self.assertEqual(result["error"], f"HTTP {status}")
                self.assertFalse(result["success"])

    def test_invalid_json_and_html_are_safe(self):
        result = self.check(Session(Response(error=ValueError(PRIVATE_TEXT))))
        self.assertEqual(result["worker_error_type"], "InvalidJSON")
        self.assertEqual(result["worker_http_status"], 200)
        self.assertNotIn("fixture-sensitive-marker", json.dumps(result))

    def test_invalid_response_schema_is_service_failure(self):
        for payload in ([], None, {}, {"success": "false"}, {"success": 1}):
            with self.subTest(payload=payload):
                result = self.check(Session(Response(payload=payload)))
                self.assertEqual(result["worker_error_type"], "InvalidResponse")
                self.assertFalse(result["success"])

    def test_transport_exception_categories_do_not_include_exception_text(self):
        for category in ("Timeout", "SSLError", "ConnectionError", "RequestException"):
            with self.subTest(category=category):
                error = getattr(requests.exceptions, category)(PRIVATE_TEXT)
                result = self.check(Session(error=error))
                self.assertEqual(result["worker_error_type"], category)
                self.assertNotIn("fixture-sensitive-marker", json.dumps(result))

    def test_unexpected_processing_error_keeps_received_http_status(self):
        result = self.check(Session(Response(payload={"success": True, "exit": "invalid"})))
        self.assertEqual(result["worker_error_type"], "UnexpectedError")
        self.assertEqual(result["worker_http_status"], 200)
        self.assertFalse(result["success"])

    def test_node_failure_is_not_worker_failure_and_remote_error_is_not_copied(self):
        result = self.check(Session(Response(payload={"success": False, "error": PRIVATE_TEXT})))
        self.assertFalse(result["success"])
        self.assertFalse(result.get("worker_error", False))
        self.assertNotIn("fixture-sensitive-marker", json.dumps(result))

    def test_summary_is_bounded_and_redacts_endpoint_and_unknown_categories(self):
        errors = [
            {"worker_http_status": status, "worker_error_type": "HTTPError"}
            for status in (400, 401, 403, 404, 429, 500, 503)
        ] + [{"worker_error_type": PRIVATE_TEXT, "error": PRIVATE_TEXT}]
        output = io.StringIO()
        with patch.object(vpngate, "WORKER_CHECK_URL", "https://user:password@checker.invalid/private?token=fixture-sensitive-marker"):
            with contextlib.redirect_stdout(output):
                vpngate.log_worker_errors(errors)
        text = output.getvalue()
        self.assertIn("checker.invalid", text)
        self.assertIn("UnexpectedError=1", text)
        self.assertIn("其他=3", text)
        for secret in ("user:password", "fixture-sensitive-marker", "/private", "token="):
            self.assertNotIn(secret, text)
        status_line = next(line for line in text.splitlines() if "HTTP 状态" in line)
        self.assertLessEqual(len(status_line.split(", ")), 6)

    def test_all_worker_failures_exit_before_generating_or_writing_outputs(self):
        for response, error in (
            (Response(403), None),
            (Response(error=ValueError(PRIVATE_TEXT)), None),
            (None, requests.exceptions.ConnectionError(PRIVATE_TEXT)),
        ):
            with self.subTest(error=type(error).__name__):
                fake_session = Session(response, error)
                output = io.StringIO()
                with patch.object(vpngate.requests, "Session", return_value=fake_session), \
                     patch.object(vpngate, "fetch_vpngate", return_value=([NODE], "offline-fixture")), \
                     patch.object(vpngate, "to_sstp_nodes", return_value=[NODE]), \
                     patch.object(vpngate, "build_outputs") as build, \
                     patch.object(vpngate, "write_outputs") as write, \
                     contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as stopped:
                        vpngate.main()
                self.assertEqual(stopped.exception.code, 1)
                build.assert_not_called()
                write.assert_not_called()
                self.assertNotIn("fixture-sensitive-marker", output.getvalue())


if __name__ == "__main__":
    unittest.main()
