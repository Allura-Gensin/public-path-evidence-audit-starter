from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch

MODULE_PATH = Path(__file__).parents[1] / "src" / "public_path_evidence_capture.py"
SPEC = importlib.util.spec_from_file_location("public_path_evidence_capture", MODULE_PATH)
assert SPEC and SPEC.loader
capture_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture_module
SPEC.loader.exec_module(capture_module)


class FakeResponse:
    def __init__(self, status: int, body: bytes, **headers: str) -> None:
        self.status = status
        self._body = body
        self._position = 0
        self.read_calls = 0
        self.fp = None
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key.replace("_", "-")] = value

    def read(self, amount: int) -> bytes:
        self.read_calls += 1
        chunk = self._body[self._position : self._position + amount]
        self._position += len(chunk)
        return chunk


class FakeConnection:
    response: FakeResponse
    requests: list[tuple[str, str, dict[str, str]]] = []

    def __init__(self, checked: object, deadline: float | None = None) -> None:
        self.checked = checked
        self.deadline = deadline
        self.sock = None

    def request(self, method: str, target: str, headers: dict[str, str]) -> None:
        self.requests.append((method, target, headers))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        pass

    def abort_active_socket(self) -> None:
        pass


class URLBoundaryTests(unittest.TestCase):
    @patch.object(capture_module, "resolve_public_addresses", return_value=("93.184.216.34",))
    def test_accepts_plain_standard_port_https(self, _resolve: object) -> None:
        checked = capture_module.check_url("https://example.com/path")
        self.assertEqual((checked.hostname, checked.port, checked.request_target), ("example.com", 443, "/path"))

    def test_rejects_unsafe_syntax_before_resolution(self) -> None:
        rejected = (
            "http://example.com/",
            "https://user:password@example.com/",
            "https://example.com:8443/",
            "https://example.com/?token=secret",
            "https://example.com/#fragment",
            "https://example.com\\@127.0.0.1/",
            "https://example.com//other-host",
            "https://xn--a.example/",
            "https://example.com/\n::error::pwned",
        )
        with patch.object(capture_module, "resolve_public_addresses") as resolver:
            for url in rejected:
                with self.subTest(url=url), self.assertRaises(capture_module.BoundaryError):
                    capture_module.check_url(url)
            resolver.assert_not_called()

    def test_rejects_ip_literals_and_obscure_numeric_spellings(self) -> None:
        rejected = (
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://169.254.169.254/latest/meta-data/",
            "https://2130706433/",
            "https://0177.0.0.1/",
            "https://0x7f000001/",
        )
        with patch.object(capture_module, "resolve_public_addresses") as resolver:
            for url in rejected:
                with self.subTest(url=url), self.assertRaises(capture_module.BoundaryError):
                    capture_module.check_url(url)
            resolver.assert_not_called()

    @patch.object(capture_module.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.2", 443))])
    def test_rejects_private_dns_answer(self, _getaddrinfo: object) -> None:
        with self.assertRaisesRegex(capture_module.BoundaryError, "non-public"):
            capture_module.resolve_public_addresses("internal.example", 443, time.monotonic() + 1)

    @patch.object(
        capture_module.socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))],
    )
    def test_rejects_mixed_dns_answers(self, _getaddrinfo: object) -> None:
        with self.assertRaises(capture_module.BoundaryError):
            capture_module.resolve_public_addresses("mixed.example", 443, time.monotonic() + 1)

    def test_json_input_requires_one_to_five_strings(self) -> None:
        for value in ("", "{}", "[]", '["a", 2]', json.dumps([f"https://example.com/{i}" for i in range(6)])):
            with self.subTest(value=value), self.assertRaises(capture_module.BoundaryError):
                capture_module.parse_urls_json(value)
        self.assertEqual(capture_module.parse_urls_json('["https://example.com/"]'), ["https://example.com/"])
        with self.assertRaises(capture_module.BoundaryError):
            capture_module.parse_urls_json('["https://example.com/", "https://example.com/"]')

    def test_explicit_special_use_address_rules(self) -> None:
        denied = (
            "0.0.0.0", "10.2.3.4", "100.64.0.1", "127.0.0.1", "169.254.169.254",
            "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1",
            "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
            "::", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::1",
            "100::1", "2001::1", "2001:db8::1", "2002:7f00:1::", "fc00::1",
            "fec0::1", "fe80::1", "ff02::1",
        )
        for address in denied:
            with self.subTest(address=address):
                self.assertFalse(capture_module.is_public_ip(address))
        self.assertTrue(capture_module.is_public_ip("8.8.8.8"))
        self.assertTrue(capture_module.is_public_ip("2606:4700:4700::1111"))

    @patch.object(capture_module.socket, "getaddrinfo")
    def test_dns_answer_cap_is_fail_closed(self, getaddrinfo: Mock) -> None:
        getaddrinfo.return_value = [(2, 1, 6, "", (f"8.8.8.{index}", 443)) for index in range(1, 18)]
        with self.assertRaisesRegex(capture_module.BoundaryError, "too many"):
            capture_module.resolve_public_addresses("many.example", 443, time.monotonic() + 1)

    def test_slow_dns_obeys_deadline(self) -> None:
        def slow_lookup(*_args: object, **_kwargs: object) -> list[object]:
            time.sleep(0.05)
            return []

        started = time.monotonic()
        with patch.object(capture_module.socket, "getaddrinfo", side_effect=slow_lookup), patch.object(capture_module, "DNS_PHASE_SECONDS", 0.01):
            with self.assertRaisesRegex(capture_module.BoundaryError, "DNS time"):
                capture_module.resolve_public_addresses("slow.example", 443, time.monotonic() + 1)
        self.assertLess(time.monotonic() - started, 0.04)


class FakeSocket:
    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.timeouts: list[float] = []
        self.closed = False

    def getpeername(self) -> tuple[str, int]:
        return self.peer, 443

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def close(self) -> None:
        self.closed = True


class ConnectionSecurityTests(unittest.TestCase):
    def checked(self, *addresses: str) -> object:
        return capture_module.CheckedURL("https://example.com/", "example.com", 443, "/", addresses)

    def test_pinned_address_and_tls_hostname_are_preserved(self) -> None:
        raw, tls = FakeSocket("8.8.8.8"), FakeSocket("8.8.8.8")
        connection = capture_module.PinnedHTTPSConnection(self.checked("8.8.8.8"), time.monotonic() + 1)
        connection._context.wrap_socket = Mock(return_value=tls)
        with patch.object(capture_module.socket, "create_connection", return_value=raw) as connector:
            connection.connect()
        connector.assert_called_once()
        self.assertEqual(connector.call_args.args[0], ("8.8.8.8", 443))
        connection._context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com")

    def test_peer_outside_validated_set_fails_before_tls(self) -> None:
        raw = FakeSocket("1.1.1.1")
        connection = capture_module.PinnedHTTPSConnection(self.checked("8.8.8.8"), time.monotonic() + 1)
        connection._context.wrap_socket = Mock()
        with patch.object(capture_module.socket, "create_connection", return_value=raw):
            with self.assertRaises(capture_module.BoundaryError):
                connection.connect()
        connection._context.wrap_socket.assert_not_called()
        self.assertTrue(raw.closed)

    def test_tls_verification_failure_is_not_bypassed(self) -> None:
        for reason in ("wrong host", "expired", "untrusted"):
            with self.subTest(reason=reason):
                raw = FakeSocket("8.8.8.8")
                connection = capture_module.PinnedHTTPSConnection(self.checked("8.8.8.8"), time.monotonic() + 1)
                self.assertTrue(connection._context.check_hostname)
                self.assertEqual(connection._context.verify_mode, capture_module.ssl.CERT_REQUIRED)
                connection._context.wrap_socket = Mock(side_effect=capture_module.ssl.SSLCertVerificationError(reason))
                with patch.object(capture_module.socket, "create_connection", return_value=raw):
                    with self.assertRaises(OSError):
                        connection.connect()

    def test_dns_rebinding_cannot_change_pinned_connect_target(self) -> None:
        public_answer = [(2, 1, 6, "", ("8.8.8.8", 443))]
        with patch.object(capture_module.socket, "getaddrinfo", return_value=public_answer) as resolver:
            checked = capture_module.check_url("https://example.com/", time.monotonic() + 1)
        raw, tls = FakeSocket("8.8.8.8"), FakeSocket("8.8.8.8")
        connection = capture_module.PinnedHTTPSConnection(checked, time.monotonic() + 1)
        connection._context.wrap_socket = Mock(return_value=tls)
        with patch.object(capture_module.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]) as rebound, patch.object(capture_module.socket, "create_connection", return_value=raw) as connector:
            connection.connect()
        resolver.assert_called_once()
        rebound.assert_not_called()
        self.assertEqual(connector.call_args.args[0], ("8.8.8.8", 443))

    def test_multi_address_connect_does_not_reset_deadline(self) -> None:
        calls: list[tuple[str, int]] = []

        def timeout_once(target: tuple[str, int], _timeout: float) -> object:
            calls.append(target)
            time.sleep(0.03)
            raise socket.timeout()

        connection = capture_module.PinnedHTTPSConnection(self.checked("8.8.8.8", "1.1.1.1"), time.monotonic() + 0.015)
        with patch.object(capture_module.socket, "create_connection", side_effect=timeout_once):
            with self.assertRaises(capture_module.BoundaryError):
                connection.connect()
        self.assertEqual(calls, [("8.8.8.8", 443)])

    def test_wall_clock_watchdog_stops_a_real_buffered_slow_drip(self) -> None:
        client, server = socket.socketpair()

        class SocketHolder:
            def __init__(self, active: socket.socket) -> None:
                self.active = active

            def abort_active_socket(self) -> None:
                try:
                    self.active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.active.close()

        def drip() -> None:
            try:
                server.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    b"Content-Length: 10000\r\n\r\n"
                )
                while True:
                    server.sendall(b"x")
                    time.sleep(0.005)
            except OSError:
                pass
            finally:
                server.close()

        producer = threading.Thread(target=drip, daemon=True)
        producer.start()
        response = capture_module.HeaderBoundedHTTPResponse(client)
        watchdog = capture_module.WallClockWatchdog(SocketHolder(client), time.monotonic() + 0.05)
        started = time.monotonic()
        try:
            response.begin()
            try:
                while response.read(1):
                    pass
            except OSError:
                pass
        finally:
            watchdog.cancel()
            response.close()
            producer.join(timeout=0.2)
        self.assertLess(time.monotonic() - started, 0.25)


class CaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeConnection.requests = []
        self.checked = capture_module.CheckedURL("https://example.com/join", "example.com", 443, "/join", ("93.184.216.34",))

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_get_only_without_credentials_and_inert_parse(self) -> None:
        FakeConnection.response = FakeResponse(
            200,
            b"<title>Join us</title><script src='https://bad.invalid/x'></script><form method='post' action='/signup?nonce=x'></form><a href='/demo?tracking=1'>Request a demo</a>",
            Content_Type="text/html; charset=utf-8",
        )
        result = capture_module.capture(self.checked)
        self.assertEqual(result.title, "Join us")
        self.assertEqual(result.forms, (("POST", "[route components omitted]"),))
        self.assertEqual(len(FakeConnection.requests), 1)
        method, target, headers = FakeConnection.requests[0]
        self.assertEqual((method, target), ("GET", "/join"))
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Accept-Encoding"], "identity")

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_redirect_never_retains_location_or_reads_body(self) -> None:
        marker = "https://127.0.0.1/?token=::error::pwned"
        FakeConnection.response = FakeResponse(302, marker.encode(), Content_Type="text/html", Location=marker)
        result = capture_module.capture(self.checked)
        self.assertEqual(result.error, "redirect not followed")
        self.assertNotIn(marker, repr(result))
        self.assertEqual(FakeConnection.response.read_calls, 0)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_non_html_body_is_not_read(self) -> None:
        FakeConnection.response = FakeResponse(200, b"secret-body", Content_Type="application/octet-stream")
        result = capture_module.capture(self.checked)
        self.assertEqual(result.error, "non-HTML response")
        self.assertEqual(FakeConnection.response.read_calls, 0)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_oversized_content_length_is_refused_before_body_read(self) -> None:
        FakeConnection.response = FakeResponse(
            200,
            b"x",
            Content_Type="text/html",
            Content_Length=str(capture_module.MAX_RESPONSE_BYTES + 1),
        )
        result = capture_module.capture(self.checked)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(FakeConnection.response.read_calls, 0)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_streamed_body_aborts_at_one_byte_over_limit(self) -> None:
        FakeConnection.response = FakeResponse(200, b"x" * (capture_module.MAX_RESPONSE_BYTES + 1), Content_Type="text/html")
        result = capture_module.capture(self.checked)
        self.assertEqual(result.status, "unavailable")
        self.assertGreater(FakeConnection.response.read_calls, 1)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_slow_header_timeout_is_controlled(self) -> None:
        class SlowHeaderConnection(FakeConnection):
            def getresponse(self) -> object:
                raise socket.timeout()

        with patch.object(capture_module, "PinnedHTTPSConnection", SlowHeaderConnection):
            result = capture_module.capture(self.checked, time.monotonic() + 0.01)
        self.assertEqual(result.status, "unavailable")

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_slow_body_cannot_extend_route_deadline(self) -> None:
        class SlowBody(FakeResponse):
            def read(self, amount: int) -> bytes:
                time.sleep(0.02)
                return super().read(amount)

        FakeConnection.response = SlowBody(200, b"first chunk", Content_Type="text/html")
        result = capture_module.capture(self.checked, time.monotonic() + 0.01)
        self.assertEqual(result.status, "unavailable")

    def test_report_escapes_markdown_html_and_workflow_commands(self) -> None:
        report = capture_module.render(
            [capture_module.Capture(url="https://example.com/a|b", status="HTTP 200", title="<b>`x`</b>\n::error::pwned")],
            datetime(2026, 8, 15, tzinfo=timezone.utc),
        )
        self.assertIn("https&#58;//example.com/a\\|b", report)
        self.assertIn("&lt;b&gt;\\`x\\`&lt;/b&gt;", report)
        self.assertNotIn("\n::error::", report)
        self.assertLessEqual(len(report.encode()), capture_module.MAX_REPORT_BYTES)

    def test_remote_text_cannot_create_links_images_autolinks_or_bidi(self) -> None:
        payload = "&#27;[31m\u202e![alt](https://attacker.invalid/x) <https://evil.invalid> user@example.com"
        report = capture_module.render([
            capture_module.Capture(
                url="https://example.com/", status="HTTP 200", title=payload,
                description=payload, forms=(("POST", payload),), cta_links=((payload, payload),),
            )
        ])
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        self.assertNotIn("![", report)
        self.assertNotIn("](https", report)
        self.assertNotIn("<https", report)
        self.assertNotIn("https://", report)
        self.assertNotIn("user@example.com", report)
        self.assertNotIn("`POST`", report)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_aggregate_header_limit_is_checked_before_body_read(self) -> None:
        FakeConnection.response = FakeResponse(
            200, b"body", Content_Type="text/html", X_Padding="x" * capture_module.MAX_HEADER_BYTES,
        )
        result = capture_module.capture(self.checked)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(FakeConnection.response.read_calls, 0)

    def test_header_reader_aborts_during_cumulative_read(self) -> None:
        first = b"X-One: " + b"a" * 32_760 + b"\r\n"
        second = b"X-Two: " + b"b" * 32_760 + b"\r\n"
        reader = capture_module.HeaderLimitedReader(io.BytesIO(first + second))
        self.assertEqual(reader.readline(), first)
        with self.assertRaises(capture_module.http.client.HTTPException):
            reader.readline()
        self.assertIs(capture_module.PinnedHTTPSConnection.response_class, capture_module.HeaderBoundedHTTPResponse)

    @patch.object(capture_module, "PinnedHTTPSConnection", FakeConnection)
    def test_unknown_declared_charset_is_controlled(self) -> None:
        FakeConnection.response = FakeResponse(
            200, b"<title>hello</title>", Content_Type="text/html; charset=not-a-real-codec",
        )
        result = capture_module.capture(self.checked)
        self.assertEqual(result.status, "unavailable")


class OutputAndCLITests(unittest.TestCase):
    def test_report_path_is_fresh_private_and_runner_temp_contained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = capture_module.create_report(directory, "test report\n")
            self.assertEqual(path.parent.parent, Path(directory).resolve())
            self.assertEqual(path.parent.name, "public-path-evidence-audit")
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.name, "report.md")

    def test_runner_temp_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            link = Path(directory) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(capture_module.BoundaryError):
                capture_module.create_report(str(link), "test report\n")

    @patch.object(capture_module, "capture")
    @patch.object(capture_module, "resolve_checked_url")
    def test_main_writes_only_fixed_report_and_outputs(self, resolver: object, capture: object) -> None:
        checked = capture_module.CheckedURL("https://example.com/", "example.com", 443, "/", ("93.184.216.34",))
        resolver.return_value = checked
        capture.return_value = capture_module.Capture(url=checked.original, status="HTTP 200", content_type="text/html", title="Example")
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory) / "outputs"
            env = {
                "PPA_RUNNER_ENVIRONMENT": "github-hosted",
                "PPA_RUNNER_OS": "Linux",
                "PPA_RUNNER_TEMP": directory,
                "PPA_URLS_JSON": '["https://example.com/"]',
                "GITHUB_OUTPUT": str(outputs),
            }
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(capture_module.main(), 0)
            output_text = outputs.read_text()
            report_path = Path(next(line.split("=", 1)[1] for line in output_text.splitlines() if line.startswith("report-path=")))
            self.assertTrue(report_path.is_file())
            discovered = list(Path(directory).glob("public-path-evidence-audit/report.md"))
            self.assertEqual([path.resolve() for path in discovered], [report_path])

    def test_self_hosted_runner_fails_before_url_processing(self) -> None:
        with patch.dict(os.environ, {"PPA_RUNNER_ENVIRONMENT": "self-hosted"}, clear=True), patch.object(capture_module, "parse_urls_json") as parser:
            self.assertEqual(capture_module.main(), 2)
            parser.assert_not_called()

    def test_non_linux_runner_fails_before_url_processing(self) -> None:
        env = {"PPA_RUNNER_ENVIRONMENT": "github-hosted", "PPA_RUNNER_OS": "macOS"}
        with patch.dict(os.environ, env, clear=True), patch.object(capture_module, "parse_urls_json") as parser:
            self.assertEqual(capture_module.main(), 2)
            parser.assert_not_called()

    def test_preexisting_fixed_directory_is_refused_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "public-path-evidence-audit"
            report_dir.mkdir()
            sentinel = report_dir / "report.md"
            sentinel.write_text("keep")
            with self.assertRaises(capture_module.BoundaryError):
                capture_module.create_report(directory, "replace")
            self.assertEqual(sentinel.read_text(), "keep")

    @patch.object(capture_module, "create_report", return_value=Path("/tmp/public-path-evidence-audit/report.md"))
    @patch.object(capture_module, "capture")
    @patch.object(capture_module, "resolve_checked_url")
    def test_route_deadlines_share_a_sixty_second_run_cap(self, resolver: Mock, capture: Mock, _create: Mock) -> None:
        resolver.side_effect = lambda checked, _deadline: checked
        capture.side_effect = [
            capture_module.Capture(url="https://one.example/", status="unavailable"),
            capture_module.Capture(url="https://two.example/", status="unavailable"),
        ]
        env = {
            "PPA_RUNNER_ENVIRONMENT": "github-hosted", "PPA_RUNNER_OS": "Linux",
            "PPA_RUNNER_TEMP": "/tmp", "PPA_URLS_JSON": '["https://one.example/", "https://two.example/"]',
        }
        with patch.dict(os.environ, env, clear=True), patch.object(
            capture_module.time, "monotonic", side_effect=[100.0, 100.0, 150.0, 150.0, 150.0]
        ):
            self.assertEqual(capture_module.main(), 0)
        deadlines = [call.args[1] for call in resolver.call_args_list]
        self.assertEqual(deadlines, [115.0, 160.0])
        self.assertEqual([call.args[1] for call in capture.call_args_list], deadlines)

    def test_action_metadata_has_no_upload_or_untrusted_run_interpolation(self) -> None:
        root = Path(__file__).parents[1]
        action = (root / "action.yml").read_text()
        workflow = (root / ".github/workflows/public-path-evidence-example.yml").read_text()
        self.assertNotIn("upload-artifact", action)
        self.assertNotIn("${{ inputs.", next(line for line in action.splitlines() if line.strip().startswith("run:")))
        self.assertIn("permissions: {}", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("PPA_RUNNER_OS: ${{ runner.os }}", action)
        references = re.findall(
            r"Allura-Gensin/public-path-evidence-audit-starter@([0-9a-f]{40})",
            workflow,
        )
        self.assertEqual(len(references), 1)
        self.assertNotEqual(references[0], "0" * 40)
        self.assertNotIn("@v1", workflow)

    @patch.object(capture_module, "create_report", side_effect=OSError("::error::secret-path"))
    @patch.object(capture_module, "capture")
    @patch.object(capture_module, "resolve_checked_url")
    def test_main_io_failure_has_fixed_safe_log(self, resolver: Mock, capture: Mock, _create: Mock) -> None:
        checked = capture_module.CheckedURL("https://example.com/", "example.com", 443, "/", ("8.8.8.8",))
        resolver.return_value = checked
        capture.return_value = capture_module.Capture(url=checked.original, status="unavailable")
        env = {
            "PPA_RUNNER_ENVIRONMENT": "github-hosted", "PPA_RUNNER_OS": "Linux",
            "PPA_RUNNER_TEMP": "/tmp", "PPA_URLS_JSON": '["https://example.com/"]',
        }
        stderr = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch("sys.stderr", stderr):
            self.assertEqual(capture_module.main(), 2)
        self.assertEqual(stderr.getvalue(), "public-path capture failed: local I/O error\n")


if __name__ == "__main__":
    unittest.main()
