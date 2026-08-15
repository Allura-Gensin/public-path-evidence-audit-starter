#!/usr/bin/env python3
"""Dependency-free, GET-only evidence capture for public GitHub-hosted Linux runners.

Python's ``http.client`` caps an individual header line and the number of
headers. A response-class wrapper additionally counts the status line and
headers while the standard-library parser reads them and aborts at 64 KiB.
The socket remains limited by the route deadline throughout that read.
"""
from __future__ import annotations

import html
import http.client
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import stat
import sys
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urlsplit

MAX_URLS = 5
MAX_URL_LENGTH = 2_048
MAX_DNS_ANSWERS = 16
MAX_HEADER_BYTES = 65_536
MAX_RESPONSE_BYTES = 1_048_576
MAX_REPORT_BYTES = 65_536
MAX_TITLE_LENGTH = 512
MAX_DESCRIPTION_LENGTH = 2_048
MAX_FIELD_LENGTH = 512
MAX_ITEMS = 10
DNS_PHASE_SECONDS = 5.0
SOCKET_PHASE_SECONDS = 5.0
TOTAL_ROUTE_SECONDS = 15.0
TOTAL_RUN_SECONDS = 60.0
USER_AGENT = "AllureLabs-PublicPathEvidenceAction/1.0"
CTA_PATTERN = re.compile(r"\b(start|sign|book|contact|buy|trial|demo|quote|get|ask|request|view)\b", re.I)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
BIDI_CONTROLS = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f")

IPV4_DENY_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
))
IPV6_DENY_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fec0::/10",
    "fe80::/10", "ff00::/8",
))


class BoundaryError(ValueError):
    """An input or runtime condition crosses the public-only boundary."""


def remaining_seconds(deadline: float, phase_limit: float | None = None) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BoundaryError("time limit exceeded")
    return min(remaining, phase_limit) if phase_limit is not None else remaining


def clean_text(value: str, limit: int = MAX_FIELD_LENGTH) -> str:
    decoded = ANSI_ESCAPE_PATTERN.sub("", html.unescape(value))
    cleaned = "".join(
        " " if ord(character) < 32 or 127 <= ord(character) <= 159 else character
        for character in decoded if character not in BIDI_CONTROLS
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def plain_markdown(value: str) -> str:
    """Render untrusted text without links, images, autolinks, code, or HTML."""
    value = html.escape(clean_text(value), quote=False)
    value = re.sub(r"(?i)\b(https?)://", lambda match: f"{match.group(1)}&#58;//", value)
    value = re.sub(r"(?i)\bwww\.", "www&#46;", value).replace("@", "&#64;")
    value = value.replace("\\", "\\\\")
    for character in "`|![]()":
        value = value.replace(character, "\\" + character)
    return value


class PageSummaryParser(HTMLParser):
    """Extract bounded inert text; never load or execute subresources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.description: str | None = None
        self.canonical: str | None = None
        self.forms: list[tuple[str, str]] = []
        self.links: list[tuple[str, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self.in_title = True
        elif tag == "meta" and values.get("name", "").lower() == "description" and self.description is None:
            self.description = clean_text(values.get("content", ""), MAX_DESCRIPTION_LENGTH) or None
        elif tag == "link" and "canonical" in values.get("rel", "").lower().split() and self.canonical is None:
            self.canonical = clean_text(values.get("href", "")) or None
        elif tag == "form" and len(self.forms) < MAX_ITEMS:
            self.forms.append((clean_text(values.get("method", "get"), 20).upper(), clean_text(values.get("action", ""))))
        elif tag == "a" and len(self.links) < 100:
            self._anchor_href = clean_text(values.get("href", ""))
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self.in_title and sum(map(len, self.title_parts)) < MAX_TITLE_LENGTH:
            self.title_parts.append(data)
        if self._anchor_href is not None and sum(map(len, self._anchor_text)) < MAX_FIELD_LENGTH:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "a" and self._anchor_href is not None:
            text, href = clean_text(" ".join(self._anchor_text)), clean_text(self._anchor_href)
            if text and href and len(self.links) < 100:
                self.links.append((text, href))
            self._anchor_href, self._anchor_text = None, []


@dataclass(frozen=True)
class CheckedURL:
    original: str
    hostname: str
    port: int
    request_target: str
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class Capture:
    url: str
    status: str
    content_type: str = ""
    title: str = ""
    description: str = ""
    canonical: str = ""
    forms: tuple[tuple[str, str], ...] = ()
    cta_links: tuple[tuple[str, str], ...] = ()
    error: str = ""


def canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        denied = any(address in network for network in IPV4_DENY_NETWORKS)
    else:
        if address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None:
            return False
        denied = any(address in network for network in IPV6_DENY_NETWORKS)
    return bool(not denied and address.is_global)


def _dns_lookup(hostname: str, port: int, result: queue.Queue[object]) -> None:
    try:
        result.put(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
    except BaseException as error:
        result.put(error)


def resolve_public_addresses(hostname: str, port: int, deadline: float) -> tuple[str, ...]:
    result: queue.Queue[object] = queue.Queue(maxsize=1)
    threading.Thread(target=_dns_lookup, args=(hostname, port, result), daemon=True).start()
    try:
        outcome = result.get(timeout=remaining_seconds(deadline, DNS_PHASE_SECONDS))
    except queue.Empty as error:
        raise BoundaryError("DNS time limit exceeded") from error
    if isinstance(outcome, BaseException):
        raise BoundaryError("hostname could not be resolved") from outcome
    answers = outcome
    if not isinstance(answers, list) or not answers:
        raise BoundaryError("hostname did not resolve to an address")
    if len(answers) > MAX_DNS_ANSWERS:
        raise BoundaryError("hostname returned too many DNS answers")
    try:
        addresses = tuple(dict.fromkeys(canonical_ip(answer[4][0]) for answer in answers))
    except (IndexError, TypeError, ValueError) as error:
        raise BoundaryError("hostname returned an invalid DNS answer") from error
    if not addresses or any(not is_public_ip(address) for address in addresses):
        raise BoundaryError("hostname resolves to a non-public address")
    return addresses


def normalize_hostname(value: str) -> str:
    if "\\" in value or value.endswith("."):
        raise BoundaryError("hostname is ambiguous")
    try:
        hostname = value.encode("idna").decode("ascii").lower()
        decoded_hostname = hostname.encode("ascii").decode("idna")
        if decoded_hostname.encode("idna").decode("ascii").lower() != hostname:
            raise UnicodeError("IDNA round trip changed the hostname")
    except UnicodeError as error:
        raise BoundaryError("hostname is invalid") from error
    labels = hostname.split(".")
    if len(hostname) > 253 or len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise BoundaryError("hostname is invalid")
    if any(label.startswith("-") or label.endswith("-") or not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        raise BoundaryError("hostname is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise BoundaryError("IP-literal URLs are not allowed")
    if hostname.isdecimal() or hostname.startswith("0x") or all(label.isdecimal() for label in labels):
        raise BoundaryError("numeric IP spellings are not allowed")
    return hostname


def parse_url(value: str) -> CheckedURL:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise BoundaryError("URL length is outside the allowed range")
    if "\\" in value or any(character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise BoundaryError("URL contains an ambiguous or control character")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.netloc or not parsed.hostname:
        raise BoundaryError("each URL must use HTTPS and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise BoundaryError("credential-bearing URLs are not allowed")
    if parsed.query or parsed.fragment:
        raise BoundaryError("query strings and fragments are not allowed")
    try:
        port = parsed.port or 443
    except ValueError as error:
        raise BoundaryError("URL contains an invalid port") from error
    if port != 443:
        raise BoundaryError("only HTTPS port 443 is allowed")
    hostname = normalize_hostname(parsed.hostname)
    path = parsed.path or "/"
    if path.startswith("//"):
        raise BoundaryError("network-path-style URL paths are not allowed")
    return CheckedURL(value, hostname, port, quote(path, safe="/%:@-._~!$&'()*+,;="))


def resolve_checked_url(checked: CheckedURL, deadline: float) -> CheckedURL:
    return replace(checked, addresses=resolve_public_addresses(checked.hostname, checked.port, deadline))


def check_url(value: str, deadline: float | None = None) -> CheckedURL:
    deadline = deadline if deadline is not None else time.monotonic() + DNS_PHASE_SECONDS
    return resolve_checked_url(parse_url(value), deadline)


class HeaderLimitedReader:
    """Count bytes consumed by status/header readline calls before body reads."""

    def __init__(self, raw: object) -> None:
        self.raw = raw
        self.header_bytes = 0
        self.limiting = True

    def readline(self, limit: int = -1) -> bytes:
        line = self.raw.readline(limit)
        if self.limiting:
            self.header_bytes += len(line)
            if self.header_bytes > MAX_HEADER_BYTES:
                raise http.client.HTTPException("response headers exceeded the capture limit")
        return line

    def stop_limiting(self) -> None:
        self.limiting = False

    def __getattr__(self, name: str) -> object:
        return getattr(self.raw, name)


class HeaderBoundedHTTPResponse(http.client.HTTPResponse):
    """Use http.client parsing while enforcing a cumulative wire-byte limit."""

    def __init__(self, sock: object, *args: object, **kwargs: object) -> None:
        super().__init__(sock, *args, **kwargs)
        self.fp = HeaderLimitedReader(self.fp)

    def begin(self) -> None:
        try:
            super().begin()
        finally:
            if isinstance(self.fp, HeaderLimitedReader):
                self.fp.stop_limiting()


class WallClockWatchdog:
    """Close a connection's active socket at an absolute monotonic deadline."""

    def __init__(self, connection: "PinnedHTTPSConnection", deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline
        self._cancelled = threading.Event()
        self._thread = threading.Thread(target=self._run, name="public-path-deadline", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        delay = max(0.0, self._deadline - time.monotonic())
        if not self._cancelled.wait(delay):
            self._connection.abort_active_socket()

    def cancel(self) -> None:
        self._cancelled.set()
        self._thread.join(timeout=0.1)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = HeaderBoundedHTTPResponse

    def __init__(self, checked: CheckedURL, deadline: float) -> None:
        super().__init__(checked.hostname, checked.port, timeout=remaining_seconds(deadline, SOCKET_PHASE_SECONDS), context=ssl.create_default_context())
        self._checked_addresses, self._deadline = checked.addresses, deadline
        self._active_socket: socket.socket | None = None
        self._active_socket_lock = threading.Lock()

    def _track_active_socket(self, active_socket: socket.socket | None) -> None:
        with self._active_socket_lock:
            self._active_socket = active_socket

    def abort_active_socket(self) -> None:
        with self._active_socket_lock:
            active_socket = self._active_socket
            self._active_socket = None
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                active_socket.close()
            except OSError:
                pass

    def connect(self) -> None:
        allowed = {canonical_ip(address) for address in self._checked_addresses}
        last_error: OSError | None = None
        for address in self._checked_addresses:
            raw_socket: socket.socket | None = None
            try:
                raw_socket = socket.create_connection((address, self.port), remaining_seconds(self._deadline, SOCKET_PHASE_SECONDS))
                self._track_active_socket(raw_socket)
                peer = canonical_ip(raw_socket.getpeername()[0])
                if peer not in allowed or not is_public_ip(peer):
                    raise BoundaryError("connected peer did not match vetted DNS")
                raw_socket.settimeout(remaining_seconds(self._deadline, SOCKET_PHASE_SECONDS))
                tls_socket = self._context.wrap_socket(raw_socket, server_hostname=self.host)
                self.sock = tls_socket
                self._track_active_socket(tls_socket)
                self.sock.settimeout(remaining_seconds(self._deadline, SOCKET_PHASE_SECONDS))
                return
            except BoundaryError:
                if raw_socket is not None:
                    raw_socket.close()
                self._track_active_socket(None)
                raise
            except OSError as error:
                last_error = error
                if raw_socket is not None:
                    raw_socket.close()
                self._track_active_socket(None)
        raise OSError("unable to connect to a vetted public address") from last_error


def observed_route(value: str) -> str:
    value = clean_text(value)
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[unparseable route omitted]"
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return "[route components omitted]"
    return clean_text(value)


def set_connection_timeout(connection: object, deadline: float) -> None:
    sock = getattr(connection, "sock", None)
    if sock is not None:
        sock.settimeout(remaining_seconds(deadline, SOCKET_PHASE_SECONDS))


def read_bounded_body(response: http.client.HTTPResponse, deadline: float) -> bytes:
    length = response.headers.get("Content-Length")
    if length:
        try:
            if int(length) > MAX_RESPONSE_BYTES:
                raise BoundaryError("response exceeded the capture limit")
        except ValueError as error:
            raise BoundaryError("response Content-Length is invalid") from error
    chunks: list[bytes] = []
    total = 0
    while True:
        timeout = remaining_seconds(deadline, SOCKET_PHASE_SECONDS)
        if response.fp and getattr(response.fp, "raw", None):
            raw_socket = getattr(response.fp.raw, "_sock", None)
            if raw_socket is not None:
                raw_socket.settimeout(timeout)
        chunk = response.read(min(65_536, MAX_RESPONSE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise BoundaryError("response exceeded the capture limit")
        chunks.append(chunk)
    return b"".join(chunks)


def capture(checked: CheckedURL, deadline: float | None = None) -> Capture:
    deadline = deadline if deadline is not None else time.monotonic() + TOTAL_ROUTE_SECONDS
    connection = PinnedHTTPSConnection(checked, deadline)
    watchdog = WallClockWatchdog(connection, deadline)
    try:
        connection.request("GET", checked.request_target, headers={
            "Accept": "text/html,application/xhtml+xml", "Accept-Encoding": "identity",
            "Connection": "close", "User-Agent": USER_AGENT,
        })
        set_connection_timeout(connection, deadline)
        response = connection.getresponse()
        remaining_seconds(deadline)
        if len(response.headers.as_bytes()) > MAX_HEADER_BYTES:
            raise BoundaryError("response headers exceeded the capture limit")
        status = f"HTTP {response.status}"
        if 300 <= response.status < 400:
            return Capture(url=checked.original, status=status, error="redirect not followed")
        content_type = response.headers.get_content_type()
        if content_type not in {"text/html", "application/xhtml+xml"}:
            return Capture(url=checked.original, status=status, content_type=content_type, error="non-HTML response")
        if response.headers.get("Content-Encoding", "").lower() not in {"", "identity"}:
            return Capture(url=checked.original, status=status, content_type=content_type, error="encoded response was not parsed")
        raw = read_bounded_body(response, deadline)
        parser = PageSummaryParser()
        parser.feed(raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace"))
        ctas = tuple((clean_text(text), observed_route(href)) for text, href in parser.links if CTA_PATTERN.search(text))[:MAX_ITEMS]
        return Capture(
            url=checked.original, status=status, content_type=content_type,
            title=clean_text(" ".join(parser.title_parts), MAX_TITLE_LENGTH),
            description=clean_text(parser.description or "", MAX_DESCRIPTION_LENGTH),
            canonical=observed_route(parser.canonical or ""),
            forms=tuple((clean_text(method, 20), observed_route(action)) for method, action in parser.forms),
            cta_links=ctas,
        )
    except (BoundaryError, OSError, ssl.SSLError, http.client.HTTPException, ValueError, LookupError) as error:
        return Capture(url=checked.original, status="unavailable", error=type(error).__name__)
    finally:
        watchdog.cancel()
        connection.abort_active_socket()
        connection.close()


def bounded_report(lines: Iterable[str]) -> str:
    kept: list[str] = []
    suffix = "[Report truncated at the 64 KiB safety limit.]\n"
    suffix_size, used = len(suffix.encode()), 0
    for line in lines:
        rendered = line + "\n"
        size = len(rendered.encode())
        if used + size + suffix_size > MAX_REPORT_BYTES:
            return "".join(kept) + suffix
        kept.append(rendered)
        used += size
    return "".join(kept)


def render(captures: Iterable[Capture], captured_at: datetime | None = None) -> str:
    items = list(captures)
    captured_at = captured_at or datetime.now(timezone.utc)
    lines = [
        "# Public-path evidence capture", "", f"Captured: {captured_at.isoformat()}", "",
        "## Method boundary", "",
        "Only the explicitly listed public HTTPS URLs were fetched with GET. DNS answers and connected peers were restricted to public addresses. No redirects were followed; no accounts, forms, purchases, messages, cookies, scripts, or private systems were used.",
        "", "## Route evidence", "",
        "| Route | Result | HTML title | Canonical | Forms | CTA-like links |",
        "|---|---|---|---|---:|---:|",
    ]
    for number, item in enumerate(items, 1):
        lines.append(f"| {number}: {plain_markdown(item.url)} | {plain_markdown(item.status)} | {plain_markdown(item.title or '—')} | {plain_markdown(item.canonical or '—')} | {len(item.forms)} | {len(item.cta_links)} |")
    for number, item in enumerate(items, 1):
        lines.extend(["", f"## Route {number}", "", f"- Result: {plain_markdown(item.status)}"])
        lines.append(f"- Requested public route: {plain_markdown(item.url)}")
        if item.content_type:
            lines.append(f"- Content type: {plain_markdown(item.content_type)}")
        if item.description:
            lines.append(f"- Public meta description: {plain_markdown(item.description)}")
        if item.error:
            lines.append(f"- Capture note: {plain_markdown(item.error)}")
        if item.forms:
            lines.append("- Forms observed but not submitted:")
            lines.extend(f"  - Method {plain_markdown(method)}; action {plain_markdown(action or '(same route)')}" for method, action in item.forms)
        if item.cta_links:
            lines.append("- CTA-like public links observed but not followed:")
            lines.extend(f"  - Text {plain_markdown(text)}; destination {plain_markdown(href)}" for text, href in item.cta_links)
    return bounded_report(lines)


def parse_urls_json(value: str) -> list[str]:
    try:
        urls = json.loads(value)
    except (json.JSONDecodeError, TypeError) as error:
        raise BoundaryError("urls-json must be valid JSON") from error
    if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS or not all(isinstance(url, str) for url in urls):
        raise BoundaryError("urls-json must contain one to five strings")
    if len(set(urls)) != len(urls):
        raise BoundaryError("urls-json must not contain duplicate routes")
    return urls


def create_report(runner_temp_value: str, report: str) -> Path:
    if not runner_temp_value or any(ord(character) < 32 for character in runner_temp_value):
        raise BoundaryError("runner temp path is unavailable")
    runner_temp = Path(runner_temp_value)
    if runner_temp.is_symlink() or not runner_temp.is_absolute() or not runner_temp.is_dir():
        raise BoundaryError("runner temp path is invalid")
    directory = runner_temp / "public-path-evidence-audit"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise BoundaryError("private report directory already exists") from error
    if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise BoundaryError("private report directory is unsafe")
    report_path = directory / "report.md"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(report_path, flags, 0o600)
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise BoundaryError("private report permissions are unsafe")
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(report)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return report_path.resolve()


def write_github_outputs(report_path: Path, route_count: int, html_count: int) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with Path(output_file).open("a", encoding="utf-8") as stream:
        stream.write(f"report-path={report_path}\nroute-count={route_count}\nhtml-count={html_count}\n")


def require_supported_runner() -> None:
    if os.environ.get("PPA_RUNNER_ENVIRONMENT") != "github-hosted" or os.environ.get("PPA_RUNNER_OS") != "Linux":
        raise BoundaryError("v1 supports GitHub-hosted Linux runners only")


def main() -> int:
    try:
        require_supported_runner()
        urls = parse_urls_json(os.environ.get("PPA_URLS_JSON", ""))
        parsed_urls = [parse_url(url) for url in urls]
        run_deadline = time.monotonic() + TOTAL_RUN_SECONDS
        captures: list[Capture] = []
        for parsed in parsed_urls:
            route_deadline = min(run_deadline, time.monotonic() + TOTAL_ROUTE_SECONDS)
            checked = resolve_checked_url(parsed, route_deadline)
            captures.append(capture(checked, route_deadline))
        remaining_seconds(run_deadline)
        report = render(captures)
        remaining_seconds(run_deadline)
        report_path = create_report(os.environ.get("PPA_RUNNER_TEMP", ""), report)
        html_count = sum(item.status.startswith("HTTP 2") and item.content_type in {"text/html", "application/xhtml+xml"} and not item.error for item in captures)
        write_github_outputs(report_path, len(captures), html_count)
    except BoundaryError:
        print("public-path capture refused: safety boundary", file=sys.stderr)
        return 2
    except OSError:
        print("public-path capture failed: local I/O error", file=sys.stderr)
        return 2
    print(f"public-path capture complete: {len(captures)} route(s); {html_count} HTML summary(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
