#!/usr/bin/env python3
"""Webhook Intake HTTP server.

The server accepts POST requests on the configured endpoint (``/webhook`` by
default), identifies matching profiles, renders a message, and delivers it to
a file, a POSIX FIFO, or both. It accepts generic JSON or plain-text payloads.

Configuration is read from an INI file. Server settings live in ``[webhook]``;
profiles are loaded from ``*.conf`` files in ``profile_dir``. A profile can
match payload fields, the network source, or act as a catch-all fallback.

Run ``python3 webhook.py --help`` for command-line options. This module uses
the Python standard library and requires Python 3.11 or later. OpenSSL is
also required only when generating a self-signed TLS certificate.
"""

from __future__ import annotations

import argparse
import configparser
import errno
import ipaddress
import json
import os
import re
import signal
import shutil
import ssl
import stat
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

JSONL_SUFFIXES = {".jsonl", ".ndjson"}
YAML_SUFFIXES = {".yaml", ".yml"}


class DeliveryError(Exception):
    """Failure in a delivery configured as required."""


def create_self_signed_certificate(cert_file: Path, key_file: Path, common_name: str, days: int) -> None:
    """Creates a development TLS certificate with OpenSSL and restrictive key permissions."""
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        try:
            ipaddress.ip_address(common_name)
            subject_alt_name = f"IP:{common_name}"
        except ValueError:
            subject_alt_name = f"DNS:{common_name}"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file), "-days", str(days),
                "-subj", f"/CN={common_name}", "-addext", f"subjectAltName={subject_alt_name}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ValueError("OpenSSL is required to generate a self-signed TLS certificate") from exc
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"failed to generate self-signed TLS certificate: {exc.stderr.strip()}") from exc
    key_file.chmod(0o600)


def build_tls_context(config: dict[str, Any]) -> ssl.SSLContext | None:
    """Builds TLS configuration, optionally creating a self-signed certificate.

    Existing certificate and key files are reused. If either is missing,
    ``tls_self_signed = true`` creates both; otherwise startup fails instead
    of silently serving plain HTTP.
    """
    if not config.get("tls_enabled", False):
        return None
    cert_file = Path(config["tls_cert_file"])
    key_file = Path(config["tls_key_file"])
    if not cert_file.exists() or not key_file.exists():
        if not config.get("tls_self_signed", False):
            raise ValueError("TLS certificate or key is missing; provide both files or enable tls_self_signed")
        if cert_file.exists() or key_file.exists():
            raise ValueError("cannot create a self-signed certificate when only one TLS file exists")
        create_self_signed_certificate(
            cert_file,
            key_file,
            config.get("tls_self_signed_common_name", "localhost"),
            config.get("tls_self_signed_days", 365),
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def update_ini_values(path: Path, values: dict[str, str]) -> None:
    """Updates existing INI key values without discarding comments or layout."""
    content = path.read_text(encoding="utf-8")
    for key, value in values.items():
        pattern = rf"(?m)^({re.escape(key)}\s*=\s*).*$"
        content, replacements = re.subn(pattern, rf"\g<1>{value}", content)
        if replacements != 1:
            raise ValueError(f"expected exactly one '{key}' setting in {path}")
    path.write_text(content, encoding="utf-8")


def run_certbot_mode(config_path: Path, ip_address: str, email: str, staging: bool, assume_yes: bool) -> None:
    """Requests a public IP certificate with Certbot, configures TLS, then exits.

    Certbot's standalone challenge must bind TCP/80 and be reachable from the
    Internet. IP address certificates are short-lived, so renewal automation
    and a service restart after renewal are still required.
    """
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("--certbot-ip must be a valid IPv4 or IPv6 address") from exc
    if not address.is_global:
        raise ValueError("--certbot-ip must be a globally routable public IP address")
    if not email or "@" not in email:
        raise ValueError("--certbot-email must contain a valid contact email address")
    if not shutil.which("certbot"):
        raise ValueError("Certbot is required; install Certbot 5.4 or later before using --certbot-mode")

    tls_dir = config_path.parent / "tls"
    certbot_dir = tls_dir / ".certbot"
    certificate_name = "webhook-intake-ip"
    destination_cert = tls_dir / "webhook-intake.crt"
    destination_key = tls_dir / "webhook-intake.key"
    environment = "staging" if staging else "production"
    message = (
        "Certbot mode will request a publicly trusted IP-address certificate "
        f"for {ip_address} from the {environment} CA environment.\n"
        "It will temporarily bind TCP/80 for ACME validation, write Certbot "
        f"state under {certbot_dir}, copy the certificate and key to {tls_dir}, "
        "and update config.ini to enable HTTPS.\n"
        "IP certificates are short-lived and require automated renewal. Continue? [y/N] "
    )
    if not assume_yes:
        try:
            approved = input(message).strip().lower() in {"y", "yes"}
        except EOFError as exc:
            raise ValueError("interactive confirmation unavailable; rerun with --certbot-yes") from exc
        if not approved:
            print("Certbot mode cancelled; no certificate was requested.", flush=True)
            return
    else:
        print(message.replace("Continue? [y/N] ", "Confirmed with --certbot-yes."), flush=True)

    tls_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--email", email, "--preferred-profile", "shortlived", "--ip-address", ip_address,
        "--cert-name", certificate_name, "--config-dir", str(certbot_dir),
        "--work-dir", str(certbot_dir / "work"), "--logs-dir", str(certbot_dir / "logs"),
    ]
    if staging:
        command.append("--staging")
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"Certbot failed with exit code {exc.returncode}; config.ini was not changed") from exc

    issued_cert = certbot_dir / "live" / certificate_name / "fullchain.pem"
    issued_key = certbot_dir / "live" / certificate_name / "privkey.pem"
    if not issued_cert.is_file() or not issued_key.is_file():
        raise ValueError("Certbot completed but did not create the expected certificate files")
    shutil.copy2(issued_cert, destination_cert)
    shutil.copy2(issued_key, destination_key)
    destination_key.chmod(0o600)
    update_ini_values(config_path, {
        "tls_enabled": "true",
        "tls_self_signed": "false",
        "tls_cert_file": "./tls/webhook-intake.crt",
        "tls_key_file": "./tls/webhook-intake.key",
    })
    print(
        f"Certificate request succeeded. HTTPS is configured in {config_path}; "
        f"certificate: {destination_cert}; key: {destination_key}",
        flush=True,
    )


def get_field(value: Any, path: str) -> Any:
    """Gets a nested field (`a.b.0.c`), returning None if it does not exist."""
    current = value
    parts = path.split(".")
    for index, part in enumerate(parts):
        # Some senders deliver body as a string that contains JSON.
        # This enables rules such as body.metadata.severity without preprocessing.
        if isinstance(current, str) and index < len(parts):
            try:
                current = json.loads(current)
            except json.JSONDecodeError:
                # A dotted path cannot continue through plain text.
                return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def rule_matches(payload: Any, rule: dict[str, Any]) -> bool:
    """Returns whether one payload field satisfies an equality, contains, or regex rule.

    ``rule`` has a dotted ``field`` path and exactly one comparison key:
    ``equals``, ``contains``, ``regex``, or ``value``. The latter is an alias
    for exact equality used by the shorter INI notation.
    """
    candidate = get_field(payload, rule.get("field", ""))
    if candidate is None:
        return False
    candidate = str(candidate)
    if "equals" in rule:
        return candidate == str(rule["equals"])
    if "contains" in rule:
        return str(rule["contains"]) in candidate
    if "regex" in rule:
        return re.search(str(rule["regex"]), candidate) is not None
    # Forma curta: field = "severity", value = "CRITICAL"
    return candidate == str(rule.get("value", ""))


def origin_matches(profile: dict[str, Any], origin: str) -> bool:
    """Applies network source filters declared directly in the profile."""
    if "origin" in profile and origin != profile["origin"]:
        return False
    if "origin_regex" in profile and re.search(str(profile["origin_regex"]), origin) is None:
        return False
    if "origin_cidr" in profile:
        try:
            # ``strict=False`` also accepts a host address written with a CIDR mask.
            if ipaddress.ip_address(origin) not in ipaddress.ip_network(profile["origin_cidr"], strict=False):
                return False
        except ValueError:
            return False
    return True


def profile_matches(profile: dict[str, Any], payload: Any, origin: str = "") -> bool:
    """Returns whether a profile applies to a payload received from ``origin``.

    Network-source constraints are checked first. A catch-all profile bypasses
    payload rules, while a normal profile requires every ``match`` rule to
    succeed.
    """
    if not origin_matches(profile, origin):
        return False
    if profile.get("catch_all", False):
        return True
    rules = profile.get("match", [])
    return bool(rules) and all(rule_matches(payload, rule) for rule in rules)


class SafeFormat(dict[str, Any]):
    """Template mapping that renders unknown ``str.format_map`` fields as empty."""
    def __missing__(self, key: str) -> str:
        return ""


def yaml_scalar(value: Any) -> str:
    """Renders a scalar in the restricted YAML representation used by ``to_yaml``."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def to_yaml(value: Any, indent: int = 0) -> str:
    """Conservative YAML serializer for records; strings are always quoted."""
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(to_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(to_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{prefix}{yaml_scalar(value)}"


def render(profile: dict[str, Any], raw: bytes, payload: Any, metadata: dict[str, str]) -> bytes:
    """Renders one delivery according to the profile's ``format`` setting.

    ``raw`` preserves the incoming bytes. Structured formats use decoded JSON
    when available; otherwise they store the raw body with delivery metadata.
    Text templates receive top-level JSON keys plus ``received_at``,
    ``content_type``, ``origin``, and ``raw``.
    """
    output_format = profile.get("format", "jsonl")
    if output_format == "raw":
        # One newline separates deliveries while preserving the received bytes.
        return raw.rstrip(b"\n") + b"\n"

    record = payload if isinstance(payload, (dict, list)) else {**metadata, "raw": raw.decode("utf-8", "replace")}
    if output_format == "jsonl":
        # JSONL is append-only: one compact JSON value per physical line.
        return (json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str) + "\n").encode()
    if output_format == "yaml":
        return (to_yaml(record) + "\n---\n").encode()
    if output_format == "text":
        fields = SafeFormat(metadata)
        if isinstance(payload, dict):
            fields.update(payload)
        template = profile.get("text_template", "{raw}")
        fields["raw"] = raw.decode("utf-8", "replace")
        try:
            # ``SafeFormat`` intentionally turns missing optional payload fields into "".
            return (template.format_map(fields).rstrip("\n") + "\n").encode()
        except (ValueError, KeyError) as exc:
            raise ValueError(f"invalid text_template: {exc}") from exc
    raise ValueError(f"invalid format: {output_format}")


class App:
    """Owns output paths, delivery synchronization, and message routing.

    One ``App`` instance is shared by all HTTP handler threads. ``self.lock``
    serializes output writes so concurrent deliveries do not interleave.
    """
    def __init__(self, config: dict[str, Any], debug: bool) -> None:
        self.config = config
        self.debug = debug or bool(config.get("debug", False))
        self.output_dir = Path(config.get("output_dir", "./output")).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def output_path(self, value: str) -> Path:
        """Resolves an absolute path as-is or a relative path below ``output_dir``."""
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.output_dir / path

    def rotation_archive_path(self, destination: Path) -> Path:
        """Builds a collision-free archive name beside the active output file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for sequence in range(1, 1_000_000):
            archive = destination.with_name(f"{destination.stem}.{timestamp}.{sequence:03d}{destination.suffix}")
            if not archive.exists():
                return archive
        raise DeliveryError(f"could not create a unique rotation name for {destination}")

    def prune_archives(self, destination: Path, keep: int) -> None:
        """Keeps the newest ``keep`` archives created by this rotation scheme."""
        prefix = f"{destination.stem}."
        archives = sorted(
            (path for path in destination.parent.glob(f"{destination.stem}.*{destination.suffix}")
             if path.name.startswith(prefix) and path != destination),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for archive in archives[keep:]:
            archive.unlink()

    def rotate_file(self, destination: Path, profile: dict[str, Any]) -> None:
        """Archives an active file by rename or copy-and-truncate, then prunes history.

        ``rename`` keeps the old inode intact for consumers that reopen files by
        name. ``copytruncate`` retains the active inode for legacy consumers,
        but they can miss unread data at truncation time.
        """
        archive = self.rotation_archive_path(destination)
        mode = profile.get("rotation_mode", "rename")
        if mode == "rename":
            destination.replace(archive)
        else:  # ``rotation_mode`` has already been validated during config load.
            # The application lock prevents its own writers from changing the file
            # between the copy and truncate operations.
            shutil.copy2(destination, archive)
            with destination.open("r+b") as active_file:
                active_file.truncate(0)
        self.prune_archives(destination, profile.get("rotate_keep", 10))

    def write_file(self, destination: Path, content: bytes, profile: dict[str, Any]) -> None:
        """Appends one delivery and rotates first when the configured size is reached."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        rotate_max_bytes = profile.get("rotate_max_bytes", 0)
        if destination.exists() and rotate_max_bytes:
            size = destination.stat().st_size
            # Do not rotate an empty file repeatedly when one message exceeds the limit.
            if size > 0 and size + len(content) > rotate_max_bytes:
                self.rotate_file(destination, profile)
        with destination.open("ab") as output:
            output.write(content)

    def deliver_fifo(self, profile: dict[str, Any], content: bytes) -> bool:
        """Non-blocking delivery; returns False when no reader exists and policy is warn."""
        pipe_path = self.output_path(profile["fifo_path"])
        pipe_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            info = pipe_path.stat()
        except FileNotFoundError:
            # Create the named pipe lazily so unused FIFO profiles do not create files.
            os.mkfifo(pipe_path, 0o660)
        else:
            if not stat.S_ISFIFO(info.st_mode):
                raise DeliveryError(f"FIFO path is not a pipe: {pipe_path}")

        try:
            pipe_buf = os.pathconf(pipe_path, "PC_PIPE_BUF")
            if len(content) > pipe_buf:
                raise DeliveryError(f"message with {len(content)} bytes exceeds PIPE_BUF ({pipe_buf}) for {pipe_path}")
            descriptor = os.open(pipe_path, os.O_WRONLY | os.O_NONBLOCK)
            try:
                # A single write up to PIPE_BUF is atomic for a POSIX FIFO.
                written = os.write(descriptor, content)
            finally:
                os.close(descriptor)
            if written != len(content):
                raise DeliveryError(f"partial FIFO write: {pipe_path}")
            return True
        except OSError as exc:
            if profile.get("fifo_on_unavailable", "warn") == "warn" and exc.errno in {errno.ENXIO, errno.EAGAIN, errno.EWOULDBLOCK}:
                if self.debug:
                    print(f"Warning: FIFO has no reader or is full ({pipe_path}); delivery skipped", file=sys.stderr, flush=True)
                return False
            raise DeliveryError(f"failed to deliver to FIFO {pipe_path}: {exc.strerror}") from exc

    def receive(self, raw: bytes, content_type: str, origin: str = "") -> list[str]:
        """Routes an incoming message to matching profiles and returns their names.

        Normal profiles are considered first. Catch-all profiles are evaluated
        only when no normal profile matches. A ``DeliveryError`` signals an
        explicitly required delivery failure to the HTTP handler.
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            payload: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        metadata = {"received_at": now, "content_type": content_type, "origin": origin}
        profiles = self.config.get("profiles", [])
        # Catch-all profiles are deliberately held back until no normal rule matches.
        targets = [p for p in profiles if not p.get("catch_all", False) and profile_matches(p, payload, origin)]
        if not targets:
            targets = [p for p in profiles if p.get("catch_all", False) and profile_matches(p, payload, origin)]
        if not targets:
            raise ValueError("no profile matched the message")

        written: list[str] = []
        # File appends and FIFO creation/writes share one lock to prevent interleaving.
        with self.lock:
            for profile in targets:
                content = render(profile, raw, payload, metadata)
                delivery = profile.get("delivery", "file")
                if delivery in {"file", "both"}:
                    destination = self.output_path(profile["file"])
                    self.write_file(destination, content, profile)
                if delivery in {"fifo", "both"}:
                    self.deliver_fifo(profile, content)
                written.append(profile.get("name", profile.get("file", profile.get("fifo_path", "profile"))))
                if profile.get("stop_after_match", False):
                    break
        if self.debug:
            preview = raw.decode("utf-8", "replace")
            print(f"[{now}] origin={origin} profiles={written} content-type={content_type} body={preview}", flush=True)
        return written


def make_handler(app: App, endpoint: str, max_body_bytes: int, trust_forwarded_for: bool = False) -> type[BaseHTTPRequestHandler]:
    """Builds a request-handler class bound to one application configuration.

    The generated handler accepts only POST requests for ``endpoint`` and a
    lightweight GET health check at ``/healthz``. When proxy forwarding is
    trusted, the first address in ``X-Forwarded-For`` becomes the origin.
    """
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] == "/healthz":
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}\n')
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != endpoint:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
                return
            if length < 0 or length > max_body_bytes:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body too large")
                return
            raw = self.rfile.read(length)
            origin = self.client_address[0]
            if trust_forwarded_for:
                # Only trust this client-controlled header when a trusted proxy is configured.
                origin = self.headers.get("X-Forwarded-For", origin).split(",", 1)[0].strip()
            try:
                profiles = app.receive(raw, self.headers.get("Content-Type", ""), origin)
            except DeliveryError as exc:
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
                return
            except (KeyError, ValueError) as exc:
                self.send_error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
                return
            self.send_response(HTTPStatus.ACCEPTED)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "stored", "profiles": profiles}).encode() + b"\n")

        def log_message(self, fmt: str, *args: Any) -> None:
            if app.debug:
                super().log_message(fmt, *args)

    return Handler


def new_ini_parser() -> configparser.ConfigParser:
    """Creates the INI parser while preserving case in JSON field paths."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # JSON fields, such as alarmMetaData, are case-sensitive
    return parser


def profile_from_section(parser: configparser.ConfigParser, section: str) -> dict[str, Any]:
    """Converts one ``[profile:name]`` INI section into a validated profile.

    File delivery requires ``file``; FIFO delivery requires ``fifo_path``.
    ``delivery`` accepts ``file``, ``fifo``, or ``both`` and defaults to file.
    """
    values = dict(parser[section])
    profile: dict[str, Any] = {key: value for key, value in values.items() if not key.startswith("match.")}
    profile["name"] = section.removeprefix("profile:")
    for option in ("enabled", "catch_all", "stop_after_match"):
        if option in profile:
            profile[option] = parser.getboolean(section, option)
    rules: list[dict[str, str]] = []
    for key, value in values.items():
        if not key.startswith("match."):
            continue
        try:
            field, operation = key.removeprefix("match.").rsplit(".", 1)
        except ValueError as exc:
            raise ValueError(f"invalid INI rule in [{section}]: {key}") from exc
        if operation not in {"equals", "contains", "regex", "value"}:
            raise ValueError(f"invalid rule operation in [{section}]: {operation}")
        rules.append({"field": field, operation: value})
    output_format = profile.get("format", "jsonl")
    if output_format not in {"raw", "text", "jsonl", "yaml"}:
        raise ValueError(f"invalid format in [{section}]: {output_format}; use jsonl instead of json")
    if "file" in profile:
        suffix = Path(profile["file"]).suffix.lower()
        if output_format == "jsonl" and suffix not in JSONL_SUFFIXES:
            raise ValueError(f"JSONL output in [{section}] requires a .jsonl or .ndjson file")
        if output_format == "yaml" and suffix not in YAML_SUFFIXES:
            raise ValueError(f"YAML output in [{section}] requires a .yaml or .yml file")

    delivery = profile.get("delivery", "file")
    if delivery not in {"file", "fifo", "both"}:
        raise ValueError(f"invalid delivery in [{section}]: {delivery}")
    if delivery in {"file", "both"} and "file" not in profile:
        raise ValueError(f"profile [{section}] must define 'file' for delivery = {delivery}")
    if delivery in {"fifo", "both"} and "fifo_path" not in profile:
        raise ValueError(f"profile [{section}] must define 'fifo_path' for delivery = {delivery}")
    if profile.get("fifo_on_unavailable", "warn") not in {"warn", "fail"}:
        raise ValueError(f"invalid fifo_on_unavailable in [{section}]")
    if "rotate_max_bytes" in profile:
        try:
            profile["rotate_max_bytes"] = int(profile["rotate_max_bytes"])
        except ValueError as exc:
            raise ValueError(f"invalid rotate_max_bytes in [{section}]") from exc
        if profile["rotate_max_bytes"] < 0:
            raise ValueError(f"rotate_max_bytes must be zero or greater in [{section}]")
    if "rotate_keep" in profile:
        try:
            profile["rotate_keep"] = int(profile["rotate_keep"])
        except ValueError as exc:
            raise ValueError(f"invalid rotate_keep in [{section}]") from exc
        if profile["rotate_keep"] < 0:
            raise ValueError(f"rotate_keep must be zero or greater in [{section}]")
    if profile.get("rotation_mode", "rename") not in {"rename", "copytruncate"}:
        raise ValueError(f"invalid rotation_mode in [{section}]")
    if profile.get("rotate_max_bytes", 0) and delivery not in {"file", "both"}:
        raise ValueError(f"rotation requires file or both delivery in [{section}]")
    profile["match"] = rules
    return profile


def load_profile_directory(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Reads valid INI profiles from profile.d; one bad file does not stop the service."""
    profiles: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not directory.is_dir():
        return profiles, warnings
    for path in sorted(directory.glob("*.conf")):
        # Stable order makes profile evaluation predictable across restarts.
        parser = new_ini_parser()
        try:
            with path.open(encoding="utf-8") as file:
                parser.read_file(file)
            sections = [section for section in parser.sections() if section.startswith("profile:")]
            if not sections:
                raise ValueError("no [profile:name] section found")
            file_profiles = [
                profile for section in sections
                for profile in [profile_from_section(parser, section)] if profile.get("enabled", True)
            ]
        except (OSError, configparser.Error, ValueError) as exc:
            warnings.append(f"profile ignored ({path}): {exc}")
            continue
        profiles.extend(file_profiles)
    return profiles, warnings


def load_config(path: Path) -> dict[str, Any]:
    """Loads server settings and active profiles from an INI configuration file.

    The main INI file intentionally cannot declare profiles. It supplies
    ``profile_dir`` instead, keeping reusable profile definitions separate
    from host-specific listener settings.
    """
    if path.suffix.lower() != ".ini":
        raise ValueError("use an INI configuration file")
    parser = new_ini_parser()
    with path.open(encoding="utf-8") as file:
        parser.read_file(file)
    if not parser.has_section("webhook"):
        raise ValueError("the INI file must contain a [webhook] section")
    if any(section.startswith("profile:") for section in parser.sections()):
        raise ValueError("profiles must be in *.conf files under profile_dir, not config.ini")
    config = dict(parser["webhook"])
    output_dir = Path(config.get("output_dir", "output")).expanduser()
    if not output_dir.is_absolute():
        output_dir = path.parent / output_dir
    config["output_dir"] = str(output_dir)
    for option in ("port", "max_body_bytes"):
        if option in config:
            config[option] = int(config[option])
    for option in ("debug", "trust_forwarded_for"):
        config[option] = parser.getboolean("webhook", option, fallback=False)
    config["tls_enabled"] = parser.getboolean("webhook", "tls_enabled", fallback=False)
    config["tls_self_signed"] = parser.getboolean("webhook", "tls_self_signed", fallback=False)
    try:
        config["tls_self_signed_days"] = parser.getint("webhook", "tls_self_signed_days", fallback=365)
    except ValueError as exc:
        raise ValueError("tls_self_signed_days must be an integer") from exc
    if config["tls_self_signed_days"] <= 0:
        raise ValueError("tls_self_signed_days must be greater than zero")
    for option, default in (("tls_cert_file", "tls/webhook-intake.crt"), ("tls_key_file", "tls/webhook-intake.key")):
        tls_path = Path(config.get(option, default)).expanduser()
        if not tls_path.is_absolute():
            tls_path = path.parent / tls_path
        config[option] = str(tls_path)
    config["tls_self_signed_common_name"] = config.get("tls_self_signed_common_name", "localhost")
    profile_dir = Path(config.get("profile_dir", "profile.d"))
    if not profile_dir.is_absolute():
        profile_dir = path.parent / profile_dir
    config["profiles"], config["profile_warnings"] = load_profile_directory(profile_dir)
    if not config.get("profiles"):
        raise ValueError("configuration must contain at least one profile")
    return config


def main() -> None:
    """Parses CLI overrides, starts the threaded HTTP server, and handles shutdown."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.ini"))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--certbot-mode", action="store_true", help="request a public IP certificate with Certbot, configure TLS, and exit")
    parser.add_argument("--certbot-ip", help="public IPv4 or IPv6 address for --certbot-mode")
    parser.add_argument("--certbot-email", help="contact email required by Certbot")
    parser.add_argument("--certbot-staging", action="store_true", help="use the untrusted Certbot staging CA")
    parser.add_argument("--certbot-yes", action="store_true", help="skip the interactive confirmation in --certbot-mode")
    args = parser.parse_args()
    if args.certbot_mode:
        if not args.certbot_ip:
            parser.error("--certbot-mode requires --certbot-ip")
        if not args.certbot_email:
            parser.error("--certbot-mode requires --certbot-email")
        run_certbot_mode(args.config, args.certbot_ip, args.certbot_email, args.certbot_staging, args.certbot_yes)
        return
    if args.certbot_ip or args.certbot_email or args.certbot_staging or args.certbot_yes:
        parser.error("--certbot-* options require --certbot-mode")
    config = load_config(args.config)
    for warning in config.get("profile_warnings", []):
        print(f"Warning: {warning}", file=sys.stderr, flush=True)
    app = App(config, args.debug)
    host = args.host or config.get("host", "127.0.0.1")
    port = args.port or int(config.get("port", 8080))
    endpoint = config.get("path", "/webhook")
    if not endpoint.startswith("/"):
        raise ValueError("path must start with '/'")
    tls_context = build_tls_context(config)
    server = ThreadingHTTPServer((host, port), make_handler(
        app, endpoint, int(config.get("max_body_bytes", 1048576)), bool(config.get("trust_forwarded_for", False))
    ))
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if tls_context else "http"
    print(f"Webhook listening on {scheme}://{host}:{port}{endpoint}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: server.shutdown())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
