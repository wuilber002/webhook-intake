import json
import os
import base64
import shutil
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from http.client import HTTPConnection, HTTPSConnection
from http.server import ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

# Allow both ``python tests/test_webhook.py`` and unittest discovery from the
# repository root without requiring package installation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webhook import App, BasicAuth, DeliveryError, basic_auth_is_valid, build_tls_context, create_basic_auth_password_file, ensure_local_config, load_basic_auth, load_config, make_handler, password_hash_record, profile_matches, render, update_ini_values


class WebhookTests(unittest.TestCase):
    def test_rules_support_nested_fields(self):
        profile = {"match": [{"field": "alarm.severity", "equals": "CRITICAL"}]}
        self.assertTrue(profile_matches(profile, {"alarm": {"severity": "CRITICAL"}}))
        self.assertFalse(profile_matches(profile, {"alarm": {"severity": "INFO"}}))

    def test_rules_support_json_inside_encoded_body(self):
        profile = {"match": [{"field": "body.metadata.severity", "equals": "CRITICAL"}]}
        payload = {"body": '{"metadata":{"severity":"CRITICAL"}}'}
        self.assertTrue(profile_matches(profile, payload))

    def test_profile_can_match_network_origin(self):
        profile = {"catch_all": True, "origin_cidr": "10.0.0.0/24"}
        self.assertTrue(profile_matches(profile, {}, "10.0.0.15"))
        self.assertFalse(profile_matches(profile, {}, "10.0.1.15"))
        self.assertTrue(profile_matches({"catch_all": True, "origin": "192.0.2.10"}, {}, "192.0.2.10"))

    def test_ini_config_loads_profiles_and_tcp_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.ini"
            (Path(directory) / "profile.d").mkdir()
            (Path(directory) / "profile.d" / "critical.conf").write_text("""[profile:critical]\nfile = critical.raw\nformat = raw\nmatch.body.alarmMetaData.severity.equals = CRITICAL\n""")
            path.write_text("""[webhook]\nport = 1604\nprofile_dir = profile.d\n""")
            config = load_config(path)
            self.assertEqual(config["port"], 1604)
            self.assertEqual(config["output_dir"], str(Path(directory) / "output"))
            self.assertEqual(config["profiles"][0]["match"], [{"field": "body.alarmMetaData.severity", "equals": "CRITICAL"}])

    def test_ini_loads_valid_profile_d_files_and_ignores_invalid_ones(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "profile.d").mkdir()
            (root / "config.ini").write_text("[webhook]\nprofile_dir = profile.d\n")
            (root / "profile.d" / "00-base.conf").write_text("[profile:base]\nfile = base.raw\nformat = raw\ncatch_all = true\n")
            (root / "profile.d" / "10-valid.conf").write_text("[profile:warning]\nfile = warning.txt\nformat = text\nmatch.severity.equals = WARNING\n")
            (root / "profile.d" / "20-invalid.conf").write_text("[profile:broken]\nformat = json\n")
            (root / "profile.d" / "ignore.ini").write_text("[profile:ignored]\nfile = ignored.raw\n")
            config = load_config(root / "config.ini")
            self.assertEqual([profile["name"] for profile in config["profiles"]], ["base", "warning"])
            self.assertEqual(len(config["profile_warnings"]), 1)

    def test_ini_rejects_profiles_outside_profile_d(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.ini"
            path.write_text("[webhook]\n\n[profile:not-allowed]\nfile = no.raw\n")
            with self.assertRaisesRegex(ValueError, "profile_dir"):
                load_config(path)

    def test_matching_profiles_write_separate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [
                {"name": "critical", "file": "critical.jsonl", "format": "jsonl", "match": [{"field": "severity", "equals": "CRITICAL"}]},
                {"name": "all", "file": "all.txt", "format": "text", "text_template": "{title}", "catch_all": True},
            ]}, False)
            profiles = app.receive(b'{"severity":"CRITICAL","title":"CPU alta"}', "application/json")
            self.assertEqual(profiles, ["critical"])
            self.assertEqual((Path(directory) / "critical.jsonl").read_text(), '{"severity":"CRITICAL","title":"CPU alta"}\n')
            self.assertFalse((Path(directory) / "all.txt").exists())

    def test_raw_non_json_is_preserved(self):
        result = render({"format": "raw"}, b"abc\n", None, {})
        self.assertEqual(result, b"abc\n")

    def test_fifo_delivery_creates_pipe_and_writes_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            pipe = Path(directory) / "alerts.fifo"
            app = App({"output_dir": directory, "profiles": [{"name": "pipe", "delivery": "fifo", "fifo_path": "alerts.fifo", "format": "text", "text_template": "{title}", "catch_all": True}]}, False)
            # Opening the reader first verifies an actual FIFO delivery.
            reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK) if pipe.exists() else None
            if reader is None:
                os.mkfifo(pipe)
                reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
            try:
                self.assertEqual(app.receive(b'{"title":"pipe ok"}', "application/json"), ["pipe"])
                self.assertEqual(os.read(reader, 4096), b"pipe ok\n")
            finally:
                os.close(reader)

    def test_fifo_without_reader_can_be_required(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"delivery": "fifo", "fifo_path": "alerts.fifo", "fifo_on_unavailable": "fail", "format": "raw", "catch_all": True}]}, False)
            with self.assertRaises(DeliveryError):
                app.receive(b"alert", "text/plain")

    def test_ini_validates_fifo_delivery_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "profile.d").mkdir()
            (root / "config.ini").write_text("[webhook]\nprofile_dir = profile.d\n")
            (root / "profile.d" / "pipe.conf").write_text("[profile:pipe]\ndelivery = fifo\nfifo_path = pipes/alerts.fifo\nformat = raw\ncatch_all = true\n")
            config = load_config(root / "config.ini")
            self.assertEqual(config["profiles"][0]["delivery"], "fifo")

    def test_ini_rejects_jsonl_with_json_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "profile.d").mkdir()
            (root / "config.ini").write_text("[webhook]\nprofile_dir = profile.d\n")
            (root / "profile.d" / "00-base.conf").write_text("[profile:base]\nfile = base.raw\nformat = raw\ncatch_all = true\n")
            (root / "profile.d" / "10-invalid.conf").write_text("[profile:invalid]\nfile = invalid.json\nformat = jsonl\ncatch_all = true\n")
            config = load_config(root / "config.ini")
            self.assertEqual([profile["name"] for profile in config["profiles"]], ["base"])
            self.assertIn("requires a .jsonl or .ndjson file", config["profile_warnings"][0])

    def test_ini_update_preserves_comments_and_changes_tls_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.ini"
            path.write_text("; keep this comment\ntls_enabled = false\ntls_cert_file = old.crt\ntls_key_file = old.key\ntls_self_signed = true\n")
            update_ini_values(path, {
                "tls_enabled": "true",
                "tls_cert_file": "./tls/webhook-intake.crt",
                "tls_key_file": "./tls/webhook-intake.key",
                "tls_self_signed": "false",
            })
            updated = path.read_text()
            self.assertIn("; keep this comment", updated)
            self.assertIn("tls_enabled = true", updated)
            self.assertIn("tls_cert_file = ./tls/webhook-intake.crt", updated)

    def test_missing_local_config_is_created_from_example(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            example = root / "config.ini.example"
            example.write_text("[webhook]\ntls_enabled = false\n")
            config = root / "config.ini"
            self.assertTrue(ensure_local_config(config))
            self.assertEqual(config.read_text(), example.read_text())
            self.assertFalse(ensure_local_config(config))

    def test_rename_rotation_archives_previous_content(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"name": "rotate", "file": "events.jsonl", "format": "jsonl", "rotate_max_bytes": 20, "rotate_keep": 2, "rotation_mode": "rename", "catch_all": True}]}, False)
            app.receive(b'{"title":"first"}', "application/json")
            app.receive(b'{"title":"second"}', "application/json")
            active = Path(directory) / "events.jsonl"
            archives = list(Path(directory).glob("events.*.jsonl"))
            self.assertEqual(active.read_text(), '{"title":"second"}\n')
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_text(), '{"title":"first"}\n')

    def test_copytruncate_rotation_keeps_active_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"name": "rotate", "file": "events.jsonl", "format": "jsonl", "rotate_max_bytes": 20, "rotate_keep": 2, "rotation_mode": "copytruncate", "catch_all": True}]}, False)
            app.receive(b'{"title":"first"}', "application/json")
            active = Path(directory) / "events.jsonl"
            inode_before = active.stat().st_ino
            app.receive(b'{"title":"second"}', "application/json")
            archives = list(Path(directory).glob("events.*.jsonl"))
            self.assertEqual(active.stat().st_ino, inode_before)
            self.assertEqual(active.read_text(), '{"title":"second"}\n')
            self.assertEqual(archives[0].read_text(), '{"title":"first"}\n')

    def test_file_rotation_uses_defaults_when_profile_omits_rotation_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = {"file": "events.jsonl", "format": "jsonl", "catch_all": True}
            app = App({"output_dir": directory, "profiles": [profile]}, False)
            # Keep this test small while verifying that omitted settings use the
            # production default path rather than silently disabling rotation.
            with patch("webhook.DEFAULT_ROTATE_MAX_BYTES", 20):
                app.receive(b'{"title":"first"}', "application/json")
                app.receive(b'{"title":"second"}', "application/json")
            archives = list(Path(directory).glob("events.*.jsonl"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_text(), '{"title":"first"}\n')

    def test_profile_can_explicitly_disable_default_file_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = {
                "file": "events.jsonl", "format": "jsonl", "catch_all": True,
                "rotate_max_bytes": 0,
            }
            app = App({"output_dir": directory, "profiles": [profile]}, False)
            with patch("webhook.DEFAULT_ROTATE_MAX_BYTES", 20):
                app.receive(b'{"title":"first"}', "application/json")
                app.receive(b'{"title":"second"}', "application/json")
            self.assertEqual(list(Path(directory).glob("events.*.jsonl")), [])
            self.assertEqual(
                (Path(directory) / "events.jsonl").read_text(),
                '{"title":"first"}\n{"title":"second"}\n',
            )

    def test_rotation_prunes_archives_beyond_retention_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"file": "events.jsonl", "format": "jsonl", "rotate_max_bytes": 20, "rotate_keep": 1, "catch_all": True}]}, False)
            for title in ("first", "second", "third"):
                app.receive(json.dumps({"title": title}).encode(), "application/json")
            archives = list(Path(directory).glob("events.*.jsonl"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_text(), '{"title":"second"}\n')
            self.assertEqual((Path(directory) / "events.jsonl").read_text(), '{"title":"third"}\n')

    def test_http_endpoint_accepts_message(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"file": "all.raw", "format": "raw", "catch_all": True}]}, False)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app, "/webhook", 1024))
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port)
                connection.request("POST", "/webhook", b'{"title":"teste"}', {"Content-Type": "application/json"})
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read()), {"status": "stored", "profiles": ["all.raw"]})
                self.assertEqual((Path(directory) / "all.raw").read_bytes(), b'{"title":"teste"}\n')
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_optional_basic_auth_protects_webhook_post(self):
        with tempfile.TemporaryDirectory() as directory:
            app = App({"output_dir": directory, "profiles": [{"file": "all.raw", "format": "raw", "catch_all": True}]}, False)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
                app, "/webhook", 1024, basic_auth=BasicAuth(b"webhook", "Webhook Intake", password=b"secret")
            ))
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port)
                connection.request("POST", "/webhook", b'{"title":"denied"}')
                response = connection.getresponse()
                self.assertEqual(response.status, 401)
                self.assertEqual(response.getheader("WWW-Authenticate"), 'Basic realm="Webhook Intake", charset="UTF-8"')
                response.read()

                token = base64.b64encode(b"webhook:secret").decode()
                connection.request("POST", "/webhook", b'{"title":"allowed"}', {"Authorization": f"Basic {token}"})
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                response.read()
                self.assertEqual((Path(directory) / "all.raw").read_bytes(), b'{"title":"allowed"}\n')
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_basic_auth_can_use_a_pbkdf2_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".faj383hfa"
            path.write_text(password_hash_record("secret") + "\n")
            path.chmod(0o600)
            credentials = load_basic_auth({
                "basic_auth_enabled": True,
                "basic_auth_username": "webhook",
                "basic_auth_password_file": str(path),
                "basic_auth_password_env": "UNUSED",
                "basic_auth_realm": "Webhook Intake",
            })
            valid = base64.b64encode(b"webhook:secret").decode()
            invalid = base64.b64encode(b"webhook:wrong").decode()
            self.assertTrue(basic_auth_is_valid(f"Basic {valid}", credentials))
            self.assertFalse(basic_auth_is_valid(f"Basic {invalid}", credentials))

    def test_password_file_creator_replaces_file_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".faj383hfa"
            path.write_text("old")
            with patch("webhook.getpass.getpass", side_effect=["new-secret", "new-secret"]):
                create_basic_auth_password_file(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            credentials = load_basic_auth({
                "basic_auth_enabled": True,
                "basic_auth_username": "webhook",
                "basic_auth_password_file": str(path),
                "basic_auth_realm": "Webhook Intake",
            })
            valid = base64.b64encode(b"webhook:new-secret").decode()
            self.assertTrue(basic_auth_is_valid(f"Basic {valid}", credentials))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for self-signed TLS test")
    def test_https_self_signed_certificate_accepts_message(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = App({"output_dir": directory, "profiles": [{"file": "all.raw", "format": "raw", "catch_all": True}]}, False)
            tls_context = build_tls_context({
                "tls_enabled": True,
                "tls_self_signed": True,
                "tls_cert_file": str(root / "tls" / "server.crt"),
                "tls_key_file": str(root / "tls" / "server.key"),
                "tls_self_signed_common_name": "127.0.0.1",
                "tls_self_signed_days": 1,
            })
            self.assertTrue((root / "tls" / "server.crt").exists())
            self.assertEqual((root / "tls" / "server.key").stat().st_mode & 0o777, 0o600)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app, "/webhook", 1024))
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                connection = HTTPSConnection("127.0.0.1", server.server_port, context=ssl._create_unverified_context())
                connection.request("POST", "/webhook", b'{"title":"tls"}', {"Content-Type": "application/json"})
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual((root / "all.raw").read_bytes(), b'{"title":"tls"}\n')
            finally:
                server.shutdown()
                thread.join()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
