"""Validate complete synthetic VPN configurations without a container runtime."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


COMMON = Path(__file__).resolve().parents[1] / "container" / "common.sh"
FIELDS = {
    "IPSec gateway": "192.0.2.1", "IPSec ID": "fixture-group",
    "IPSec secret": "PRIVATE_SHARED", "Xauth username": "PRIVATE_USER",
    "Xauth password": "PRIVATE_PASSWORD", "Interface MTU": "1412",
    "Enable weak encryption": "0",
}
SECRET_KEYS = ("IPSec secret", "Xauth username", "Xauth password")


def configuration(values=None):
    fields = dict(FIELDS)
    fields.update(values or {})
    return "".join(f"{key} {value}\n" for key, value in fields.items()).encode()


class ConfigurationTests(unittest.TestCase):
    def bash(self, body, *arguments, environment=None):
        settings = os.environ.copy()
        for name in ("VPN_GATEWAY", "VPN_IPSEC_ID", "VPN_DNS", "VPN_MTU", "VPN_ENABLE_WEAK_ENCRYPTION"):
            settings.pop(name, None)
        settings.update(environment or {})
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", 'source "$1"; shift; ' + body, "test", str(COMMON), *arguments],
            env=settings, capture_output=True, text=True, check=False,
        )

    def credentials(self, content, body="", environment=None):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "input.conf", Path(directory) / "output.conf"
            source.write_bytes(content)
            script = 'load_credentials "$1" "$2"' + (" && " + body if body else "")
            result = self.bash(script, str(source), str(destination), environment=environment)
            output = destination.read_bytes() if destination.exists() else None
            mode = destination.stat().st_mode & 0o777 if destination.exists() else None
            return result, output, mode

    def test_secrets_are_literal_private_and_separate_from_connection_settings(self):
        values = {"IPSec secret": "a*?[x]$HOME", "Xauth username": "user$(false)",
                  "Xauth password": '"a b"#comment`false`\\'}
        result, output, mode = self.credentials(configuration(values))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "".join(f"{key} {values[key]}\n" for key in SECRET_KEYS).encode())
        self.assertEqual(mode, 0o600)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_rejects_unsafe_configuration_without_echoing_values(self):
        valid = configuration()
        cases = {
            "duplicate": valid + b"Xauth password other\n",
            "duplicate connection": valid + b"IPSec gateway 203.0.113.1\n",
            "injected option": valid + b"Script /tmp/untrusted\n",
            "old environment key": valid + b"VPN_GATEWAY 203.0.113.1\n",
            "CRLF": valid.replace(b"\n", b"\r\n"), "NUL": valid + b"\x00\n",
            "NUL before large comment": valid + b"\x00\n#" + b"x" * 60000,
            "placeholder": valid.replace(b"PRIVATE_SHARED", b"REPLACE_WITH_IPSEC_SECRET"),
            "empty secret": valid.replace(b"PRIVATE_PASSWORD", b""),
            "oversized": valid + b"#" + b"x" * 65536,
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                result, output, _ = self.credentials(content)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("PRIVATE_", result.stderr)

    def test_every_required_field_must_be_in_the_file(self):
        old_environment = {"VPN_GATEWAY": "192.0.2.2", "VPN_IPSEC_ID": "environment-group",
                           "VPN_MTU": "1400", "VPN_ENABLE_WEAK_ENCRYPTION": "1"}
        for missing in ("IPSec gateway", "IPSec ID", *SECRET_KEYS):
            with self.subTest(missing=missing):
                content = "".join(f"{key} {value}\n" for key, value in FIELDS.items() if key != missing).encode()
                result, output, _ = self.credentials(content, environment=old_environment)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(output)

    def test_optional_mtu_and_weak_encryption_default_without_using_old_environment(self):
        content = "".join(f"{key} {value}\n" for key, value in FIELDS.items()
                          if key not in ("Interface MTU", "Enable weak encryption")).encode()
        result, _, _ = self.credentials(content, body='printf "%s|%s" "$VPN_MTU" "$VPN_ENABLE_WEAK_ENCRYPTION"',
                                        environment={"VPN_MTU": "1490", "VPN_ENABLE_WEAK_ENCRYPTION": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1412|0")

    def test_file_settings_override_old_environment_and_are_exported(self):
        old_environment = {"VPN_GATEWAY": "203.0.113.1", "VPN_IPSEC_ID": "environment-group",
                           "VPN_DNS": "203.0.113.53", "VPN_MTU": "1490", "VPN_ENABLE_WEAK_ENCRYPTION": "1"}
        body = 'bash -c \'printf "%s|%s|%s|%s|%s" "$VPN_GATEWAY" "$VPN_IPSEC_ID" "$VPN_DNS" "$VPN_MTU" "$VPN_ENABLE_WEAK_ENCRYPTION"\''
        for fields, expected in (({"VPN DNS": "198.18.0.53,198.18.0.54"}, "192.0.2.1|fixture-group|198.18.0.53,198.18.0.54|1412|0"),
                                 ({}, "192.0.2.1|fixture-group||1412|0")):
            result, _, _ = self.credentials(configuration(fields), body=body, environment=old_environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)

    def test_interface_mtu_is_normalized_to_decimal(self):
        result, _, _ = self.credentials(configuration({"Interface MTU": "0576"}), body='printf "%s" "$VPN_MTU"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "576")

    def test_invalid_connection_settings_fail_before_private_output(self):
        cases = [{"IPSec gateway": "999.2.3.4"}, {"IPSec gateway": "bad..name"},
                 {"IPSec gateway": "host\nother"}, {"IPSec ID": "group\nother"},
                 {"Interface MTU": "575"}, {"Interface MTU": "1501"}, {"Interface MTU": "$(id)"},
                 *({"VPN DNS": value} for value in ("127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
                    "255.255.255.255", "10.01.0.1", "::1", "10.0.0.53,", ",10.0.0.53", "10.0.0.53,,10.0.0.54"))]
        for settings in cases:
            with self.subTest(settings=settings):
                result, output, _ = self.credentials(configuration(settings))
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(output)

    def test_explicit_weak_encryption_values_are_zero_or_one(self):
        for value in ("0", "1"):
            result, _, _ = self.credentials(configuration({"Enable weak encryption": value}),
                                            body='printf "%s" "$VPN_ENABLE_WEAK_ENCRYPTION"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, value)
        for value in ("", "true", "yes", "2", "-1", "01", " 1", "1 ", "$(id)"):
            with self.subTest(value=value):
                result, output, _ = self.credentials(configuration({"Enable weak encryption": value}))
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(output)
                self.assertEqual(result.stdout, "")

    def test_proxy_target_accepts_tcp_hosts_and_ports(self):
        for host, port in (("internal.test", "22"), ("198.18.0.2", "2222"), ("host_name", "65535"), ("internal.test", "00022")):
            result = self.bash('valid_proxy_target "$@"', host, port)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_proxy_target_rejects_invalid_arguments(self):
        for arguments in ((), ("internal.test",), ("internal.test", "22", "extra"), ("-option", "22"),
                          ("host/path", "22"), ("host name", "22"), ("host\nname", "22"), ("::1", "22"),
                          ("", "22"), ("internal.test", "0"), ("internal.test", "65536"), ("internal.test", "-22"),
                          ("internal.test", "22 "), ("internal.test", "$(id)")):
            with self.subTest(arguments=arguments):
                result = self.bash('valid_proxy_target "$@"', *arguments)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_integration_configurations_cannot_escape_their_temporary_tree(self):
        import integration
        previous = integration.TEST_DIRECTORY_ROOT
        with tempfile.TemporaryDirectory(prefix="vpncsocks-integration-", dir=COMMON.parents[1] / "tests") as temporary:
            root = Path(temporary).resolve()
            integration.TEST_DIRECTORY_ROOT = root
            try:
                created = integration.write_configuration(root)
                self.assertEqual(created.parent, root)
                with self.assertRaises(ValueError):
                    integration.write_configuration(COMMON.parent)
                with self.assertRaises(ValueError):
                    integration.configuration_mount(COMMON)
                escape = root / "escape"
                escape.symlink_to(COMMON.parent, target_is_directory=True)
                with self.assertRaises(ValueError):
                    integration.write_configuration(escape)
            finally:
                integration.TEST_DIRECTORY_ROOT = previous


if __name__ == "__main__":
    unittest.main()
