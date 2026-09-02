import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


AGENT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = AGENT_DIR / "scripts" / "configure_custom_ca.sh"


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _make_test_ca(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "xASM corporate CA test")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _run_script(tmp_path: Path, ca_bundle: Path | None):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    command_log = tmp_path / "commands.log"
    _write_executable(
        fake_bin / "update-ca-certificates",
        "#!/bin/sh\nprintf 'update-ca-certificates\\n' >> \"$XASM_CA_TEST_LOG\"\n",
    )
    _write_executable(
        fake_bin / "certutil",
        "#!/bin/sh\n"
        "printf 'certutil %s\\n' \"$*\" >> \"$XASM_CA_TEST_LOG\"\n"
        "if [ \"$1\" = '-N' ]; then touch \"${3#sql:}/cert9.db\"; fi\n",
    )

    system_cert_dir = tmp_path / "system-certs"
    nss_db_dir = tmp_path / "nssdb"
    system_bundle = tmp_path / "ca-certificates.crt"
    system_bundle.write_text("test system bundle", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "XASM_CA_TEST_LOG": str(command_log),
        "XASM_CA_SYSTEM_CERT_DIR": str(system_cert_dir),
        "XASM_CA_NSSDB_DIR": str(nss_db_dir),
        "XASM_CA_SYSTEM_BUNDLE": str(system_bundle),
    }
    if ca_bundle is None:
        env.pop("XASM_CA_BUNDLE", None)
    else:
        env["XASM_CA_BUNDLE"] = str(ca_bundle)

    completed = subprocess.run(
        ["bash", "-c", f"source {SCRIPT!s}; env"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    return completed, command_log, system_cert_dir, nss_db_dir, system_bundle


def test_custom_ca_is_opt_in_and_default_trust_is_unchanged(tmp_path):
    completed, command_log, system_cert_dir, nss_db_dir, _ = _run_script(tmp_path, None)

    assert completed.returncode == 0
    assert not command_log.exists()
    assert not system_cert_dir.exists()
    assert not nss_db_dir.exists()
    assert "XASM_CA_BUNDLE=" not in completed.stdout


def test_agent_image_wires_custom_ca_before_any_network_activity():
    dockerfile = (AGENT_DIR / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (AGENT_DIR / "entrypoint.sh").read_text(encoding="utf-8")

    assert "libnss3-tools" in dockerfile
    assert "openssl" in dockerfile
    ca_setup = ". /app/scripts/configure_custom_ca.sh"
    assert ca_setup in entrypoint
    assert entrypoint.index(ca_setup) < entrypoint.index("nuclei -update-templates")
    assert "--ignore-certificate-errors" not in entrypoint
    assert "ignoreHTTPSErrors" not in entrypoint


def test_valid_custom_ca_configures_system_and_chromium_trust(tmp_path):
    ca_bundle = tmp_path / "corporate-ca.pem"
    _make_test_ca(ca_bundle)

    completed, command_log, system_cert_dir, nss_db_dir, system_bundle = _run_script(
        tmp_path, ca_bundle
    )

    assert completed.returncode == 0, completed.stderr
    assert "Installed 1 custom CA certificate(s)" in completed.stdout
    assert f"SSL_CERT_FILE={system_bundle}" in completed.stdout
    assert f"REQUESTS_CA_BUNDLE={system_bundle}" in completed.stdout
    assert f"CURL_CA_BUNDLE={system_bundle}" in completed.stdout
    assert f"NODE_EXTRA_CA_CERTS={ca_bundle}" in completed.stdout
    assert len(list(system_cert_dir.glob("xasm-custom-ca-*.crt"))) == 1
    assert (nss_db_dir / "cert9.db").exists()
    commands = command_log.read_text(encoding="utf-8")
    assert "certutil -A -d sql:" in commands
    assert " -t C,, -i " in commands
    assert "update-ca-certificates" in commands


def test_missing_custom_ca_path_fails_before_agent_startup(tmp_path):
    missing_bundle = tmp_path / "missing-ca.pem"

    completed, command_log, _, _, _ = _run_script(tmp_path, missing_bundle)

    assert completed.returncode != 0
    assert "not a readable, non-empty file" in completed.stderr
    assert not command_log.exists()
