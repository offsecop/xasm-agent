#!/usr/bin/env bash
# Install an explicitly mounted corporate CA bundle for every TLS client used by
# the agent, including Playwright's Chromium. TLS verification remains enabled.
set -euo pipefail

configure_custom_ca() {
  local ca_bundle="${XASM_CA_BUNDLE:-}"
  if [ -z "$ca_bundle" ]; then
    return 0
  fi

  if [ ! -r "$ca_bundle" ] || [ ! -s "$ca_bundle" ]; then
    echo "[TLS] XASM_CA_BUNDLE is not a readable, non-empty file: $ca_bundle" >&2
    return 1
  fi

  local required_command
  for required_command in openssl update-ca-certificates certutil; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      echo "[TLS] Required command is unavailable: $required_command" >&2
      return 1
    fi
  done

  local system_cert_dir="${XASM_CA_SYSTEM_CERT_DIR:-/usr/local/share/ca-certificates}"
  local system_bundle="${XASM_CA_SYSTEM_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
  local nss_db_dir="${XASM_CA_NSSDB_DIR:-/root/.pki/nssdb}"
  local work_dir
  work_dir="$(mktemp -d)"

  awk -v output_dir="$work_dir" '
    /-----BEGIN CERTIFICATE-----/ {
      certificate_count++
      output_file = sprintf("%s/certificate-%04d.pem", output_dir, certificate_count)
      in_certificate = 1
    }
    in_certificate { print > output_file }
    /-----END CERTIFICATE-----/ {
      close(output_file)
      in_certificate = 0
    }
    END {
      if (in_certificate || certificate_count == 0) exit 1
    }
  ' "$ca_bundle" || {
    echo "[TLS] XASM_CA_BUNDLE does not contain a complete PEM certificate: $ca_bundle" >&2
    rm -rf -- "$work_dir"
    return 1
  }

  mkdir -p "$system_cert_dir" "$nss_db_dir"
  find "$system_cert_dir" -maxdepth 1 -type f -name 'xasm-custom-ca-*.crt' -delete

  if [ ! -f "$nss_db_dir/cert9.db" ]; then
    certutil -N -d "sql:$nss_db_dir" --empty-password
  fi

  local managed_nicknames="$nss_db_dir/xasm-managed-ca-nicknames"
  if [ -f "$managed_nicknames" ]; then
    while IFS= read -r nickname; do
      [ -z "$nickname" ] || certutil -D -d "sql:$nss_db_dir" -n "$nickname" >/dev/null 2>&1 || true
    done < "$managed_nicknames"
  fi
  : > "$managed_nicknames"

  local certificate fingerprint nickname installed_count=0
  for certificate in "$work_dir"/certificate-*.pem; do
    if ! openssl x509 -in "$certificate" -noout >/dev/null 2>&1; then
      echo "[TLS] XASM_CA_BUNDLE contains an invalid certificate: $ca_bundle" >&2
      rm -rf -- "$work_dir"
      return 1
    fi
    if ! openssl x509 -in "$certificate" -noout -text | grep -q 'CA:TRUE'; then
      echo "[TLS] XASM_CA_BUNDLE contains a certificate that is not a CA: $ca_bundle" >&2
      rm -rf -- "$work_dir"
      return 1
    fi

    fingerprint="$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')"
    if [ -z "$fingerprint" ]; then
      echo "[TLS] Could not calculate the CA fingerprint: $ca_bundle" >&2
      rm -rf -- "$work_dir"
      return 1
    fi
    nickname="xasm-custom-ca-${fingerprint}"
    cp "$certificate" "$system_cert_dir/${nickname}.crt"
    certutil -A -d "sql:$nss_db_dir" -n "$nickname" -t 'C,,' -i "$certificate"
    printf '%s\n' "$nickname" >> "$managed_nicknames"
    installed_count=$((installed_count + 1))
  done

  update-ca-certificates >/dev/null
  if [ ! -r "$system_bundle" ]; then
    echo "[TLS] System CA bundle was not produced at: $system_bundle" >&2
    rm -rf -- "$work_dir"
    return 1
  fi

  export SSL_CERT_FILE="$system_bundle"
  export REQUESTS_CA_BUNDLE="$system_bundle"
  export CURL_CA_BUNDLE="$system_bundle"
  export NODE_EXTRA_CA_CERTS="$ca_bundle"
  rm -rf -- "$work_dir"
  echo "[TLS] Installed $installed_count custom CA certificate(s) for system, Python, curl, Node.js, and Chromium clients."
}

configure_custom_ca
