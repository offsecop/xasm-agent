from pathlib import Path


DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def _dockerfile_text():
    return DOCKERFILE.read_text(encoding="utf-8")


def test_nuclei_is_pinned_to_expected_stable_release():
    dockerfile = _dockerfile_text()

    assert "ARG NUCLEI_VERSION=3.11.1" in dockerfile
    assert "releases/download/v${NUCLEI_VERSION}" in dockerfile
    assert 'nuclei -version;' in dockerfile
    assert "v3.3.6" not in dockerfile


def test_nuclei_install_maps_amd64_and_arm64_and_rejects_unknown_architecture():
    dockerfile = _dockerfile_text()

    assert 'ARCH="$(dpkg --print-architecture)"' in dockerfile
    assert 'amd64) NUCLEI_ARCH="amd64"' in dockerfile
    assert 'arm64) NUCLEI_ARCH="arm64"' in dockerfile
    assert '*) echo "Unsupported Nuclei architecture: $ARCH" >&2; exit 1' in dockerfile
    assert 'linux_${NUCLEI_ARCH}.zip' in dockerfile


def test_nuclei_archive_is_verified_with_official_checksum_asset_before_unzip():
    dockerfile = _dockerfile_text()

    checksum_asset = 'NUCLEI_CHECKSUMS="nuclei_${NUCLEI_VERSION}_checksums.txt"'
    checksum_download = 'wget -q "${NUCLEI_RELEASE_URL}/${NUCLEI_CHECKSUMS}"'
    checksum_verify = "sha256sum -c nuclei.sha256"
    unzip = 'unzip "$NUCLEI_ASSET" nuclei'
    assert checksum_asset in dockerfile
    assert checksum_download in dockerfile
    assert 'grep -E "[[:space:]]${NUCLEI_ASSET}$" "$NUCLEI_CHECKSUMS"' in dockerfile
    assert "test -s nuclei.sha256" in dockerfile
    assert checksum_verify in dockerfile
    assert dockerfile.index(checksum_download) < dockerfile.index(checksum_verify)
    assert dockerfile.index(checksum_verify) < dockerfile.index(unzip)
