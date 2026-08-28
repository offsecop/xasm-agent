"""#1572 — capture chrome launcher shim.

Chromium's HTTPS-Upgrades / HTTPS-First machinery silently upgrades http://
navigations and, under headless/automation, surfaces a failed upgrade as
net::ERR_BLOCKED_BY_CLIENT instead of falling back to http — making every
http-only host with a broken/filtered 443 uncapturable. gowitness v3 has no
chrome-args pass-through, so the fix is a generated launcher shim handed to
--chrome-path that merges our --disable-features into whatever chromedp already
passes and execs the real Chrome in place (same PID → the #571 process-group
teardown is untouched).

These tests exercise the shim generation and its argv contract with a fake
Chrome binary — no real browser, no network.
"""

import os
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools import screenshot_utils  # noqa: E402
from tools.screenshot_utils import (  # noqa: E402
    DEFAULT_CHROME_DISABLE_FEATURES,
    _chrome_shim_path,
    find_chrome_path,
)


@pytest.fixture()
def shim_dir(tmp_path, monkeypatch):
    d = tmp_path / 'shims'
    d.mkdir()
    monkeypatch.setenv('DRP_CHROME_SHIM_DIR', str(d))
    monkeypatch.delenv('DRP_CHROME_DISABLE_FEATURES', raising=False)
    return d


@pytest.fixture()
def fake_chrome(tmp_path):
    """A stand-in Chrome that dumps its argv (one per line) and exits 0."""
    dump = tmp_path / 'argv.txt'
    binary = tmp_path / 'fake-chrome'
    binary.write_text(
        '#!/bin/sh\n'
        f'printf \'%s\\n\' "$@" > {dump}\n'
    )
    binary.chmod(0o755)
    return binary, dump


def _run_shim(shim, args):
    subprocess.run([shim, *args], check=True, timeout=10)


class TestShimGeneration:
    def test_shim_is_created_executable_with_features(self, shim_dir):
        shim = _chrome_shim_path('/usr/bin/true', DEFAULT_CHROME_DISABLE_FEATURES)
        assert os.path.isfile(shim)
        assert os.stat(shim).st_mode & stat.S_IXUSR
        content = open(shim, encoding='utf-8').read()
        assert 'HttpsUpgrades' in content
        assert content.startswith('#!/bin/sh')

    def test_idempotent_and_content_addressed(self, shim_dir):
        first = _chrome_shim_path('/usr/bin/true', 'FeatureA')
        again = _chrome_shim_path('/usr/bin/true', 'FeatureA')
        other = _chrome_shim_path('/usr/bin/true', 'FeatureB')
        assert first == again
        assert other != first  # changed inputs → new shim, never a stale reuse
        assert len(list(shim_dir.iterdir())) == 2


class TestShimArgvContract:
    def test_appends_disable_features_when_none_present(
        self, shim_dir, fake_chrome
    ):
        binary, dump = fake_chrome
        shim = _chrome_shim_path(str(binary), 'HttpsUpgrades,FeatX')
        _run_shim(shim, ['--headless', '--no-sandbox', 'http://lure.test'])
        argv = dump.read_text().splitlines()
        assert argv[:3] == ['--headless', '--no-sandbox', 'http://lure.test']
        assert argv[-1] == '--disable-features=HttpsUpgrades,FeatX'

    def test_merges_callers_disable_features_into_one_switch(
        self, shim_dir, fake_chrome
    ):
        """Chromium keeps only one value for a repeated switch — the shim must
        emit a SINGLE merged --disable-features carrying both chromedp's list
        and ours, or one of them silently stops applying."""
        binary, dump = fake_chrome
        shim = _chrome_shim_path(str(binary), 'HttpsUpgrades')
        _run_shim(shim, [
            '--headless',
            '--disable-features=site-per-process,Translate',
            '--user-agent=Agent Name With Spaces',
            'http://lure.test',
        ])
        argv = dump.read_text().splitlines()
        features = [a for a in argv if a.startswith('--disable-features=')]
        assert len(features) == 1
        value = features[0][len('--disable-features='):]
        assert 'site-per-process' in value
        assert 'Translate' in value
        assert 'HttpsUpgrades' in value
        # Other args survive untouched, including embedded spaces.
        assert '--user-agent=Agent Name With Spaces' in argv
        assert 'http://lure.test' in argv

    def test_execs_real_binary_exit_code_passthrough(self, shim_dir, tmp_path):
        binary = tmp_path / 'failing-chrome'
        binary.write_text('#!/bin/sh\nexit 42\n')
        binary.chmod(0o755)
        shim = _chrome_shim_path(str(binary), 'HttpsUpgrades')
        proc = subprocess.run([shim], timeout=10)
        assert proc.returncode == 42


class TestFindChromePath:
    def test_returns_shim_when_chrome_on_path(self, shim_dir, monkeypatch):
        monkeypatch.setattr(
            screenshot_utils.shutil, 'which', lambda _: '/usr/bin/true'
        )
        path = find_chrome_path()
        assert path is not None
        assert os.path.basename(path).startswith('xasm-chrome-shim-')
        assert os.stat(path).st_mode & stat.S_IXUSR

    def test_kill_switch_empty_features_returns_real_binary(
        self, shim_dir, monkeypatch
    ):
        monkeypatch.setattr(
            screenshot_utils.shutil, 'which', lambda _: '/usr/bin/true'
        )
        monkeypatch.setenv('DRP_CHROME_DISABLE_FEATURES', '')
        assert find_chrome_path() == '/usr/bin/true'
        assert list(shim_dir.iterdir()) == []  # no shim written

    def test_fail_open_on_unwritable_shim_dir(self, tmp_path, monkeypatch):
        # Point the shim dir INSIDE a regular file → open() raises
        # NotADirectoryError (an OSError) on every platform, root included.
        blocker = tmp_path / 'not-a-dir'
        blocker.write_text('x')
        monkeypatch.setenv('DRP_CHROME_SHIM_DIR', str(blocker))
        monkeypatch.delenv('DRP_CHROME_DISABLE_FEATURES', raising=False)
        monkeypatch.setattr(
            screenshot_utils.shutil, 'which', lambda _: '/usr/bin/true'
        )
        assert find_chrome_path() == '/usr/bin/true'

    def test_none_when_no_chrome_anywhere(self, shim_dir, monkeypatch):
        monkeypatch.setattr(screenshot_utils.shutil, 'which', lambda _: None)
        monkeypatch.setattr(
            screenshot_utils._glob, 'glob', lambda _: []
        )
        assert find_chrome_path() is None
