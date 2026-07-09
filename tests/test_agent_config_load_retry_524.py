"""#524 — agents must not boot with the localhost fallback api_url.

When CONFIG_FILE is explicitly set (docker-compose mounts `config.docker.yaml`)
the file is expected to exist. A fresh deploy can race the volume mount, so a
boot-time FileNotFoundError used to silently pin `api_url` to
`http://localhost:3001/api`, leaving the long-running agent enrolling against
the wrong backend until a manual restart. load_config now retries the read
briefly so it rides out the race.
"""
import os
import sys
import tempfile
import threading
import time
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

import main_rest  # noqa: E402

_ENV_KEYS = (
    'CONFIG_FILE',
    'AGENT_CONFIG_RETRY_ATTEMPTS',
    'AGENT_CONFIG_RETRY_INTERVAL_S',
    'AGENT_API_URL',
)


class TestLoadConfigRetry(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _set(self, **kw):
        for k, v in kw.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = str(v)

    def test_reads_existing_config_immediately(self):
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as f:
            f.write('server:\n  api_url: http://backend:3001/api\n')
            path = f.name
        try:
            self._set(CONFIG_FILE=path, AGENT_CONFIG_RETRY_ATTEMPTS=3, AGENT_CONFIG_RETRY_INTERVAL_S=0.01)
            cfg = main_rest.load_config()
            self.assertEqual(cfg['server']['api_url'], 'http://backend:3001/api')
        finally:
            os.unlink(path)

    def test_recovers_when_config_appears_after_a_delay(self):
        # The volume-mount race: the file shows up shortly after boot. The agent
        # must end up with the MOUNTED api_url, never the localhost fallback.
        d = tempfile.mkdtemp()
        path = os.path.join(d, 'config.docker.yaml')
        self._set(
            CONFIG_FILE=path,
            AGENT_CONFIG_RETRY_ATTEMPTS=40,
            AGENT_CONFIG_RETRY_INTERVAL_S=0.05,
            AGENT_API_URL=None,
        )

        def _create_after_delay():
            time.sleep(0.25)
            with open(path, 'w') as f:
                f.write('server:\n  api_url: http://backend:3001/api\n')

        t = threading.Thread(target=_create_after_delay)
        t.start()
        try:
            cfg = main_rest.load_config()
            self.assertEqual(cfg['server']['api_url'], 'http://backend:3001/api')
            self.assertNotIn('localhost', cfg['server']['api_url'])
        finally:
            t.join()
            os.unlink(path)
            os.rmdir(d)

    def test_falls_back_to_env_url_when_config_never_appears(self):
        # Last resort: honor an explicit AGENT_API_URL rather than localhost.
        self._set(
            CONFIG_FILE='/nonexistent/never/config.docker.yaml',
            AGENT_CONFIG_RETRY_ATTEMPTS=2,
            AGENT_CONFIG_RETRY_INTERVAL_S=0.01,
            AGENT_API_URL='http://backend:3001/api',
        )
        cfg = main_rest.load_config()
        self.assertEqual(cfg['server']['api_url'], 'http://backend:3001/api')


if __name__ == '__main__':
    unittest.main()
