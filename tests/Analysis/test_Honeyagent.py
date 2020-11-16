import os
import logging
from mock import patch
from mock import Mock

import thug
from thug.Analysis.honeyagent import HoneyAgent
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.Logging.ThugLogging import ThugLogging

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts = ThugOpts()
log.PyHooks  = dict()

log.configuration_path = configuration_path
log.ThugLogging = ThugLogging()

HAGENT = HoneyAgent.HoneyAgent()


class mock_cls:
    """Mock class for other required methods in log
    """

    def __getattr__(self, attr):
        return lambda *args: None


class mock_log():
    """Mock class for log
    """

    def __init__(self):
        self.data = []
        self.ThugOpts = mock_cls()
        self.ThugLogging = mock_cls()

    def warning(self, *args):
        self.data.append(args)


class TestHoneyAgent:
    cwd_path = os.path.dirname(os.path.realpath(__file__))
    samples_path = os.path.join(cwd_path, os.pardir, os.pardir, "tests/test_files")

    # Mock requests POST method
    @patch('requests.post')
    def test_analyze(self, mocked_post):
        expected = [('d4be8fbeb3a219ec8c6c26ffe4033a16',),
                    ('d4be8fbeb3a219ec8c6c26ffe4033a16', 'file'),
                    ('d4be8fbeb3a219ec8c6c26ffe4033a16', 'heuristics', 'LocalFileAccess')]

        sample = {'type': 'JAR', 'md5': 'd4be8fbeb3a219ec8c6c26ffe4033a16'}

        jar_path = os.path.join(self.samples_path, "sample.jar")
        with open(jar_path, 'rb') as f:
            data = f.read()

        json_data = lambda: {"result": {"files": {"file": "test"},
                                            "yara": {"heuristics":
                                                     [{"rule": "LocalFileAccess"}]}}}

        mocked_post.return_value = Mock(json=json_data)

        _log = HoneyAgent.log
        HoneyAgent.log = mock_log()

        HAGENT.enabled = True
        HAGENT.opts = {'enable': True, 'scanurl': 'http://test.com'}

        HAGENT.analyze(data, sample, self.samples_path, None)

        mock_data = [dat[1:]for dat in HoneyAgent.log.data]
        assert mock_data == expected

        HoneyAgent.log = _log
