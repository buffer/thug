import os
import logging
import time

from mock import patch

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.ThugAPI.Watchdog import Watchdog
from thug.DOM.HTTPSession import HTTPSession
from thug.Logging.ThugLogging import ThugLogging
from thug.Classifier.URLClassifier import URLClassifier
from thug.Classifier.SampleClassifier import SampleClassifier

configuration_path = thug.__configuration_path__

log                    = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts         = ThugOpts()
log.HTTPSession      = HTTPSession()
log.URLClassifier    = URLClassifier()
log.SampleClassifier = SampleClassifier()
log.ThugLogging = ThugLogging(thug.__version__)


@patch('os.kill')
class TestWatchDog:
    def callback(self, signum, frame):
        pass

    def test_watch(self, os_kill):
        with Watchdog(0, callback=self.callback):
            time.sleep(1)
        assert not os_kill.called

    def test_abort(self, os_kill, caplog):
        caplog.clear()
        with Watchdog(1, callback=self.callback):
            time.sleep(1)
        assert os_kill.called
        assert "The analysis took more than 1 second(s). Aborting!" in caplog.text
