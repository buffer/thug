import os
import logging

import thug

from thug.DOM.Personality import Personality
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.ThugAPI.ThugOpts import ThugOpts

log = logging.getLogger("Thug")

configuration_path = thug.__configuration_path__
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugVulnModules = ThugVulnModules()
log.ThugOpts = ThugOpts()

log.ThugOpts.useragent = 'winxpie60'


class TestPersonality(object):
    def test_personality(self):
        personality = Personality()

        assert 'Windows NT 5.1' in personality.userAgent
        assert 'Mozilla/4.0 (Windows XP 5.1) Java' in personality.javaUserAgent
        assert '6.0' in personality.browserVersion
        assert 'Win32' in personality.platform
        assert personality.browserMajorVersion == 6
        assert '5.6' in personality.cc_on['_jscript_version']
        assert personality.isIE() is True
        assert personality.isEdge() is False
        assert personality.isWindows() is True
        assert personality.isChrome() is False
        assert personality.isSafari() is False
        assert personality.ScriptEngineMajorVersion() == 5
        assert personality.ScriptEngineMinorVersion() == 6
        assert personality.ScriptEngineBuildVersion()
