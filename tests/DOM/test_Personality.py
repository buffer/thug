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

log.ThugOpts.useragent = 'win7ie90'


class TestPersonality(object):
    def test_personality(self):
        personality = Personality()

        assert 'MSIE 9.0; Windows NT 6.1' in personality.userAgent
        assert 'Mozilla/5.0 (Windows 7 6.1) Java/160_32' in personality.javaUserAgent
        assert '9.0' in personality.browserVersion
        assert 'Win32' in personality.platform
        assert personality.browserMajorVersion is 9
        assert '9' in personality.cc_on['_jscript_version']
        assert personality.isIE() is True
        assert personality.isEdge() is False
        assert personality.isWindows() is True
        assert personality.isChrome() is False
        assert personality.isSafari() is False
        assert personality.ScriptEngineMajorVersion() is 9
        assert personality.ScriptEngineMinorVersion() is 0
        assert personality.ScriptEngineBuildVersion() == 16443
