import os
import logging

import thug

from thug.DOM.Location import Location
from thug.DOM.Navigator import Navigator
from thug.DOM.HTMLInspector import HTMLInspector
from thug.DOM.HTTPSession import HTTPSession
from thug.DOM.MIMEHandler import MIMEHandler
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.DOM.SchemeHandler import SchemeHandler
from thug.Logging.ThugLogging import ThugLogging

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts = ThugOpts()
log.HTMLInspector = HTMLInspector()
log.HTTPSession = HTTPSession()
log.MIMEHandler = MIMEHandler()
log.ThugVulnModules = ThugVulnModules()
log.SchemeHandler = SchemeHandler()
log.PyHooks = dict()
log.ThugLogging = ThugLogging()


class WindowDict(dict):
    def __setitem__(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        return self[key]


class TestLocation:
    def check_expected(self, caplog, expected):
        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def testParts(self):
        window = WindowDict()
        window.url = 'https://www.google.com:1234/search?&q=test'

        location = Location(window)

        assert location.host == 'www.google.com:1234'
        assert location.hostname == 'www.google.com'
        assert location.pathname == '/search'
        assert location.search == '&q=test'
        assert location.port == 1234
        assert location.hash == ''

    def testPathname(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://www.google.com/search --> Location: https://www.google.com/test']

        window = WindowDict()
        window.url = 'https://www.google.com/search'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.pathname = '/search'
        location.pathname = '/test'

        self.check_expected(caplog, expected)

    def testProtocol(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: http://www.google.com --> Location: https://www.google.com'
        ]

        window = WindowDict()
        window.url = 'http://www.google.com'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.protocol = 'http'
        location.protocol = 'https'

        self.check_expected(caplog, expected)

    def testHost(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://www.google.com:1234/search?&q=test --> Location: https://www.google.com/search?&q=test'
        ]

        window = WindowDict()
        window.url = 'https://www.google.com:1234/search?&q=test'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.host = 'www.google.com:1234'
        location.host = 'www.google.com'

        self.check_expected(caplog, expected)

    def testHostname(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://ww.google.com --> Location: https://www.google.com'
        ]

        window = WindowDict()
        window.url = 'https://ww.google.com'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.hostname = 'ww.google.com'
        location.hostname = 'www.google.com'

        self.check_expected(caplog, expected)

    def testPort(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://www.google.com:1234 --> Location: https://www.google.com:443'
        ]

        window = WindowDict()
        window.url = 'https://www.google.com:1234'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.port = 1234
        location.port = 443

        self.check_expected(caplog, expected)

    def testSearch(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://www.google.com/search?&q=test --> Location: https://www.google.com/search?&q=test2'
        ]

        window = WindowDict()
        window.url = 'https://www.google.com/search?&q=test'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.search = '&q=test'
        location.search = '&q=test2'

        self.check_expected(caplog, expected)

    def testHash(self, caplog):
        expected = [
            '[HREF Redirection (document.location)]',
            'Content-Location: https://www.google.com/search#foo --> Location: https://www.google.com/search#bar'
        ]

        window = WindowDict()
        window.url = 'https://www.google.com/search#foo'
        window._navigator = Navigator("winxpie60")

        location = Location(window)
        location.hash = 'foo'
        location.hash = 'bar'

        self.check_expected(caplog, expected)
