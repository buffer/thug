#!/usr/bin/env python
#
# Location.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import PyV8
import Window
import W3C
import DFT
import logging
from Personality import Personality
from urlparse import urlparse

log = logging.getLogger("Thug.DOM")

class Location(PyV8.JSClass):
    def __init__(self, window):
        self._window = window

    def toString(self):
        return self._window.url

    @property
    def parts(self):
        return urlparse(self._window.url)

    @property
    def href(self):
        return self._window.url

    @href.setter
    def href(self, url):
        # FIXME
        #self._window.open(url)
        referer = self._window.url
        if referer == url:
            log.warning("Detected redirection from %s to %s... skipping" % (referer, url, ))
            return

        #self._window.url = url

        for p in Personality:
            if Personality[p]['userAgent'] == self._window._navigator.userAgent:
                break

        doc    = W3C.w3c.parseString('')
        window = Window.Window(referer, doc, personality = p)
        window = window.open(url)
        if not window:
            return

        self._window.url = url
        dft = DFT.DFT(window)
        dft.run()

    @property
    def protocol(self):
        return self.parts.scheme

    @property
    def host(self):
        return self.parts.netloc

    @property
    def hostname(self):
        return self.parts.hostname

    @property
    def port(self):
        return self.parts.port

    @property
    def pathname(self):
        return self.parts.path

    @property
    def search(self):
        return self.parts.query

    @property
    def hash(self):
        return self.parts.fragment

    def assign(self, url):
        """Loads a new HTML document."""
        self._window.open(url)

    def reload(self):
        """Reloads the current page."""
        self._window.open(self._window.url)

    def replace(self, url):
        """Replaces the current document by loading another document at the specified URL."""
        self._window.open(url)

