#!/usr/bin/env python
#
# History.py
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

import logging

from .JSClass import JSClass
from .Alexa import Alexa

log = logging.getLogger("Thug")


class History(JSClass):
    def __init__(self, window):
        self._window  = window
        self.urls     = Alexa
        self.pos      = None

        self.__init_personality()

    def __init_personality(self):
        self._navigationMode = "automatic"

        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_personality_Safari()
            return

        if log.ThugOpts.Personality.isOpera():
            self.__init_personality_Opera()

    def __init_personality_IE(self):
        pass

    def __init_personality_Firefox(self):
        self.current  = self._current
        self.next     = self._next
        self.previous = self._previous

    def __init_personality_Chrome(self):
        pass

    def __init_personality_Safari(self):
        pass

    def __init_personality_Opera(self):
        self.current        = self._current
        self.navigationMode = property(self._get_navigationMode, self._set_navigationMode)

    @property
    def window(self):
        return self._window

    @property
    def length(self):
        return len(self.urls)

    @property
    def _current(self):
        if self.pos:
            return self.urls[self.pos]
        return None

    @property
    def _next(self):
        if self.pos and len(self.urls) > self.pos + 1:
            return self.urls[self.pos + 1]
        return None

    @property
    def _previous(self):
        if self.pos and self.pos > 0:
            return self.urls[self.pos - 1]
        return None

    def _get_navigationMode(self):
        return self._navigationMode

    def _set_navigationMode(self, value):
        if value in ("automatic", "compatible", "fast", ):
            self._navigationMode = value

    def back(self):
        """Loads the previous URL in the history list"""
        return self.go(-1)

    def forward(self):
        """Loads the next URL in the history list"""
        return self.go(1)

    def go(self, num_or_url):
        """Loads a specific URL from the history list"""
        try:
            off = int(num_or_url)

            self.pos += off
            self.pos = min(max(0, self.pos), len(self.urls) - 1)
            self._window.open(self.urls[self.pos])
        except ValueError:
            self._window.open(num_or_url)

    def update(self, url, replace = False):
        if self.pos is None:
            self.urls.append(url)
            self.pos = 0
        elif replace:
            self.urls[self.pos] = url
        elif self.urls[self.pos] != url:
            self.urls = self.urls[:self.pos + 1]
            self.urls.append(url)
            self.pos += 1
