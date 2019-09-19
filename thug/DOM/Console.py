#!/usr/bin/env python
#
# Console.py
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

log = logging.getLogger("Thug")


class Console(JSClass):
    def __init__(self):
        self._counter = 0
        self._label_counter = dict()
        self.__init_console_personality()

    def __init_console_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_console_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_console_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_console_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_console_personality_Safari()
            return

    def __init_console_personality_IE(self):
        self.__methods__['assert'] = self._assert

        self.clear = self._clear
        self.count = self._count

        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.info = self._info
            self.log  = self._log
            self.warn = self._warn

            self.__methods__['error'] = self._error

        if log.ThugOpts.Personality.browserMajorVersion > 10:
            self.group          = self._group
            self.groupCollapsed = self._groupCollapsed
            self.groupEnd       = self._groupEnd
            self.time           = self._time
            self.timeEnd        = self._timeEnd
            self.trace          = self._trace

    def __init_console_personality_Firefox(self):
        if log.ThugOpts.Personality.browserMajorVersion > 3:
            self.group          = self._group
            self.groupCollapsed = self._groupCollapsed
            self.groupEnd       = self._groupEnd
            self.info           = self._info
            self.log            = self._log
            self.warn           = self._warn

            self.__methods__['error'] = self._error

        if log.ThugOpts.Personality.browserMajorVersion > 9:
            self.time    = self._time
            self.timeEnd = self._timeEnd
            self.trace   = self._trace

        if log.ThugOpts.Personality.browserMajorVersion > 27:
            self.__methods__['assert'] = self._assert

        if log.ThugOpts.Personality.browserMajorVersion > 29:
            self.count = self._count

        if log.ThugOpts.Personality.browserMajorVersion > 47: # pragma: no cover
            self.clear = self._clear

    def __init_console_personality_Chrome(self):
        self.clear          = self._clear
        self.count          = self._count
        self.group          = self._group
        self.groupCollapsed = self._groupCollapsed
        self.groupEnd       = self._groupEnd
        self.info           = self._info
        self.log            = self._log
        self.warn           = self._warn
        self.time           = self._time
        self.timeEnd        = self._timeEnd
        self.trace          = self._trace

        self.__methods__['assert'] = self._assert
        self.__methods__['error']  = self._error

    def __init_console_personality_Safari(self):
        self.clear = self._clear
        self.count = self._count
        self.info  = self._info
        self.log   = self._log
        self.warn  = self._warn

        self.__methods__['assert'] = self._assert
        self.__methods__['error']  = self._error

        if log.ThugOpts.Personality.browserMajorVersion > 3:
            self.time    = self._time
            self.timeEnd = self._timeEnd
            self.trace   = self._trace

        if log.ThugOpts.Personality.browserMajorVersion > 4:
            self.group          = self._group
            self.groupCollapsed = self._groupCollapsed
            self.groupEnd       = self._groupEnd

    def _assert(self, expression, statement):
        log.warning("[Console] assert(%s, '%s')", expression is False, statement)

    def _clear(self):
        log.warning("[Console] clear()")

    def _count(self, label = None):
        if not label:
            self._counter += 1
            log.warning("[Console] count() = %s", self._counter)
            return

        if label not in self._label_counter:
            self._label_counter[label] = 0

        self._label_counter[label] += 1
        log.warning("[Console] count('%s') = %s", label, self._label_counter[label])

    def debug(self, *args):
        pass

    def _error(self, message):
        log.warning("[Console] error('%s')", message)

    def _group(self):
        log.warning("[Console] group()")

    def _groupCollapsed(self):
        log.warning("[Console] groupCollapsed()")

    def _groupEnd(self):
        log.warning("[Console] groupEnd()")

    def _info(self, message):
        log.warning("[Console] info('%s')", message)

    def _log(self, message):
        log.warning("[Console] log('%s')", message)

    def _time(self, label = None):
        pass

    def _timeEnd(self, label = None):
        pass

    def _trace(self, label = None):
        pass

    def _warn(self, message):
        log.warning("[Console] warn('%s')", message)
