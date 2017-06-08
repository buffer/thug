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
        self.__init_personality()

    def __init_personality(self):
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
        pass

    def __init_personality_Chrome(self):
        pass

    def __init_personality_Safari(self):
        pass

    def __init_personality_Opera(self):
        pass

    def debug(self, *args):
        pass

    # def dir(self, *args):
    #    pass

    # def error(self, *args):
    #    pass

    def group(self):
        pass

    def groupCollapsed(self):
        pass

    def groupEnd(self):
        pass

    # def info(self, *args):
    #    pass

    # def log(self, *args):
    #    pass

    def time(self, timerName):
        pass

    def timeEnd(self, timerName):
        pass

    def trace(self):
        pass

    def warn(self, *args):
        pass
