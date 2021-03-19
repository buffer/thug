#!/usr/bin/env python
#
# ContextAnalyzer.py
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


import inspect
import logging

log = logging.getLogger("Thug")


class ContextAnalyzer:
    def __init__(self):
        self.__init_checks()

    def __init_checks(self):
        self.checks = list()

        for (name, method) in inspect.getmembers(self, predicate = inspect.ismethod):
            if name.startswith('context_analyzer_check'):
                self.checks.append(method)

    def context_analyzer_check_sharepoint_is_anonymous_user(self, window):
        spPageContextInfo = getattr(window, '_spPageContextInfo', None)
        if spPageContextInfo and 'isAnonymousGuestUser' in spPageContextInfo: # pragma: no cover
            log.ThugLogging.log_classifier("sharepoint", log.ThugLogging.url, "SharePointAnonymousGuestUser")

    def analyze(self, window):
        for m in self.checks:
            m(window)
