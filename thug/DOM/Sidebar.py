#!/usr/bin/env python
#
# Sidebar.py
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

from .JSClass import JSClass

import logging
log = logging.getLogger("Thug")


class Sidebar(JSClass):
    def __init__(self):
        self._providers  = set()
        self._engines    = set()
        self._favorites  = set()
        self._generators = set()

    def addMicrosummaryGenerator(self, generatorURL):
        self._generators.add(generatorURL)

    def addPanel(self, title, URL, customizeURL):
        self._favorites.add((title, URL, customizeURL))

    def addPersistentPanel(self, title, URL, customizeURL):
        self._favorites.add((title, URL, customizeURL))

    def addSearchEngine(self, engineURL, iconURL, message, suggestedCategory):
        self._enginess.add((engineURL, iconURL, message, suggestedCategory))

    def AddSearchProvider(self, URL):
        self._providers.add(URL)

    def IsSearchProviderInstalled(self, URL):
        if URL in self._providers:
            return 1  # A matching search provider is installed, but it is not the default.

        return 0    # No installed search provider was found with the specified prefix
